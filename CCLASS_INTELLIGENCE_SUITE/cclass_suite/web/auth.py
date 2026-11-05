"""Authentication, RBAC enforcement, request auditing and account/audit API routes.

Written against plain Starlette (a pure-ASGI middleware plus Starlette routes) so it is
independent of FastAPI and unit-testable on its own.
"""
from __future__ import annotations

import ipaddress
import logging
import secrets
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .. import security
from ..accounts import AccountError, public

log = logging.getLogger("cclass.auth")
COOKIE = "cclass_session"
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "cclass"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
# Handlers below write their own, more specific audit entries for these prefixes.
SELF_AUDITED = ("/api/auth/", "/api/users", "/api/audit", "/api/backups")
LOCAL_USER = {"id": 0, "username": "local", "display_name": "Local (auth disabled)", "role": "admin",
              "totp_enabled": False, "must_change_password": False, "disabled": False}


def client_ip(request_or_scope, trust_proxy: bool) -> str:
    req = request_or_scope if isinstance(request_or_scope, Request) else Request(request_or_scope)
    if trust_proxy:
        xff = req.headers.get("x-forwarded-for", "")
        first = xff.split(",")[0].strip()
        try:
            ipaddress.ip_address(first)
            return first
        except ValueError:
            pass
    return req.client.host if req.client else ""


def is_secure_request(request: Request, ctx) -> bool:
    if ctx.settings.cookie_secure:
        return True
    if ctx.settings.trust_proxy and request.headers.get("x-forwarded-proto", "").lower() == "https":
        return True
    return request.url.scheme == "https"


def _json(detail: str, status: int, **extra: Any) -> JSONResponse:
    return JSONResponse({"detail": detail, **extra}, status_code=status,
                        headers={"Cache-Control": "no-store"})


# ---------------------------------------------------------------------------
class AuthMiddleware:
    """Authenticate, authorise (RBAC), enforce the CSRF header and audit API requests."""

    def __init__(self, app: ASGIApp, ctx):
        self.app = app
        self.ctx = ctx

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]
        method: str = scope["method"].upper()
        if not path.startswith("/api/"):
            await self.app(scope, receive, send)       # SPA shell + static files are public
            return
        request = Request(scope, receive)
        ctx = self.ctx
        ip = client_ip(request, ctx.settings.trust_proxy)

        # CSRF defence in depth (cookie is SameSite=Strict and Origin is checked elsewhere):
        # browsers cannot add a custom header to a cross-site request without a CORS pre-flight.
        if method not in SAFE_METHODS and request.headers.get(CSRF_HEADER, "").lower() != CSRF_VALUE:
            await _json("missing CSRF header", 403)(scope, receive, send)
            return

        user: Optional[Dict[str, Any]]
        if not ctx.settings.auth_enabled:
            user = dict(LOCAL_USER)
        elif security.is_public(path):
            user = None
        else:
            user = ctx.accounts.resolve_session(request.cookies.get(COOKIE))
            if user is None:
                ctx.audit.append("anonymous", "access.unauthenticated", f"{method} {path}", "", ip)
                await _json("authentication required", 401)(scope, receive, send)
                return
            if user["must_change_password"] and path not in ("/api/auth/me", "/api/auth/logout", "/api/auth/password"):
                await _json("password change required", 403, password_change_required=True)(scope, receive, send)
                return
            need = security.required_role(method, path)
            if not security.role_at_least(user["role"], need):
                ctx.audit.append(user["username"], "access.denied", f"{method} {path}",
                                 f"role={user['role']} needs={need}", ip, user["id"])
                await _json("you do not have permission to do that", 403)(scope, receive, send)
                return
        scope.setdefault("state", {})["user"] = user
        scope["state"]["ip"] = ip

        status_holder = {"code": 0}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["code"] = message["status"]
                headers = list(message.get("headers", []))
                if not any(k.lower() == b"cache-control" for k, _ in headers):
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)

        audited_read = method == "GET" and (path.endswith("/download") or "/export" in path)
        if (method not in SAFE_METHODS or audited_read) and not path.startswith(SELF_AUDITED):
            who = user["username"] if user else "anonymous"
            try:
                ctx.audit.append(who, f"api.{method.lower()}", path,
                                 f"status={status_holder['code']}", ip, user["id"] if user else None)
            except Exception:  # noqa: BLE001 - auditing must never break a response that already succeeded
                log.exception("audit write failed")


# ---------------------------------------------------------------------------
class LoginLimiter:
    """Small in-memory per-IP limiter (defence in depth on top of per-account lockout)."""

    def __init__(self, limit: int = 20, window: int = 300):
        self.limit, self.window = limit, window
        self.hits: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True


async def _body(request: Request) -> Dict[str, Any]:
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        raise AccountError("request body must be JSON")
    if not isinstance(data, dict):
        raise AccountError("request body must be a JSON object")
    return data


def _s(data: Dict[str, Any], key: str, maxlen: int = 300) -> str:
    v = data.get(key, "")
    if not isinstance(v, str) or len(v) > maxlen:
        raise AccountError(f"{key} must be text of at most {maxlen} characters")
    return v


def build_auth_routes(ctx) -> List[Route]:
    limiter = LoginLimiter()
    setup_token = secrets.token_urlsafe(12) if ctx.settings.auth_enabled and ctx.accounts.count() == 0 else ""
    if setup_token:
        log.warning("First-run setup token (needed to create the first administrator from a "
                    "non-local address): %s", setup_token)
    state = {"setup_token": setup_token}
    ctx.setup_token = setup_token          # shown on the console by `cclass.py` at start-up

    def actor(request: Request) -> Dict[str, Any]:
        return request.state.user or {"username": "anonymous", "id": None}

    def aud(request: Request, action: str, target: str = "", detail: str = "", who: Optional[str] = None) -> None:
        u = actor(request)
        ctx.audit.append(who or u["username"], action, target, detail,
                         client_ip(request, ctx.settings.trust_proxy), u.get("id") or None)

    def err(exc: AccountError, status: int = 400) -> JSONResponse:
        return _json(str(exc), status)

    def set_cookie(request: Request, resp: Response, token: str) -> None:
        resp.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/",
                        secure=is_secure_request(request, ctx))

    # ------------------------------------------------------------ status / setup / login
    async def status(request: Request) -> Response:
        u = ctx.accounts.resolve_session(request.cookies.get(COOKIE)) if ctx.settings.auth_enabled else dict(LOCAL_USER)
        return _json("ok", 200, auth_enabled=ctx.settings.auth_enabled,
                     setup_required=ctx.settings.auth_enabled and ctx.accounts.count() == 0,
                     authenticated=u is not None, user=public(u) if u else None)

    async def setup(request: Request) -> Response:
        if not ctx.settings.auth_enabled or ctx.accounts.count() > 0:
            return _json("setup is not available", 409)
        ip = client_ip(request, ctx.settings.trust_proxy)
        local = ip in ("127.0.0.1", "::1") and not ctx.settings.trust_proxy
        try:
            data = await _body(request)
            if not local and not secrets.compare_digest(_s(data, "setup_token", 100), state["setup_token"] or "x"):
                return _json("a valid setup token (printed in the server log) is required", 403)
            uid = ctx.accounts.create_user(_s(data, "username", 40), _s(data, "password", 256), "admin",
                                           _s(data, "display_name", 80))
        except AccountError as exc:
            return err(exc)
        ctx.audit.append(_s(data, "username", 40), "setup.first_admin", f"user:{uid}", "", ip, uid)
        token = ctx.accounts.create_session(uid, ip, request.headers.get("user-agent", ""))
        resp = _json("ok", 201, user=public(ctx.accounts.get(uid)))
        set_cookie(request, resp, token)
        return resp

    async def login(request: Request) -> Response:
        ip = client_ip(request, ctx.settings.trust_proxy)
        if not ctx.settings.auth_enabled:
            return _json("authentication is disabled", 409)
        if not limiter.allow(ip):
            ctx.audit.append("anonymous", "login.rate_limited", "", "", ip)
            return _json("too many attempts, try again later", 429)
        try:
            data = await _body(request)
            username, password, code = _s(data, "username", 40), _s(data, "password", 256), _s(data, "totp", 12)
        except AccountError as exc:
            return err(exc)
        result = ctx.accounts.authenticate(username, password, code)
        st = result["status"]
        if st == "totp_required":
            return _json("verification code required", 200, totp_required=True)
        if st != "ok":
            ctx.audit.append(username[:40] or "unknown", f"login.fail.{st}", "", "", ip,
                             (result["user"] or {}).get("id"))
            return _json("invalid credentials, code, or the account is temporarily locked", 401)
        user = result["user"]
        token = ctx.accounts.create_session(user["id"], ip, request.headers.get("user-agent", ""))
        ctx.audit.append(user["username"], "login.ok", "", "", ip, user["id"])
        resp = _json("ok", 200, user=public(user))
        set_cookie(request, resp, token)
        return resp

    async def logout(request: Request) -> Response:
        ctx.accounts.delete_session(request.cookies.get(COOKIE))
        if ctx.settings.auth_enabled:
            aud(request, "logout")
        resp = _json("ok", 200)
        resp.delete_cookie(COOKIE, path="/")
        return resp

    async def me(request: Request) -> Response:
        return _json("ok", 200, user=public(request.state.user), auth_enabled=ctx.settings.auth_enabled)

    async def change_password(request: Request) -> Response:
        user = request.state.user
        if not ctx.settings.auth_enabled:
            return _json("authentication is disabled", 409)
        try:
            data = await _body(request)
            full = ctx.accounts.get(user["id"])
            if not security.verify_password(_s(data, "current", 256), full["password_hash"]):
                aud(request, "password.change_failed")
                return _json("current password is incorrect", 403)
            ctx.accounts.set_password(user["id"], _s(data, "new", 256),
                                      keep_session_token=request.cookies.get(COOKIE))
        except AccountError as exc:
            return err(exc)
        aud(request, "password.changed", f"user:{user['id']}")
        return _json("ok", 200)

    async def totp_begin(request: Request) -> Response:
        user = request.state.user
        if not ctx.settings.auth_enabled:
            return _json("authentication is disabled", 409)
        secret = ctx.accounts.begin_totp(user["id"])
        return _json("ok", 200, secret=secret, uri=security.totp_uri(secret, user["username"]))

    async def totp_confirm(request: Request) -> Response:
        try:
            data = await _body(request)
        except AccountError as exc:
            return err(exc)
        if not ctx.accounts.confirm_totp(request.state.user["id"], _s(data, "code", 12)):
            return _json("that code is not valid", 400)
        aud(request, "totp.enabled", f"user:{request.state.user['id']}")
        return _json("ok", 200)

    async def totp_disable(request: Request) -> Response:
        user = request.state.user
        try:
            data = await _body(request)
            full = ctx.accounts.get(user["id"])
            if not security.verify_password(_s(data, "password", 256), full["password_hash"]):
                return _json("password is incorrect", 403)
        except AccountError as exc:
            return err(exc)
        ctx.accounts.disable_totp(user["id"])
        aud(request, "totp.disabled", f"user:{user['id']}")
        return _json("ok", 200)

    # ------------------------------------------------------------ user administration
    async def users_list(request: Request) -> Response:
        return JSONResponse(ctx.accounts.list_users(), headers={"Cache-Control": "no-store"})

    async def users_create(request: Request) -> Response:
        try:
            data = await _body(request)
            uid = ctx.accounts.create_user(_s(data, "username", 40), _s(data, "password", 256),
                                           _s(data, "role", 20) or "analyst", _s(data, "display_name", 80),
                                           must_change=bool(data.get("must_change", True)))
        except AccountError as exc:
            return err(exc)
        aud(request, "user.create", f"user:{uid}", f"role={data.get('role') or 'analyst'}")
        return _json("ok", 201, user=public(ctx.accounts.get(uid)))

    def uid_of(request: Request) -> int:
        try:
            return int(request.path_params["uid"])
        except (KeyError, ValueError):
            raise AccountError("invalid user id")

    async def users_patch(request: Request) -> Response:
        try:
            uid = uid_of(request)
            data = await _body(request)
            role = _s(data, "role", 20) if "role" in data else None
            disabled = data["disabled"] if "disabled" in data else None
            if disabled is not None and not isinstance(disabled, bool):
                raise AccountError("disabled must be true or false")
            name = _s(data, "display_name", 80) if "display_name" in data else None
            if uid == request.state.user["id"] and (disabled or (role and role != request.state.user["role"])):
                raise AccountError("you cannot change your own role or disable yourself")
            user = ctx.accounts.update_user(uid, role=role, disabled=disabled, display_name=name)
        except AccountError as exc:
            return err(exc)
        aud(request, "user.update", f"user:{uid}", ", ".join(sorted(data))[:200])
        return _json("ok", 200, user=user)

    async def users_password(request: Request) -> Response:
        try:
            uid = uid_of(request)
            data = await _body(request)
            ctx.accounts.set_password(uid, _s(data, "password", 256), must_change=True)
        except AccountError as exc:
            return err(exc)
        aud(request, "user.password_reset", f"user:{uid}")
        return _json("ok", 200)

    async def users_unlock(request: Request) -> Response:
        try:
            uid = uid_of(request)
        except AccountError as exc:
            return err(exc)
        ctx.accounts.unlock(uid)
        aud(request, "user.unlock", f"user:{uid}")
        return _json("ok", 200)

    async def users_reset_2fa(request: Request) -> Response:
        try:
            uid = uid_of(request)
        except AccountError as exc:
            return err(exc)
        ctx.accounts.disable_totp(uid)
        ctx.accounts.delete_user_sessions(uid)
        aud(request, "user.reset_2fa", f"user:{uid}")
        return _json("ok", 200)

    async def users_delete(request: Request) -> Response:
        try:
            uid = uid_of(request)
            if uid == request.state.user["id"]:
                raise AccountError("you cannot delete your own account")
            ctx.accounts.delete_user(uid)
        except AccountError as exc:
            return err(exc)
        aud(request, "user.delete", f"user:{uid}")
        return _json("ok", 200)

    # ------------------------------------------------------------ audit
    async def audit_list(request: Request) -> Response:
        q = request.query_params
        try:
            limit, offset = int(q.get("limit", 100)), int(q.get("offset", 0))
        except ValueError:
            return _json("limit and offset must be integers", 400)
        rows = ctx.audit.list(limit, offset, q.get("actor", "")[:80], q.get("action", "")[:80], q.get("since", "")[:40])
        return JSONResponse({"entries": rows, "total": ctx.audit.count()}, headers={"Cache-Control": "no-store"})

    async def audit_verify(request: Request) -> Response:
        result = ctx.audit.verify()
        aud(request, "audit.verify", "", "ok" if result["ok"] else f"BROKEN at {result['first_bad_seq']}")
        return JSONResponse(result)

    async def audit_export(request: Request) -> Response:
        fmt = request.query_params.get("format", "csv")
        if fmt not in ("csv", "json"):
            return _json("format must be csv or json", 400)
        aud(request, "audit.export", fmt)
        body = ctx.audit.export(fmt)
        media = "text/csv" if fmt == "csv" else "application/json"
        return PlainTextResponse(body, media_type=media, headers={
            "Content-Disposition": f'attachment; filename="cclass_audit.{fmt}"', "Cache-Control": "no-store"})

    return [
        Route("/api/auth/status", status, methods=["GET"]),
        Route("/api/auth/setup", setup, methods=["POST"]),
        Route("/api/auth/login", login, methods=["POST"]),
        Route("/api/auth/logout", logout, methods=["POST"]),
        Route("/api/auth/me", me, methods=["GET"]),
        Route("/api/auth/password", change_password, methods=["POST"]),
        Route("/api/auth/totp/begin", totp_begin, methods=["POST"]),
        Route("/api/auth/totp/confirm", totp_confirm, methods=["POST"]),
        Route("/api/auth/totp/disable", totp_disable, methods=["POST"]),
        Route("/api/users", users_list, methods=["GET"]),
        Route("/api/users", users_create, methods=["POST"]),
        Route("/api/users/{uid}", users_patch, methods=["PATCH"]),
        Route("/api/users/{uid}", users_delete, methods=["DELETE"]),
        Route("/api/users/{uid}/password", users_password, methods=["POST"]),
        Route("/api/users/{uid}/unlock", users_unlock, methods=["POST"]),
        Route("/api/users/{uid}/reset-2fa", users_reset_2fa, methods=["POST"]),
        Route("/api/audit", audit_list, methods=["GET"]),
        Route("/api/audit/verify", audit_verify, methods=["GET"]),
        Route("/api/audit/export", audit_export, methods=["GET"]),
    ]
