"""Auth middleware + account/audit routes, tested on plain Starlette (no FastAPI needed)."""
import pytest

pytest.importorskip("httpx")
from starlette.applications import Starlette  # noqa: E402
from starlette.responses import JSONResponse, PlainTextResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from cclass_suite import security  # noqa: E402
from cclass_suite.web.auth import AuthMiddleware, build_auth_routes  # noqa: E402
from cclass_suite.web.ops import build_ops_routes  # noqa: E402

PW = "Tr1cky-Passphrase!"
XHR = {"X-Requested-With": "cclass"}


def make_app(ctx):
    async def ok(request):
        return JSONResponse({"user": (request.state.user or {}).get("username")})

    async def boom(request):
        return JSONResponse({"detail": "nope"}, status_code=404)

    async def page(request):
        return PlainTextResponse("<html>shell</html>")

    routes = [
        Route("/", page),
        Route("/api/health", ok),
        Route("/api/overview", ok),
        Route("/api/investigate", ok, methods=["POST"]),
        Route("/api/investigations/1", boom, methods=["DELETE"]),
        Route("/api/settings", ok, methods=["GET", "PUT"]),
        Route("/api/reports/1/download", ok),
        Route("/api/unclassified", ok, methods=["POST"]),
    ]
    app = Starlette(routes=build_auth_routes(ctx) + build_ops_routes(ctx) + routes)
    app.add_middleware(AuthMiddleware, ctx=ctx)
    return app


@pytest.fixture()
def ctx(ctx):
    ctx.settings.auth_enabled = True
    return ctx


@pytest.fixture()
def app(ctx):
    return make_app(ctx)


def client_for(app):
    return TestClient(app, base_url="http://localhost", headers=XHR, client=("127.0.0.1", 5000))


def setup_admin(c):
    r = c.post("/api/auth/setup", json={"username": "admin1", "password": PW, "display_name": "Ada"})
    assert r.status_code == 201, r.text
    return r


def login(app, ctx, username, role, password=PW):
    ctx.accounts.create_user(username, password, role)
    c = client_for(app)
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return c


def test_shell_and_public_endpoints_open_api_closed(app):
    c = client_for(app)
    assert c.get("/").status_code == 200
    assert c.get("/api/health").status_code == 200
    st = c.get("/api/auth/status").json()
    assert st["auth_enabled"] and st["setup_required"] and not st["authenticated"]
    assert c.get("/api/overview").status_code == 401
    assert c.get("/api/users").status_code == 401


def test_first_run_setup_logs_in_then_closes(app, ctx):
    c = client_for(app)
    r = setup_admin(c)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert c.get("/api/overview").status_code == 200
    assert c.get("/api/auth/me").json()["user"]["role"] == "admin"
    assert client_for(app).post("/api/auth/setup", json={"username": "x" * 5, "password": PW}).status_code == 409
    assert c.get("/api/auth/status").json()["setup_required"] is False


def test_setup_needs_token_from_non_local_client(app, ctx):
    c = TestClient(app, base_url="http://localhost", headers=XHR, client=("203.0.113.9", 5000))
    r = c.post("/api/auth/setup", json={"username": "admin1", "password": PW})
    assert r.status_code == 403 and ctx.accounts.count() == 0


def test_setup_rejects_weak_password(app):
    r = client_for(app).post("/api/auth/setup", json={"username": "admin1", "password": "weak"})
    assert r.status_code == 400 and "12 characters" in r.json()["detail"]


def test_csrf_header_required_for_mutations(app, ctx):
    c = login(app, ctx, "ana", "analyst")
    no_hdr = TestClient(app, base_url="http://localhost")
    no_hdr.cookies.update(c.cookies)
    assert no_hdr.post("/api/investigate", json={}).status_code == 403
    assert no_hdr.get("/api/overview").status_code == 200       # reads need no header
    assert c.post("/api/investigate", json={}).status_code == 200


def test_login_failures_are_generic_and_audited(app, ctx):
    ctx.accounts.create_user("ana", PW, "analyst")
    c = client_for(app)
    bad_pw = c.post("/api/auth/login", json={"username": "ana", "password": "wrong"})
    ghost = c.post("/api/auth/login", json={"username": "ghost", "password": "wrong"})
    assert bad_pw.status_code == ghost.status_code == 401
    assert bad_pw.json() == ghost.json()
    actions = [e["action"] for e in ctx.audit.list(50)]
    assert actions.count("login.fail.invalid") == 2
    assert ctx.audit.verify()["ok"]


def test_lockout_hides_state_but_blocks_login(app, ctx):
    ctx.accounts.create_user("ana", PW, "analyst")
    c = client_for(app)
    for _ in range(5):
        c.post("/api/auth/login", json={"username": "ana", "password": "wrong"})
    r = c.post("/api/auth/login", json={"username": "ana", "password": PW})
    assert r.status_code == 401
    assert any(e["action"] == "login.fail.locked" for e in ctx.audit.list(50))


def test_ip_rate_limit(app, ctx):
    c = client_for(app)
    codes = [c.post("/api/auth/login", json={"username": "u", "password": "p"}).status_code for _ in range(25)]
    assert 429 in codes


@pytest.mark.parametrize("role,method,path,expected", [
    ("viewer", "GET", "/api/overview", 200),
    ("viewer", "POST", "/api/investigate", 403),
    ("viewer", "GET", "/api/users", 403),
    ("analyst", "POST", "/api/investigate", 200),
    ("analyst", "PUT", "/api/settings", 403),
    ("analyst", "GET", "/api/settings", 403),
    ("analyst", "GET", "/api/audit", 403),
    ("analyst", "POST", "/api/unclassified", 200),
    ("admin", "PUT", "/api/settings", 200),
    ("admin", "GET", "/api/audit", 200),
    ("admin", "GET", "/api/users", 200),
])
def test_rbac_matrix(app, ctx, role, method, path, expected):
    c = login(app, ctx, f"{role}1", role)
    assert c.request(method, path, json={} if method != "GET" else None).status_code == expected


def test_denials_and_mutations_are_audited(app, ctx):
    v = login(app, ctx, "vic", "viewer")
    v.post("/api/investigate", json={})
    a = login(app, ctx, "ana", "analyst")
    a.post("/api/investigate", json={})
    a.delete("/api/investigations/1")
    a.get("/api/reports/1/download")
    log = ctx.audit.list(100)
    acts = {(e["actor"], e["action"]) for e in log}
    assert ("vic", "access.denied") in acts
    assert ("ana", "api.post") in acts and ("ana", "api.delete") in acts
    assert ("ana", "api.get") in acts                  # downloads are audited
    assert not any(e["actor"] == "ana" and e["target"] == "/api/overview" for e in log)
    assert ctx.audit.verify()["ok"]


def test_logout_invalidates_session(app, ctx):
    c = login(app, ctx, "ana", "analyst")
    assert c.get("/api/overview").status_code == 200
    token = c.cookies.get("cclass_session")
    assert c.post("/api/auth/logout").status_code == 200
    c.cookies.set("cclass_session", token)
    assert c.get("/api/overview").status_code == 401


def test_forged_cookie_rejected(app):
    c = client_for(app)
    c.cookies.set("cclass_session", "A" * 43)
    assert c.get("/api/overview").status_code == 401


def test_user_admin_flow(app, ctx):
    admin = login(app, ctx, "boss1", "admin")
    r = admin.post("/api/users", json={"username": "newbie", "password": PW, "role": "viewer"})
    assert r.status_code == 201
    uid = r.json()["user"]["id"]
    assert "password_hash" not in r.text and "totp_secret" not in r.text
    assert "password_hash" not in admin.get("/api/users").text
    # new accounts must change their password before doing anything else
    n = client_for(app)
    assert n.post("/api/auth/login", json={"username": "newbie", "password": PW}).status_code == 200
    blocked = n.get("/api/overview")
    assert blocked.status_code == 403 and blocked.json()["password_change_required"]
    ok = n.post("/api/auth/password", json={"current": PW, "new": "Br4nd-New-Passphrase?"})
    assert ok.status_code == 200
    assert n.get("/api/overview").status_code == 200
    # role change, disable, no self-lockout
    assert admin.patch(f"/api/users/{uid}", json={"role": "analyst"}).json()["user"]["role"] == "analyst"
    me = admin.get("/api/auth/me").json()["user"]["id"]
    assert admin.patch(f"/api/users/{me}", json={"disabled": True}).status_code == 400
    assert admin.delete(f"/api/users/{me}").status_code == 400
    assert admin.patch(f"/api/users/{uid}", json={"disabled": True}).status_code == 200
    assert n.get("/api/overview").status_code == 401
    acts = [e["action"] for e in ctx.audit.list(100)]
    assert "user.create" in acts and "user.update" in acts and "password.changed" in acts


def test_wrong_current_password_rejected(app, ctx):
    c = login(app, ctx, "ana", "analyst")
    r = c.post("/api/auth/password", json={"current": "nope", "new": "Br4nd-New-Passphrase?"})
    assert r.status_code == 403


def test_totp_enrolment_and_login(app, ctx):
    c = login(app, ctx, "ana", "analyst")
    begin = c.post("/api/auth/totp/begin").json()
    assert begin["uri"].startswith("otpauth://")
    assert c.post("/api/auth/totp/confirm", json={"code": "000000"}).status_code == 400
    code = security.totp_at(begin["secret"])
    assert c.post("/api/auth/totp/confirm", json={"code": code}).status_code == 200
    fresh = client_for(app)
    r = fresh.post("/api/auth/login", json={"username": "ana", "password": PW})
    assert r.json().get("totp_required") is True and "set-cookie" not in r.headers
    import time
    nxt = security.totp_at(begin["secret"], time.time() + 30)
    ok = fresh.post("/api/auth/login", json={"username": "ana", "password": PW, "totp": nxt})
    assert ok.status_code == 200 and fresh.get("/api/overview").status_code == 200


def test_audit_endpoints(app, ctx):
    admin = login(app, ctx, "boss1", "admin")
    admin.post("/api/investigate", json={})
    data = admin.get("/api/audit?limit=5").json()
    assert data["total"] >= 2 and len(data["entries"]) <= 5
    assert admin.get("/api/audit/verify").json()["ok"] is True
    exp = admin.get("/api/audit/export?format=csv")
    assert exp.status_code == 200 and "attachment" in exp.headers["content-disposition"]
    assert admin.get("/api/audit/export?format=xml").status_code == 400
    assert admin.get("/api/audit?limit=abc").status_code == 400


def test_auth_disabled_mode_acts_as_local_admin(app, ctx):
    ctx.settings.auth_enabled = False
    c = client_for(app)
    assert c.get("/api/overview").json()["user"] == "local"
    assert c.put("/api/settings", json={}).status_code == 200
    assert c.post("/api/auth/login", json={"username": "a", "password": "b"}).status_code == 409
    assert TestClient(app, base_url="http://localhost").post("/api/investigate", json={}).status_code == 403  # CSRF header still enforced


def test_responses_not_cacheable(app, ctx):
    c = login(app, ctx, "ana", "analyst")
    assert c.get("/api/overview").headers["cache-control"] == "no-store"


def test_backup_api_flow_and_permissions(app, ctx):
    admin = login(app, ctx, "boss1", "admin")
    ana = login(app, ctx, "ana", "analyst")
    assert ana.get("/api/backups").status_code == 403
    assert ana.post("/api/backups").status_code == 403
    r = admin.post("/api/backups")
    assert r.status_code == 201
    name = r.json()["name"]
    assert admin.get("/api/backups").json()["backups"][0]["name"] == name
    assert admin.get(f"/api/backups/{name}/verify").json()["ok"] is True
    dl = admin.get(f"/api/backups/{name}/download")
    assert dl.status_code == 200 and dl.content[:2] == b"PK"
    assert admin.get("/api/backups/..%2f..%2fetc%2fpasswd/download").status_code == 404
    assert admin.get("/api/backups/evil.zip/verify").status_code == 404
    pre = admin.post("/api/retention/run", json={"dry_run": True}).json()
    assert pre["dry_run"] is True and "would_remove" in pre
    assert ana.post("/api/retention/run", json={}).status_code == 403
    acts = {e["action"] for e in ctx.audit.list(100)}
    assert {"backup.create", "backup.verify", "backup.download", "retention.preview"} <= acts
    assert admin.delete(f"/api/backups/{name}").status_code == 200
    assert admin.get("/api/backups").json()["backups"] == []
    assert ctx.audit.verify()["ok"]
