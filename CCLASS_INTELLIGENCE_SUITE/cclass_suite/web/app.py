"""FastAPI application: REST API plus the single-page dashboard."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field, field_validator

from .. import __version__
from ..config import Settings, SettingsError
from ..context import AppContext
from ..demo import load_demo
from ..ingest import persist_result
from ..modules import CATALOG, REGISTRY
from ..modules.networkintel import AuthorizationError
from ..modules.reportgen import CONTENT_TYPES, FORMATS
from ..scheduler import TASK_TYPES
from ..scoring import RELIABILITY_LABEL
from ..utils import detect_type
from starlette.responses import HTMLResponse as _HTML
from starlette.routing import Route as _Route

from ..graphlab.routes import build_graphlab_routes
from .auth import AuthMiddleware, build_auth_routes
from .ops import build_ops_routes

log = logging.getLogger("cclass.web")
WEB_DIR = Path(__file__).resolve().parent
LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]", "testserver"}
SEVERITY = Literal["info", "low", "medium", "high", "critical"]
PRIORITY = Literal["low", "medium", "high", "critical"]
TLP = Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]


# ---------------------------------------------------------------- request models
class InvestigationIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=5000)
    priority: PRIORITY = "medium"
    tlp: TLP = "AMBER"
    tags: List[str] = Field(default_factory=list, max_length=10)
    due_date: Optional[str] = Field(default=None, max_length=10)
    assignee_id: Optional[int] = None


class InvestigationPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    status: Optional[Literal["open", "closed", "archived"]] = None
    priority: Optional[PRIORITY] = None
    tlp: Optional[TLP] = None
    tags: Optional[List[str]] = Field(default=None, max_length=10)
    due_date: Optional[str] = Field(default=None, max_length=10)      # null / "" clears it
    assignee_id: Optional[int] = None                                 # null clears it


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class InvestigateIn(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    investigation_id: Optional[int] = None
    modules: Optional[List[str]] = None
    pivot: bool = True


class ModuleRunIn(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    investigation_id: Optional[int] = None
    authorized: bool = False
    ports: Optional[List[int]] = Field(default=None, max_length=100)
    options: Optional[Dict[str, Any]] = None  # only keys a module lists in api_options are passed on


class WatchlistIn(BaseModel):
    kind: Literal["keyword", "product", "vendor", "cve", "domain", "ip", "email", "username"]
    value: str = Field(min_length=2, max_length=200)
    notes: str = Field(default="", max_length=500)

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class TaskIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    task_type: Literal["feed_refresh", "watchlist_scan", "backup", "retention"]
    interval_minutes: int = Field(ge=1, le=10080)
    enabled: bool = True


class ReportIn(BaseModel):
    investigation_id: int
    format: str = "html"


class SourcePatch(BaseModel):
    reliability: Literal["A", "B", "C", "D", "E", "F"]


class EnabledIn(BaseModel):
    enabled: bool


def hostname_of(host_header: str) -> str:
    """Hostname part of a Host header, lower-cased; IPv6 literals keep their brackets."""
    h = host_header.strip().lower()
    if h.startswith("["):
        return h.split("]", 1)[0] + "]"
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def create_app(ctx: Optional[AppContext] = None) -> FastAPI:
    ctx = ctx or AppContext()
    app = FastAPI(title="CCLASS Intelligence Suite", version=__version__, docs_url="/api/docs", redoc_url=None)
    app.state.ctx = ctx
    env = Environment(loader=FileSystemLoader(str(WEB_DIR / "templates")), autoescape=select_autoescape(["html"]))
    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

    if not ctx.settings.auth_enabled and ctx.settings.host not in ("127.0.0.1", "::1", "localhost") \
            and os.environ.get("CCLASS_ALLOW_INSECURE") != "1":
        raise RuntimeError(
            "Refusing to serve a network-reachable dashboard with authentication disabled. "
            "Re-enable authentication, bind to 127.0.0.1, or set CCLASS_ALLOW_INSECURE=1 if you "
            "really accept the risk.")

    def allowed_hosts() -> set:
        return LOOPBACK | {ctx.settings.host.lower()} | set(ctx.settings.allowed_hosts)

    # Authentication / RBAC / audit (added first so the guard below wraps it).
    app.add_middleware(AuthMiddleware, ctx=ctx)
    async def graphlab_page(request: Request) -> _HTML:
        vendor = WEB_DIR / "static" / "vendor"
        return _HTML(env.get_template("graphlab.html").render(local_vendor=(vendor / "bootstrap.min.css").exists()),
                     headers={"Cache-Control": "no-store"})

    app.router.routes[0:0] = (build_auth_routes(ctx) + build_ops_routes(ctx) + build_graphlab_routes(ctx)
                              + [_Route("/graphlab", graphlab_page, methods=["GET"])])

    # ------------------------------------------------------------ request guard
    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = hostname_of(request.headers.get("host") or "")
        bind = ctx.settings.host
        wildcard = bind in ("0.0.0.0", "::") and not ctx.settings.allowed_hosts
        if not wildcard and host not in allowed_hosts():
            return JSONResponse({"detail": "host header not allowed"}, status_code=403)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and urlparse(origin).netloc.lower() != (request.headers.get("host") or "").lower():
                return JSONResponse({"detail": "cross-origin request blocked"}, status_code=403)
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001
            log.exception("unhandled error on %s %s", request.method, request.url.path)
            return JSONResponse({"detail": "internal server error"}, status_code=500)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        # Not "no-referrer": OpenStreetMap rejects map-tile requests that carry no Referer (HTTP 403).
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if ctx.settings.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.on_event("startup")
    def _start() -> None:
        if ctx.settings.scheduler_enabled:
            ctx.scheduler.start()

    @app.on_event("shutdown")
    def _stop() -> None:
        ctx.scheduler.stop()

    def need_inv(inv_id: int) -> Dict[str, Any]:
        inv = ctx.db.get_investigation(inv_id)
        if inv is None:
            raise HTTPException(404, "investigation not found")
        return inv

    # ------------------------------------------------------------ pages
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index() -> str:
        vendor = WEB_DIR / "static" / "vendor"
        local = (vendor / "bootstrap.min.css").exists()
        return env.get_template("index.html").render(version=__version__, local_vendor=local)

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok", "version": __version__, "offline_mode": ctx.settings.offline_mode,
                "schema_version": ctx.db.schema_version(), "scheduler_running": ctx.scheduler.running}

    # ------------------------------------------------------------ overview / search
    @app.get("/api/overview")
    def overview() -> Dict[str, Any]:
        stats = ctx.db.stats()
        stats["recent_activity"] = ctx.db.list_activity(15)
        stats["recent_alerts"] = ctx.db.list_alerts(limit=6)
        stats["offline_mode"] = ctx.settings.offline_mode
        stats["overlaps"] = ctx.db.cross_investigation_overlaps(10)
        return stats

    @app.get("/api/search")
    def search(q: str = Query(min_length=1, max_length=500)) -> Dict[str, Any]:
        return ctx.xkey.search(q)

    @app.post("/api/investigate")
    def investigate(body: InvestigateIn) -> Dict[str, Any]:
        try:
            return ctx.xkey.investigate(body.query, body.investigation_id, body.modules, body.pivot)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/detect")
    def detect(q: str = Query(max_length=500)) -> Dict[str, str]:
        return {"type": detect_type(q)}

    # ------------------------------------------------------------ modules
    @app.get("/api/modules")
    def modules() -> List[Dict[str, Any]]:
        return CATALOG

    @app.post("/api/modules/{name}/run")
    def run_module(name: str, body: ModuleRunIn) -> Dict[str, Any]:
        mod = REGISTRY.get(name.upper())
        if mod is None:
            raise HTTPException(404, "unknown module")
        if mod.cli_only:
            raise HTTPException(400, f"{mod.name} analyses uploaded evidence; attach a file to an investigation instead")
        inv_id = body.investigation_id
        if inv_id is not None:
            need_inv(inv_id)
        if mod.requires_authorization:
            if not body.authorized:
                raise HTTPException(400, "authorisation confirmation is required for this module")
            result = mod.safe_run(body.query, ctx.mctx, authorized=True, ports=body.ports)
        else:
            extra = {k: v for k, v in (body.options or {}).items() if k in mod.api_options}
            result = mod.safe_run(body.query, ctx.mctx, **extra)
        created = False
        if inv_id is None:
            inv_id = ctx.db.create_investigation(f"{mod.name}: {body.query[:60]}", "Created from a module run.")
            created = True
        stats = persist_result(ctx.db, inv_id, result)
        insights = ctx.correlation.correlate(inv_id)
        return {"investigation_id": inv_id, "created_investigation": created, "result": result.to_dict(),
                "stats": stats, "insights": insights}

    # ------------------------------------------------------------ investigations
    def me(request: Request) -> Dict[str, Any]:
        return getattr(request.state, "user", None) or {"id": None, "username": "anonymous", "role": "viewer"}

    def audit_case(request: Request, action: str, inv_id: int, detail: str = "") -> None:
        u = me(request)
        ctx.audit.append(u["username"], action, f"investigation:{inv_id}", detail,
                         getattr(request.state, "ip", "") or "", u.get("id") or None)

    @app.get("/api/people")
    def people() -> List[Dict[str, Any]]:
        """Active users that cases can be assigned to (no sensitive fields)."""
        return [{"id": u["id"], "username": u["username"], "display_name": u["display_name"], "role": u["role"]}
                for u in ctx.accounts.list_users() if not u["disabled"]]

    @app.get("/api/investigations")
    def list_investigations(request: Request, status: Optional[str] = None, assignee_id: Optional[int] = None,
                            tag: Optional[str] = Query(None, max_length=40), tlp: Optional[TLP] = None,
                            overdue: bool = False, mine: bool = False) -> List[Dict[str, Any]]:
        if mine:
            assignee_id = me(request).get("id")
        return ctx.db.list_investigations(status, assignee_id, tag, tlp, overdue)

    @app.post("/api/investigations", status_code=201)
    def create_investigation(body: InvestigationIn, request: Request) -> Dict[str, Any]:
        try:
            inv_id = ctx.db.create_investigation(body.name, body.description, body.priority, body.tlp,
                                                 body.tags, body.due_date, body.assignee_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        audit_case(request, "case.create", inv_id, f"tlp={body.tlp}")
        return need_inv(inv_id)

    @app.get("/api/investigations/{inv_id}")
    def get_investigation(inv_id: int) -> Dict[str, Any]:
        inv = need_inv(inv_id)
        inv["activity"] = ctx.db.list_activity(30, inv_id)
        return inv

    @app.patch("/api/investigations/{inv_id}")
    def patch_investigation(inv_id: int, body: InvestigationPatch, request: Request) -> Dict[str, Any]:
        before = need_inv(inv_id)
        changes = body.model_dump(exclude_unset=True)
        if changes.get("due_date") == "":
            changes["due_date"] = None
        try:
            ctx.db.update_investigation(inv_id, **changes)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        after = need_inv(inv_id)
        notable = [k for k in ("assignee_id", "tlp", "status", "due_date", "priority") if before.get(k) != after.get(k)]
        if notable:
            audit_case(request, "case.update", inv_id,
                       "; ".join(f"{k}: {before.get(k)} -> {after.get(k)}" for k in notable))
        return after

    @app.delete("/api/investigations/{inv_id}")
    def delete_investigation(inv_id: int) -> Dict[str, bool]:
        if not ctx.delete_investigation(inv_id):
            raise HTTPException(404, "investigation not found")
        return {"deleted": True}

    @app.get("/api/investigations/{inv_id}/comments")
    def list_comments(inv_id: int) -> List[Dict[str, Any]]:
        need_inv(inv_id)
        return ctx.db.list_comments(inv_id)

    @app.post("/api/investigations/{inv_id}/comments", status_code=201)
    def add_comment(inv_id: int, body: CommentIn, request: Request) -> Dict[str, Any]:
        need_inv(inv_id)
        u = me(request)
        try:
            cid = ctx.db.add_comment(inv_id, u.get("id"), u.get("display_name") or u["username"], body.body)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return ctx.db.get_comment(cid)  # type: ignore[return-value]

    @app.delete("/api/comments/{comment_id}")
    def delete_comment(comment_id: int, request: Request) -> Dict[str, bool]:
        c = ctx.db.get_comment(comment_id)
        if c is None:
            raise HTTPException(404, "comment not found")
        u = me(request)
        if u.get("role") != "admin" and (not u.get("id") or c["user_id"] != u["id"]):
            raise HTTPException(403, "you can only delete your own comments")
        ctx.db.delete_comment(comment_id)
        audit_case(request, "case.comment_delete", c["investigation_id"], f"comment:{comment_id}")
        return {"deleted": True}

    @app.get("/api/investigations/{inv_id}/findings")
    def findings(inv_id: int, severity: Optional[SEVERITY] = None, module: Optional[str] = None,
                 limit: int = Query(500, ge=1, le=5000), offset: int = Query(0, ge=0)) -> List[Dict[str, Any]]:
        need_inv(inv_id)
        return ctx.db.list_findings(inv_id, severity, module, limit, offset)

    @app.get("/api/investigations/{inv_id}/entities")
    def entities(inv_id: int, type: Optional[str] = None) -> List[Dict[str, Any]]:
        need_inv(inv_id)
        return ctx.db.list_entities(inv_id, type)

    @app.get("/api/investigations/{inv_id}/graph")
    def graph(inv_id: int) -> Dict[str, Any]:
        need_inv(inv_id)
        return ctx.db.graph(inv_id)

    @app.get("/api/investigations/{inv_id}/timeline")
    def timeline(inv_id: int, limit: int = Query(300, ge=1, le=2000)) -> List[Dict[str, Any]]:
        need_inv(inv_id)
        return ctx.db.timeline(inv_id, limit)

    @app.post("/api/investigations/{inv_id}/correlate")
    def correlate(inv_id: int) -> Dict[str, Any]:
        need_inv(inv_id)
        return {"insights": ctx.correlation.correlate(inv_id)}

    @app.get("/api/map")
    def map_points(investigation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        return ctx.db.map_points(investigation_id)

    # ------------------------------------------------------------ evidence
    @app.get("/api/investigations/{inv_id}/evidence")
    def list_evidence(inv_id: int) -> List[Dict[str, Any]]:
        need_inv(inv_id)
        return ctx.db.list_evidence(inv_id)

    @app.post("/api/investigations/{inv_id}/evidence", status_code=201)
    async def upload_evidence(inv_id: int, file: UploadFile = File(...), notes: str = Form(""),
                              analyze: bool = Form(True)) -> Dict[str, Any]:
        need_inv(inv_id)
        limit = ctx.settings.max_upload_mb * 1024 * 1024
        tmp = ctx.temp_upload_path()
        size = 0
        try:
            with open(tmp, "wb") as out:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise HTTPException(413, f"file exceeds the {ctx.settings.max_upload_mb} MB limit")
                    out.write(chunk)
            if size == 0:
                raise HTTPException(400, "empty file")
            info = ctx.add_evidence_from_path(inv_id, tmp, file.filename or "upload.bin", notes[:2000])
        finally:
            tmp.unlink(missing_ok=True)
        if analyze and not info.get("duplicate"):
            info["analysis"] = ctx.analyze_evidence(info["id"])
        return info

    @app.post("/api/evidence/{evidence_id}/analyze")
    def analyze_evidence(evidence_id: int) -> Dict[str, Any]:
        try:
            return ctx.analyze_evidence(evidence_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/evidence/{evidence_id}/download")
    def download_evidence(evidence_id: int) -> FileResponse:
        ev = ctx.db.get_evidence(evidence_id)
        path = Path(ev["stored_path"]).resolve() if ev else None
        if not ev or not path or not path.is_file() or not str(path).startswith(str(ctx.settings.evidence_dir.resolve())):
            raise HTTPException(404, "evidence not found")
        return FileResponse(path, filename=ev["filename"], media_type="application/octet-stream")

    @app.delete("/api/evidence/{evidence_id}")
    def delete_evidence(evidence_id: int) -> Dict[str, bool]:
        if not ctx.delete_evidence(evidence_id):
            raise HTTPException(404, "evidence not found")
        return {"deleted": True}

    # ------------------------------------------------------------ threat alerts / watchlists / feeds
    @app.get("/api/alerts")
    def alerts(severity: Optional[SEVERITY] = None, matched_only: bool = False, q: Optional[str] = Query(None, max_length=200),
               hide_acknowledged: bool = False, limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0)):
        return ctx.db.list_alerts(severity, matched_only, q, not hide_acknowledged, limit, offset)

    @app.post("/api/alerts/{alert_id}/ack")
    def ack(alert_id: int, body: EnabledIn) -> Dict[str, bool]:
        if not ctx.db.acknowledge_alert(alert_id, body.enabled):
            raise HTTPException(404, "alert not found")
        return {"ok": True}

    @app.post("/api/feeds/refresh")
    def refresh_feeds(sample: bool = False) -> Dict[str, Any]:
        return ctx.feeds.refresh(offline_sample=sample)

    @app.get("/api/watchlists")
    def watchlists() -> List[Dict[str, Any]]:
        return ctx.db.list_watchlists()

    @app.post("/api/watchlists", status_code=201)
    def add_watchlist(body: WatchlistIn) -> Dict[str, Any]:
        wid, created = ctx.db.add_watchlist(body.kind, body.value, body.notes)
        matched = ctx.feeds.match_watchlists()
        return {"id": wid, "created": created, "alerts_matched": matched}

    @app.post("/api/watchlists/{watch_id}/active")
    def watch_active(watch_id: int, body: EnabledIn) -> Dict[str, bool]:
        if not ctx.db.set_watchlist_active(watch_id, body.enabled):
            raise HTTPException(404, "watchlist entry not found")
        ctx.feeds.match_watchlists()
        return {"ok": True}

    @app.delete("/api/watchlists/{watch_id}")
    def del_watchlist(watch_id: int) -> Dict[str, bool]:
        if not ctx.db.delete_watchlist(watch_id):
            raise HTTPException(404, "watchlist entry not found")
        return {"deleted": True}

    # ------------------------------------------------------------ scheduled tasks
    @app.get("/api/tasks")
    def tasks() -> Dict[str, Any]:
        return {"tasks": ctx.db.list_tasks(), "scheduler_running": ctx.scheduler.running, "types": list(TASK_TYPES)}

    @app.post("/api/tasks", status_code=201)
    def add_task(body: TaskIn, request: Request) -> Dict[str, Any]:
        user = getattr(request.state, "user", None) or {}
        if body.task_type in ("backup", "retention") and user.get("role") != "admin":
            raise HTTPException(403, "only administrators can schedule backup or retention tasks")
        return {"id": ctx.db.add_task(body.name, body.task_type, body.interval_minutes, {}, body.enabled)}

    @app.post("/api/tasks/{task_id}/run")
    def run_task(task_id: int) -> Dict[str, str]:
        if ctx.db.get_task(task_id) is None:
            raise HTTPException(404, "task not found")
        status, message = ctx.scheduler.run_task(task_id)
        return {"status": status, "message": message}

    @app.post("/api/tasks/{task_id}/enabled")
    def task_enabled(task_id: int, body: EnabledIn) -> Dict[str, bool]:
        if not ctx.db.set_task_enabled(task_id, body.enabled):
            raise HTTPException(404, "task not found")
        return {"ok": True}

    @app.delete("/api/tasks/{task_id}")
    def del_task(task_id: int) -> Dict[str, bool]:
        if not ctx.db.delete_task(task_id):
            raise HTTPException(404, "task not found")
        return {"deleted": True}

    # ------------------------------------------------------------ sources
    @app.get("/api/sources")
    def sources() -> Dict[str, Any]:
        return {"sources": ctx.db.list_sources(), "scale": RELIABILITY_LABEL}

    @app.patch("/api/sources/{source_id}")
    def patch_source(source_id: int, body: SourcePatch) -> Dict[str, bool]:
        if not ctx.db.set_source_reliability(source_id, body.reliability):
            raise HTTPException(404, "source not found")
        return {"ok": True}

    # ------------------------------------------------------------ reports
    @app.get("/api/reports")
    def reports(investigation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        return ctx.db.list_reports(investigation_id)

    @app.post("/api/reports", status_code=201)
    def make_report(body: ReportIn) -> Dict[str, Any]:
        if body.format.lower() not in FORMATS:
            raise HTTPException(400, f"format must be one of {', '.join(FORMATS)}")
        need_inv(body.investigation_id)
        try:
            path = ctx.reports.generate(body.investigation_id, body.format)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
        rep = ctx.db.list_reports(body.investigation_id)[0]
        return {**rep, "filename": path.name}

    @app.get("/api/reports/{report_id}/download")
    def download_report(report_id: int, inline: bool = False) -> Response:
        rep = ctx.db.get_report(report_id)
        path = Path(rep["path"]).resolve() if rep else None
        if not rep or not path or not path.is_file() or not str(path).startswith(str(ctx.settings.reports_dir.resolve())):
            raise HTTPException(404, "report not found")
        headers = {"Content-Security-Policy": "sandbox"} if rep["format"] == "html" else {}
        resp = FileResponse(path, media_type=CONTENT_TYPES.get(rep["format"], "application/octet-stream"),
                            filename=None if inline else path.name, headers=headers)
        return resp

    # ------------------------------------------------------------ settings / demo
    @app.get("/api/settings")
    def get_settings() -> Dict[str, Any]:
        return ctx.settings.to_public_dict()

    @app.put("/api/settings")
    def put_settings(changes: Dict[str, Any]) -> Dict[str, Any]:
        try:
            ctx.settings.update(changes)
            ctx.settings.save()
        except SettingsError as exc:
            raise HTTPException(400, str(exc)) from exc
        if ctx.settings.scheduler_enabled:
            ctx.scheduler.start()
        else:
            ctx.scheduler.stop()
        ctx.db.log("settings_changed", ", ".join(sorted(changes))[:300])
        return ctx.settings.to_public_dict()

    @app.post("/api/demo")
    def demo() -> Dict[str, Any]:
        return load_demo(ctx)

    @app.get("/api/activity")
    def activity(limit: int = Query(100, ge=1, le=500)) -> List[Dict[str, Any]]:
        return ctx.db.list_activity(limit)

    return app
