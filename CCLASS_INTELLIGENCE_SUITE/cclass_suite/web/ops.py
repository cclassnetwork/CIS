"""Administrator operations API: backups and data retention (plain Starlette routes)."""
from __future__ import annotations

from pathlib import Path
from typing import List

from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route

from .. import backup
from .auth import _json, client_ip


def build_ops_routes(ctx) -> List[Route]:
    def aud(request: Request, action: str, target: str = "", detail: str = "") -> None:
        u = request.state.user or {"username": "anonymous", "id": None}
        ctx.audit.append(u["username"], action, target, detail, client_ip(request, ctx.settings.trust_proxy),
                         u.get("id") or None)

    def named(request: Request):
        try:
            return backup.resolve_backup(ctx.settings, request.path_params["name"])
        except backup.BackupError as exc:
            return _json(str(exc), 404)

    async def list_(request: Request) -> Response:
        return JSONResponse({"backups": backup.list_backups(ctx.settings), "keep": ctx.settings.backup_keep,
                             "directory": str(ctx.settings.backups_dir)}, headers={"Cache-Control": "no-store"})

    async def create(request: Request) -> Response:
        try:
            path = backup.create_backup(ctx.settings)
        except (OSError, backup.BackupError) as exc:
            return _json(f"backup failed: {exc}", 500)
        removed = backup.prune_backups(ctx.settings)
        aud(request, "backup.create", path.name, f"pruned={len(removed)}")
        return _json("ok", 201, name=path.name, size=path.stat().st_size, pruned=removed)

    async def verify(request: Request) -> Response:
        p = named(request)
        if isinstance(p, Response):
            return p
        res = backup.verify_backup(p)
        aud(request, "backup.verify", p.name, "ok" if res["ok"] else "FAILED")
        return JSONResponse(res)

    async def download(request: Request) -> Response:
        p = named(request)
        if isinstance(p, Response):
            return p
        aud(request, "backup.download", p.name)
        return FileResponse(p, filename=p.name, media_type="application/zip", headers={"Cache-Control": "no-store"})

    async def delete(request: Request) -> Response:
        p = named(request)
        if isinstance(p, Response):
            return p
        p.unlink()
        aud(request, "backup.delete", p.name)
        return _json("ok", 200)

    async def retention(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        dry = bool((body or {}).get("dry_run", True))
        res = backup.apply_retention(ctx.db, ctx.settings.retention_alert_days,
                                     ctx.settings.retention_activity_days, dry_run=dry)
        aud(request, "retention.preview" if dry else "retention.run", "", str(res))
        return JSONResponse({"dry_run": dry, "removed" if not dry else "would_remove": res,
                             "alert_days": ctx.settings.retention_alert_days,
                             "activity_days": ctx.settings.retention_activity_days})

    return [
        Route("/api/backups", list_, methods=["GET"]),
        Route("/api/backups", create, methods=["POST"]),
        Route("/api/backups/{name}/verify", verify, methods=["GET"]),
        Route("/api/backups/{name}/download", download, methods=["GET"]),
        Route("/api/backups/{name}", delete, methods=["DELETE"]),
        Route("/api/retention/run", retention, methods=["POST"]),
    ]
