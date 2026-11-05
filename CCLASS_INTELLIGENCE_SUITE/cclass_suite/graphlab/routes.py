"""Graph Lab HTTP API (plain Starlette routes; RBAC/CSRF/audit come from AuthMiddleware)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ..utils import detect_type
from . import engine, social, transforms
from .store import MAX_IMPORT_BYTES, TYPES, GraphError, GraphStore

MAX_BODY = MAX_IMPORT_BYTES + 4096


def _json(payload: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers={"Cache-Control": "no-store"})


def _err(exc: GraphError) -> JSONResponse:
    msg = str(exc)
    return _json({"detail": msg}, 404 if msg.endswith("not found") else 400)


async def _body(request: Request) -> Dict[str, Any]:
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise GraphError("Request body is too large")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        raise GraphError("Body must be valid JSON") from None
    if not isinstance(data, dict):
        raise GraphError("Body must be a JSON object")
    return data


def _actor(request: Request) -> str:
    u = getattr(request.state, "user", None) or {}
    return u.get("username", "anonymous")


def build_graphlab_routes(ctx) -> List[Route]:
    store: GraphStore = ctx.graphs

    def guarded(fn):
        async def handler(request: Request) -> Response:
            try:
                return await fn(request)
            except GraphError as exc:
                return _err(exc)
        return handler

    @guarded
    async def meta(request: Request) -> Response:
        return _json({"types": {k: {"label": v[0], "color": v[1]} for k, v in TYPES.items()},
                      "transforms": [t.public() for t in transforms.TRANSFORMS.values()],
                      "offline_mode": ctx.settings.offline_mode,
                      "limits": {"max_selection": engine.MAX_SELECTION, "max_entities_per_run": transforms.MAX_ENTITIES_PER_RUN}})

    @guarded
    async def graphs_list(request: Request) -> Response:
        return _json(await run_in_threadpool(store.list_graphs))

    @guarded
    async def graphs_create(request: Request) -> Response:
        d = await _body(request)
        gid = await run_in_threadpool(store.create_graph, str(d.get("name") or ""), str(d.get("description") or ""), _actor(request))
        return _json(store.get_graph(gid), 201)

    @guarded
    async def graph_get(request: Request) -> Response:
        return _json(await run_in_threadpool(store.snapshot, request.path_params["gid"]))

    @guarded
    async def graph_patch(request: Request) -> Response:
        d = await _body(request)
        return _json(await run_in_threadpool(store.update_graph, request.path_params["gid"], d.get("name"), d.get("description")))

    @guarded
    async def graph_delete(request: Request) -> Response:
        await run_in_threadpool(store.delete_graph, request.path_params["gid"])
        return _json({"ok": True})

    @guarded
    async def node_add(request: Request) -> Response:
        d = await _body(request)
        gid = request.path_params["gid"]
        t = str(d.get("type") or "auto")
        value = d.get("value")
        if t == "auto":
            if not isinstance(value, str):
                raise GraphError("Value must be text")
            v = value.strip()
            if re.fullmatch(r"\+\d[\d ()\-.]{6,24}", v):
                t = "phone"
            elif social.parse_profile_url(v):
                t = "profile"
            else:
                det = detect_type(v)
                t = {"coordinates": "place"}.get(det, det)
                if t not in TYPES:
                    t = "text"
        node, created = await run_in_threadpool(
            lambda: store.add_node(gid, t, value, label=str(d.get("label") or ""), x=d.get("x"), y=d.get("y"),
                                   notes=str(d.get("notes") or ""), source=f"manual:{_actor(request)}"))
        return _json({"node": node, "created": created}, 201 if created else 200)

    @guarded
    async def node_patch(request: Request) -> Response:
        d = await _body(request)
        return _json(await run_in_threadpool(lambda: store.update_node(
            request.path_params["nid"], label=d.get("label"), notes=d.get("notes"), x=d.get("x"), y=d.get("y"), value=d.get("value"))))

    @guarded
    async def node_delete(request: Request) -> Response:
        await run_in_threadpool(store.delete_node, request.path_params["nid"])
        return _json({"ok": True})

    @guarded
    async def positions(request: Request) -> Response:
        d = await _body(request)
        items = d.get("nodes")
        if not isinstance(items, list):
            raise GraphError("nodes must be a list")
        return _json({"saved": await run_in_threadpool(store.move_nodes, request.path_params["gid"], items)})

    @guarded
    async def edge_add(request: Request) -> Response:
        d = await _body(request)
        if not isinstance(d.get("src"), int) or not isinstance(d.get("dst"), int):
            raise GraphError("src and dst must be entity ids")
        edge, created = await run_in_threadpool(lambda: store.add_edge(
            request.path_params["gid"], d["src"], d["dst"], str(d.get("label") or "related_to"), source=f"manual:{_actor(request)}"))
        return _json({"edge": edge, "created": created}, 201 if created else 200)

    @guarded
    async def edge_patch(request: Request) -> Response:
        d = await _body(request)
        return _json(await run_in_threadpool(store.update_edge, request.path_params["eid"], str(d.get("label") or "")))

    @guarded
    async def edge_delete(request: Request) -> Response:
        await run_in_threadpool(store.delete_edge, request.path_params["eid"])
        return _json({"ok": True})

    @guarded
    async def transform(request: Request) -> Response:
        d = await _body(request)
        ids = d.get("node_ids")
        if not isinstance(ids, list):
            raise GraphError("node_ids must be a list")
        res = await run_in_threadpool(engine.run_on_nodes, store, ctx, request.path_params["gid"],
                                      str(d.get("transform") or ""), ids, _actor(request))
        ip = getattr(request.state, "ip", "")
        u = getattr(request.state, "user", None) or {}
        ctx.audit.append(_actor(request), "graphlab.transform", f"graph:{request.path_params['gid']}",
                         f"{res['transform']} on {len(ids)} entit(y/ies): +{len(res['added_nodes'])} nodes, "
                         f"+{len(res['added_edges'])} links", ip, u.get("id"))
        return _json(res)

    @guarded
    async def runs(request: Request) -> Response:
        store.need_graph(request.path_params["gid"])
        return _json(await run_in_threadpool(store.list_runs, request.path_params["gid"]))

    @guarded
    async def export(request: Request) -> Response:
        fmt = request.query_params.get("format", "json")
        part = request.query_params.get("part", "nodes")
        gid = request.path_params["gid"]
        body, ctype = await run_in_threadpool(store.export, gid, fmt, part)
        ext = "csv" if fmt == "csv" else fmt
        name = f"graph_{gid}" + (f"_{part}" if fmt == "csv" else "")
        return Response(body, media_type=ctype, headers={
            "Content-Disposition": f'attachment; filename="{name}.{ext}"', "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff"})

    @guarded
    async def import_(request: Request) -> Response:
        raw = (await request.body()).decode("utf-8", "replace")
        return _json(await run_in_threadpool(store.import_json, request.path_params["gid"], raw, _actor(request)))

    B = "/api/graphlab"
    return [
        Route(f"{B}/meta", meta, methods=["GET"]),
        Route(f"{B}/graphs", graphs_list, methods=["GET"]),
        Route(f"{B}/graphs", graphs_create, methods=["POST"]),
        Route(B + "/graphs/{gid:int}", graph_get, methods=["GET"]),
        Route(B + "/graphs/{gid:int}", graph_patch, methods=["PATCH"]),
        Route(B + "/graphs/{gid:int}", graph_delete, methods=["DELETE"]),
        Route(B + "/graphs/{gid:int}/nodes", node_add, methods=["POST"]),
        Route(B + "/graphs/{gid:int}/edges", edge_add, methods=["POST"]),
        Route(B + "/graphs/{gid:int}/positions", positions, methods=["POST"]),
        Route(B + "/graphs/{gid:int}/transform", transform, methods=["POST"]),
        Route(B + "/graphs/{gid:int}/runs", runs, methods=["GET"]),
        Route(B + "/graphs/{gid:int}/export", export, methods=["GET"]),
        Route(B + "/graphs/{gid:int}/import", import_, methods=["POST"]),
        Route(B + "/nodes/{nid:int}", node_patch, methods=["PATCH"]),
        Route(B + "/nodes/{nid:int}", node_delete, methods=["DELETE"]),
        Route(B + "/edges/{eid:int}", edge_patch, methods=["PATCH"]),
        Route(B + "/edges/{eid:int}", edge_delete, methods=["DELETE"]),
    ]
