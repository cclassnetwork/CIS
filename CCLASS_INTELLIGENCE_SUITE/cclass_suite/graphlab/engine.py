"""Apply transform output to a stored graph (merge, de-duplicate, place new nodes, audit the run)."""
from __future__ import annotations

import math
from typing import Any, Dict, List, Tuple

from . import transforms
from .store import GraphError, GraphStore, norm_of

MAX_SELECTION = 25


def _ring(cx: float, cy: float, i: int, n: int, base: float = 170.0) -> Tuple[float, float]:
    r = base + 18 * (n // 12)
    a = 2 * math.pi * i / max(n, 1)
    return cx + r * math.cos(a), cy + r * math.sin(a)


def run_on_nodes(store: GraphStore, ctx: Any, graph_id: int, transform_id: str, node_ids: List[int],
                 actor: str) -> Dict[str, Any]:
    """Run ``transform_id`` on each selected node. Returns the new/changed elements and per-node status."""
    store.need_graph(graph_id)
    t = transforms.TRANSFORMS.get(transform_id)
    if t is None:
        raise GraphError("Unknown transform")
    ids = list(dict.fromkeys(i for i in node_ids if isinstance(i, int)))[:MAX_SELECTION]
    if not ids:
        raise GraphError("Select at least one entity")
    new_nodes: List[Dict[str, Any]] = []
    new_edges: List[Dict[str, Any]] = []
    touched_nodes: Dict[int, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for nid in ids:
        node = store.get_node(nid)
        if not node or node["graph_id"] != graph_id:
            results.append({"node_id": nid, "status": "error", "message": "Entity not found"})
            continue
        try:
            out = transforms.run(transform_id, node, ctx)
        except GraphError as exc:
            results.append({"node_id": nid, "status": "error", "message": str(exc)})
            continue
        except Exception as exc:  # noqa: BLE001 - a transform must never take the server down
            results.append({"node_id": nid, "status": "error", "message": f"internal error: {exc.__class__.__name__}"})
            store.record_run(graph_id, nid, transform_id, actor, 0, 0, "error", exc.__class__.__name__)
            continue
        if out.error:
            store.record_run(graph_id, nid, transform_id, actor, 0, 0, "error", out.error)
            results.append({"node_id": nid, "status": "error", "message": out.error, "warnings": out.warnings})
            continue

        refs: Dict[Tuple[str, str], Dict[str, Any]] = {(node["type"], node["norm"]): node}
        added_n = added_e = 0
        total = len(out.entities)
        for i, ent in enumerate(out.entities):
            x, y = _ring(node["x"], node["y"], i, total)
            try:
                n, created = store.add_node(graph_id, ent["type"], ent["value"], label=ent.get("label") or "", x=x, y=y,
                                            attrs=ent.get("attrs"), source=t.name)
            except GraphError as exc:
                out.warnings.append(str(exc))
                continue
            refs[(n["type"], n["norm"])] = n
            if created:
                new_nodes.append(n)
                added_n += 1
        for e in out.edges:
            def find(ref):
                r = (ref[0], norm_of(ref[0], ref[1]) if ref[0] != "text" else ref[1])
                return refs.get(r) or refs.get(tuple(ref))
            a, b = find(e["src"]), find(e["dst"])
            if not a or not b or a["id"] == b["id"]:
                continue
            try:
                edge, created = store.add_edge(graph_id, a["id"], b["id"], e["label"], source=t.name, confidence=e["confidence"])
            except GraphError as exc:
                out.warnings.append(str(exc))
                continue
            if created:
                new_edges.append(edge)
                added_e += 1
        if out.summary_notes:
            note = (node.get("notes") or "").rstrip()
            lines = [f"{t.name}: {s}" for s in dict.fromkeys(out.summary_notes)]
            add = "\n".join(x for x in lines if x not in note)
            if add:
                touched_nodes[nid] = store.update_node(nid, notes=(note + "\n" + add).strip()[:5000])
        store.record_run(graph_id, nid, transform_id, actor, added_n, added_e, "ok", "; ".join(out.warnings)[:300])
        results.append({"node_id": nid, "status": "ok", "added_nodes": added_n, "added_edges": added_e,
                        "warnings": out.warnings})
    return {"transform": transform_id, "added_nodes": new_nodes, "added_edges": new_edges,
            "updated_nodes": list(touched_nodes.values()), "results": results}
