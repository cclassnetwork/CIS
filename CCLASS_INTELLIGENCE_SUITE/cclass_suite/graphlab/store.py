"""Persistence and validation for Graph Lab (Maltego-style link-analysis graphs)."""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import math
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

from ..db import Database
from ..models import utcnow_iso
from ..utils import clean_text, normalise_value, valid_domain, valid_email, valid_ip, valid_username

MAX_NODES = 2000
MAX_EDGES = 6000
MAX_IMPORT_BYTES = 5 * 1024 * 1024

# type -> (label, colour). Colours are also used by the browser palette.
TYPES: Dict[str, Tuple[str, str]] = {
    "person": ("Person", "#f59e0b"),
    "organization": ("Organization", "#a78bfa"),
    "email": ("Email address", "#22d3ee"),
    "domain": ("Domain", "#3b82f6"),
    "hostname": ("Hostname", "#60a5fa"),
    "ip": ("IP address", "#10b981"),
    "network": ("Network (CIDR)", "#34d399"),
    "asn": ("AS number", "#14b8a6"),
    "url": ("URL", "#38bdf8"),
    "username": ("Username", "#f472b6"),
    "profile": ("Social profile", "#fb7185"),
    "phone": ("Phone number", "#fbbf24"),
    "place": ("Place", "#ef4444"),
    "country": ("Country", "#fb7185"),
    "cve": ("CVE", "#dc2626"),
    "hash": ("File hash", "#94a3b8"),
    "event": ("Event / news", "#f43f5e"),
    "text": ("Note / text", "#cbd5e1"),
}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$", re.I)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class GraphError(ValueError):
    """Invalid request; the message is safe to show to the user."""


def validate_value(node_type: str, value: Any) -> str:
    """Return the cleaned display value for ``node_type`` or raise GraphError."""
    if node_type not in TYPES:
        raise GraphError(f"Unknown entity type '{node_type}'")
    if not isinstance(value, str):
        raise GraphError("Value must be text")
    v = value.strip()
    if not v:
        raise GraphError("Value cannot be empty")
    if _CTRL_RE.search(v):
        raise GraphError("Value contains control characters")
    limit = 4000 if node_type == "text" else 500
    if len(v) > limit:
        raise GraphError(f"Value is too long (max {limit} characters)")
    if node_type == "email" and not valid_email(v):
        raise GraphError("Not a valid email address")
    if node_type in ("domain", "hostname") and not valid_domain(v.rstrip(".")):
        raise GraphError("Not a valid domain name")
    if node_type == "ip" and not valid_ip(v):
        raise GraphError("Not a valid IP address")
    if node_type == "network":
        try:
            v = str(ipaddress.ip_network(v, strict=False))
        except ValueError:
            raise GraphError("Not a valid network (use CIDR, e.g. 203.0.113.0/24)") from None
    if node_type == "asn" and not re.fullmatch(r"(?i)(AS)?\d{1,10}", v):
        raise GraphError("Not a valid AS number (e.g. AS64500)")
    if node_type == "phone":
        digits = re.sub(r"\D", "", v)
        if not re.fullmatch(r"\+?[0-9][0-9 ()\-.]{5,24}", v) or not 7 <= len(digits) <= 15:
            raise GraphError("Not a valid phone number (use international format, e.g. +234 803 000 0000)")
        v = ("+" if v.lstrip().startswith("+") else "") + digits
    if node_type in ("url", "profile") and not re.fullmatch(r"https?://[^\s<>\"']{3,}", v, re.I):
        raise GraphError("URL must start with http:// or https:// and contain no spaces")
    if node_type == "username" and not (valid_username(v) or re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", v)):
        raise GraphError("Not a valid username")
    if node_type == "cve":
        if not _CVE_RE.match(v):
            raise GraphError("Not a valid CVE id (e.g. CVE-2024-3400)")
        v = v.upper()
    if node_type == "hash" and not _HASH_RE.match(v):
        raise GraphError("Not a valid MD5/SHA-1/SHA-256/SHA-512 hex hash")
    return v


def norm_of(node_type: str, value: str) -> str:
    if node_type in ("url", "profile"):
        return value.strip()
    if node_type == "phone":
        return "+" + re.sub(r"\D", "", value)
    if node_type == "network":
        return value
    if node_type == "hostname":
        return normalise_value("hostname", value)
    return normalise_value(node_type, value)


def _clip(v: Any, n: int) -> str:
    return clean_text(v if isinstance(v, str) else "", n)


def _num(v: Any, default: float = 0.0) -> float:
    try:
        f = float(v)
        return f if math.isfinite(f) and abs(f) < 1e7 else default
    except (TypeError, ValueError):
        return default


class GraphStore:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------ graphs
    def create_graph(self, name: str, description: str = "", user: str = "") -> int:
        name = _clip(name, 120).strip()
        if not name:
            raise GraphError("Graph name is required")
        now = utcnow_iso()
        with self.db.connect() as c:
            return int(c.execute(
                "INSERT INTO gl_graphs(name, description, created_by, created_at, updated_at) VALUES (?,?,?,?,?)",
                (name, _clip(description, 2000), user[:80], now, now)).lastrowid)

    def list_graphs(self) -> List[Dict[str, Any]]:
        with self.db.connect() as c:
            rows = c.execute(
                "SELECT g.*, (SELECT COUNT(*) FROM gl_nodes n WHERE n.graph_id=g.id) AS node_count, "
                "(SELECT COUNT(*) FROM gl_edges e WHERE e.graph_id=g.id) AS edge_count "
                "FROM gl_graphs g ORDER BY g.updated_at DESC, g.id DESC").fetchall()
        return [dict(r) for r in rows]

    def get_graph(self, graph_id: int) -> Optional[Dict[str, Any]]:
        with self.db.connect() as c:
            r = c.execute("SELECT * FROM gl_graphs WHERE id=?", (graph_id,)).fetchone()
        return dict(r) if r else None

    def need_graph(self, graph_id: int) -> Dict[str, Any]:
        g = self.get_graph(graph_id)
        if not g:
            raise GraphError("Graph not found")
        return g

    def update_graph(self, graph_id: int, name: Optional[str] = None, description: Optional[str] = None) -> Dict[str, Any]:
        g = self.need_graph(graph_id)
        name = _clip(name, 120).strip() if name is not None else g["name"]
        if not name:
            raise GraphError("Graph name is required")
        desc = _clip(description, 2000) if description is not None else g["description"]
        with self.db.connect() as c:
            c.execute("UPDATE gl_graphs SET name=?, description=?, updated_at=? WHERE id=?",
                      (name, desc, utcnow_iso(), graph_id))
        return self.need_graph(graph_id)

    def delete_graph(self, graph_id: int) -> None:
        self.need_graph(graph_id)
        with self.db.connect() as c:
            c.execute("DELETE FROM gl_graphs WHERE id=?", (graph_id,))

    def _touch(self, c, graph_id: int) -> None:
        c.execute("UPDATE gl_graphs SET updated_at=? WHERE id=?", (utcnow_iso(), graph_id))

    # ------------------------------------------------------------ snapshot
    @staticmethod
    def _node(r) -> Dict[str, Any]:
        d = dict(r)
        try:
            d["attrs"] = json.loads(d.get("attrs") or "{}")
        except ValueError:
            d["attrs"] = {}
        return d

    def snapshot(self, graph_id: int) -> Dict[str, Any]:
        g = self.need_graph(graph_id)
        with self.db.connect() as c:
            nodes = [self._node(r) for r in c.execute("SELECT * FROM gl_nodes WHERE graph_id=? ORDER BY id", (graph_id,))]
            edges = [dict(r) for r in c.execute("SELECT * FROM gl_edges WHERE graph_id=? ORDER BY id", (graph_id,))]
        return {"graph": g, "nodes": nodes, "edges": edges}

    def get_node(self, node_id: int) -> Optional[Dict[str, Any]]:
        with self.db.connect() as c:
            r = c.execute("SELECT * FROM gl_nodes WHERE id=?", (node_id,)).fetchone()
        return self._node(r) if r else None

    # ------------------------------------------------------------ nodes
    def add_node(self, graph_id: int, node_type: str, value: str, *, label: str = "", x: Any = None, y: Any = None,
                 notes: str = "", attrs: Optional[Dict[str, Any]] = None, source: str = "manual"
                 ) -> Tuple[Dict[str, Any], bool]:
        """Insert a node, or return the existing one (merge) when the same entity is already in the graph."""
        self.need_graph(graph_id)
        value = validate_value(node_type, value)
        norm = norm_of(node_type, value)
        with self.db.connect() as c:
            row = c.execute("SELECT * FROM gl_nodes WHERE graph_id=? AND type=? AND norm=?",
                            (graph_id, node_type, norm)).fetchone()
            if row:
                return self._node(row), False
            if c.execute("SELECT COUNT(*) FROM gl_nodes WHERE graph_id=?", (graph_id,)).fetchone()[0] >= MAX_NODES:
                raise GraphError(f"This graph already has the maximum of {MAX_NODES} entities")
            clean_attrs = {str(k)[:60]: (v if isinstance(v, (int, float, bool)) else _clip(str(v), 500))
                           for k, v in list((attrs or {}).items())[:30]}
            nid = c.execute(
                "INSERT INTO gl_nodes(graph_id, type, value, norm, label, x, y, notes, attrs, source, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (graph_id, node_type, value, norm, _clip(label, 200), _num(x), _num(y), _clip(notes, 5000),
                 json.dumps(clean_attrs), source[:80], utcnow_iso())).lastrowid
            self._touch(c, graph_id)
            row = c.execute("SELECT * FROM gl_nodes WHERE id=?", (nid,)).fetchone()
        return self._node(row), True

    def update_node(self, node_id: int, **changes: Any) -> Dict[str, Any]:
        node = self.get_node(node_id)
        if not node:
            raise GraphError("Entity not found")
        fields: Dict[str, Any] = {}
        if "label" in changes and changes["label"] is not None:
            fields["label"] = _clip(changes["label"], 200)
        if "notes" in changes and changes["notes"] is not None:
            fields["notes"] = _clip(changes["notes"], 5000)
        if "x" in changes and changes["x"] is not None:
            fields["x"] = _num(changes["x"])
        if "y" in changes and changes["y"] is not None:
            fields["y"] = _num(changes["y"])
        if changes.get("value") is not None and changes["value"] != node["value"]:
            value = validate_value(node["type"], changes["value"])
            norm = norm_of(node["type"], value)
            with self.db.connect() as c:
                if c.execute("SELECT 1 FROM gl_nodes WHERE graph_id=? AND type=? AND norm=? AND id<>?",
                             (node["graph_id"], node["type"], norm, node_id)).fetchone():
                    raise GraphError("Another entity with that value already exists in this graph")
            fields["value"], fields["norm"] = value, norm
        if fields:
            sets = ", ".join(f"{k}=?" for k in fields)
            with self.db.connect() as c:
                c.execute(f"UPDATE gl_nodes SET {sets} WHERE id=?", (*fields.values(), node_id))
                self._touch(c, node["graph_id"])
        return self.get_node(node_id)  # type: ignore[return-value]

    def delete_node(self, node_id: int) -> int:
        node = self.get_node(node_id)
        if not node:
            raise GraphError("Entity not found")
        with self.db.connect() as c:
            c.execute("DELETE FROM gl_nodes WHERE id=?", (node_id,))
            self._touch(c, node["graph_id"])
        return int(node["graph_id"])

    def move_nodes(self, graph_id: int, positions: Iterable[Dict[str, Any]]) -> int:
        self.need_graph(graph_id)
        rows = []
        for p in list(positions)[:MAX_NODES]:
            if isinstance(p, dict) and isinstance(p.get("id"), int):
                rows.append((_num(p.get("x")), _num(p.get("y")), p["id"], graph_id))
        with self.db.connect() as c:
            c.executemany("UPDATE gl_nodes SET x=?, y=? WHERE id=? AND graph_id=?", rows)
        return len(rows)

    # ------------------------------------------------------------ edges
    def add_edge(self, graph_id: int, src: int, dst: int, label: str = "related_to", *, source: str = "manual",
                 confidence: float = 1.0) -> Tuple[Dict[str, Any], bool]:
        self.need_graph(graph_id)
        if src == dst:
            raise GraphError("An entity cannot be linked to itself")
        label = _clip(label, 80).strip() or "related_to"
        with self.db.connect() as c:
            ok = c.execute("SELECT COUNT(*) FROM gl_nodes WHERE graph_id=? AND id IN (?,?)", (graph_id, src, dst)).fetchone()[0]
            if ok != 2:
                raise GraphError("Both entities must belong to this graph")
            row = c.execute("SELECT * FROM gl_edges WHERE graph_id=? AND src=? AND dst=? AND label=?",
                            (graph_id, src, dst, label)).fetchone()
            if row:
                return dict(row), False
            if c.execute("SELECT COUNT(*) FROM gl_edges WHERE graph_id=?", (graph_id,)).fetchone()[0] >= MAX_EDGES:
                raise GraphError(f"This graph already has the maximum of {MAX_EDGES} links")
            eid = c.execute(
                "INSERT INTO gl_edges(graph_id, src, dst, label, source, confidence, created_at) VALUES (?,?,?,?,?,?,?)",
                (graph_id, src, dst, label, source[:80], max(0.0, min(1.0, _num(confidence, 1.0))), utcnow_iso())).lastrowid
            self._touch(c, graph_id)
            row = c.execute("SELECT * FROM gl_edges WHERE id=?", (eid,)).fetchone()
        return dict(row), True

    def update_edge(self, edge_id: int, label: str) -> Dict[str, Any]:
        label = _clip(label, 80).strip()
        if not label:
            raise GraphError("Link label cannot be empty")
        with self.db.connect() as c:
            r = c.execute("SELECT * FROM gl_edges WHERE id=?", (edge_id,)).fetchone()
            if not r:
                raise GraphError("Link not found")
            if c.execute("SELECT 1 FROM gl_edges WHERE graph_id=? AND src=? AND dst=? AND label=? AND id<>?",
                         (r["graph_id"], r["src"], r["dst"], label, edge_id)).fetchone():
                raise GraphError("That link already exists")
            c.execute("UPDATE gl_edges SET label=? WHERE id=?", (label, edge_id))
            r = c.execute("SELECT * FROM gl_edges WHERE id=?", (edge_id,)).fetchone()
        return dict(r)

    def delete_edge(self, edge_id: int) -> None:
        with self.db.connect() as c:
            r = c.execute("SELECT graph_id FROM gl_edges WHERE id=?", (edge_id,)).fetchone()
            if not r:
                raise GraphError("Link not found")
            c.execute("DELETE FROM gl_edges WHERE id=?", (edge_id,))
            self._touch(c, r["graph_id"])

    # ------------------------------------------------------------ runs
    def record_run(self, graph_id: int, node_id: Optional[int], transform: str, actor: str, added_nodes: int,
                   added_edges: int, status: str, message: str = "") -> None:
        with self.db.connect() as c:
            c.execute("INSERT INTO gl_runs(graph_id, node_id, transform, actor, added_nodes, added_edges, status, "
                      "message, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                      (graph_id, node_id, transform, actor[:80], added_nodes, added_edges, status[:20],
                       _clip(message, 500), utcnow_iso()))

    def list_runs(self, graph_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        with self.db.connect() as c:
            return [dict(r) for r in c.execute(
                "SELECT r.*, n.type AS node_type, n.value AS node_value FROM gl_runs r "
                "LEFT JOIN gl_nodes n ON n.id = r.node_id WHERE r.graph_id=? ORDER BY r.id DESC LIMIT ?",
                (graph_id, max(1, min(limit, 500))))]

    # ------------------------------------------------------------ import / export
    def export(self, graph_id: int, fmt: str, part: str = "nodes") -> Tuple[str, str]:
        """Return (body, content_type)."""
        snap = self.snapshot(graph_id)
        nodes, edges = snap["nodes"], snap["edges"]
        if fmt == "json":
            data = {"format": "cclass-graphlab", "version": 1, "graph": {k: snap["graph"][k] for k in ("name", "description")},
                    "nodes": [{"id": n["id"], "type": n["type"], "value": n["value"], "label": n["label"], "x": n["x"],
                               "y": n["y"], "notes": n["notes"], "attrs": n["attrs"], "source": n["source"]} for n in nodes],
                    "edges": [{"src": e["src"], "dst": e["dst"], "label": e["label"], "source": e["source"],
                               "confidence": e["confidence"]} for e in edges]}
            return json.dumps(data, indent=2, ensure_ascii=False), "application/json"
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            if part == "edges":
                by_id = {n["id"]: n for n in nodes}
                w.writerow(["source_type", "source_value", "label", "target_type", "target_value", "origin", "confidence"])
                for e in edges:
                    s, d = by_id.get(e["src"]), by_id.get(e["dst"])
                    if s and d:
                        w.writerow([s["type"], _csv_safe(s["value"]), _csv_safe(e["label"]), d["type"],
                                    _csv_safe(d["value"]), e["source"], e["confidence"]])
            else:
                w.writerow(["id", "type", "value", "label", "notes", "origin"])
                for n in nodes:
                    w.writerow([n["id"], n["type"], _csv_safe(n["value"]), _csv_safe(n["label"]), _csv_safe(n["notes"]), n["source"]])
            return buf.getvalue(), "text/csv"
        if fmt == "graphml":
            out = ['<?xml version="1.0" encoding="UTF-8"?>',
                   '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
                   '<key id="type" for="node" attr.name="type" attr.type="string"/>',
                   '<key id="value" for="node" attr.name="value" attr.type="string"/>',
                   '<key id="label" for="edge" attr.name="label" attr.type="string"/>',
                   '<graph id="G" edgedefault="directed">']
            for n in nodes:
                out.append(f'<node id="n{n["id"]}"><data key="type">{xml_escape(n["type"])}</data>'
                           f'<data key="value">{xml_escape(_xml_clean(n["value"]))}</data></node>')
            for e in edges:
                out.append(f'<edge id="e{e["id"]}" source="n{e["src"]}" target="n{e["dst"]}">'
                           f'<data key="label">{xml_escape(_xml_clean(e["label"]))}</data></edge>')
            out.append("</graph></graphml>")
            return "\n".join(out), "application/xml"
        raise GraphError("Unknown export format")

    def import_json(self, graph_id: int, raw: str, user: str = "") -> Dict[str, int]:
        if len(raw.encode("utf-8", "ignore")) > MAX_IMPORT_BYTES:
            raise GraphError("Import file is too large")
        try:
            data = json.loads(raw)
        except ValueError:
            raise GraphError("Not valid JSON") from None
        if not isinstance(data, dict) or data.get("format") != "cclass-graphlab":
            raise GraphError("Not a CCLASS Graph Lab export")
        nodes, edges = data.get("nodes"), data.get("edges")
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise GraphError("Malformed export")
        idmap: Dict[Any, int] = {}
        added_n = added_e = skipped = 0
        for n in nodes[:MAX_NODES]:
            if not isinstance(n, dict):
                skipped += 1
                continue
            try:
                node, created = self.add_node(graph_id, str(n.get("type")), n.get("value"), label=n.get("label") or "",
                                              x=n.get("x"), y=n.get("y"), notes=n.get("notes") or "",
                                              attrs=n.get("attrs") if isinstance(n.get("attrs"), dict) else None,
                                              source="import")
            except GraphError:
                skipped += 1
                continue
            idmap[n.get("id")] = node["id"]
            added_n += int(created)
        for e in edges[:MAX_EDGES]:
            if not isinstance(e, dict) or e.get("src") not in idmap or e.get("dst") not in idmap:
                skipped += 1
                continue
            try:
                _, created = self.add_edge(graph_id, idmap[e["src"]], idmap[e["dst"]], str(e.get("label") or "related_to"),
                                           source="import", confidence=e.get("confidence", 1.0))
                added_e += int(created)
            except GraphError:
                skipped += 1
        return {"nodes": added_n, "edges": added_e, "skipped": skipped}


def _csv_safe(v: Any) -> Any:
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _xml_clean(s: str) -> str:
    return _CTRL_RE.sub("", s)
