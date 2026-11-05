"""Tamper-evident, append-only audit log.

Each row stores ``hash = SHA-256(prev_hash || canonical(row fields))``. SQLite triggers
(migration 3) reject UPDATE and DELETE, and :meth:`AuditLog.verify` recomputes the chain
so any edit, deletion or reordering is detected.

Limit (stated honestly): someone with write access to the database *file* can rebuild the
entire chain. To defend against that, record :meth:`head` somewhere outside the database
(a ticket, a signed email, WORM storage) and pass it to ``verify(expected_head=...)``.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
from typing import Any, Dict, List, Optional

from .db import Database
from .models import utcnow_iso

GENESIS = "0" * 64
MAX_DETAIL = 2000


def compute_hash(prev_hash: str, row: Dict[str, Any]) -> str:
    payload = json.dumps(
        [row["ts"], row["actor"], row["actor_id"], row["action"], row["target"],
         row["detail"], row["ip"]],
        ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256((prev_hash + "|" + payload).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, db: Database):
        self.db = db

    def append(self, actor: str, action: str, target: str = "", detail: str = "",
               ip: str = "", actor_id: Optional[int] = None) -> int:
        row = {
            "ts": utcnow_iso(), "actor": (actor or "system")[:80], "actor_id": actor_id,
            "action": action[:80], "target": str(target)[:200],
            "detail": str(detail)[:MAX_DETAIL], "ip": (ip or "")[:64],
        }
        conn = sqlite3.connect(self.db.path, timeout=30, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")           # serialise writers so the chain cannot fork
            try:
                last = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
                prev = last[0] if last else GENESIS
                digest = compute_hash(prev, row)
                cur = conn.execute(
                    "INSERT INTO audit_log(ts, actor, actor_id, action, target, detail, ip, prev_hash, hash) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (row["ts"], row["actor"], row["actor_id"], row["action"], row["target"],
                     row["detail"], row["ip"], prev, digest))
                conn.execute("COMMIT")
                return int(cur.lastrowid)
            except Exception:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    # ------------------------------------------------------------ reading
    def head(self) -> Dict[str, Any]:
        with self.db.connect() as c:
            r = c.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        return {"seq": r["seq"], "hash": r["hash"]} if r else {"seq": 0, "hash": GENESIS}

    def count(self) -> int:
        with self.db.connect() as c:
            return int(c.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])

    def list(self, limit: int = 100, offset: int = 0, actor: str = "", action: str = "",
             since: str = "", until: str = "") -> List[Dict[str, Any]]:
        sql, args = "SELECT * FROM audit_log WHERE 1=1", []
        if actor:
            sql += " AND actor = ?"; args.append(actor)
        if action:
            sql += " AND action LIKE ? ESCAPE '\\'"
            args.append(action.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        if since:
            sql += " AND ts >= ?"; args.append(since)
        if until:
            sql += " AND ts <= ?"; args.append(until)
        sql += " ORDER BY seq DESC LIMIT ? OFFSET ?"
        args += [max(1, min(int(limit), 1000)), max(0, int(offset))]
        with self.db.connect() as c:
            return [dict(r) for r in c.execute(sql, args).fetchall()]

    # ------------------------------------------------------------ verification
    def verify(self, expected_head: Optional[str] = None) -> Dict[str, Any]:
        prev, n = GENESIS, 0
        last_seq = 0
        with self.db.connect() as c:
            for r in c.execute("SELECT * FROM audit_log ORDER BY seq ASC"):
                row = dict(r)
                n += 1
                if row["prev_hash"] != prev:
                    return {"ok": False, "entries": n, "first_bad_seq": row["seq"],
                            "problem": "chain link broken (row removed, inserted or reordered)"}
                if compute_hash(prev, row) != row["hash"]:
                    return {"ok": False, "entries": n, "first_bad_seq": row["seq"],
                            "problem": "row content does not match its hash (row altered)"}
                prev, last_seq = row["hash"], row["seq"]
        if expected_head and expected_head != prev:
            return {"ok": False, "entries": n, "first_bad_seq": last_seq,
                    "problem": "head hash differs from the externally recorded value (log truncated or rebuilt)"}
        return {"ok": True, "entries": n, "head": prev, "last_seq": last_seq}

    # ------------------------------------------------------------ export
    def export(self, fmt: str = "json", **filters: Any) -> str:
        rows = list(reversed(self.list(limit=1000, **filters)))
        if fmt == "csv":
            buf = io.StringIO()
            cols = ["seq", "ts", "actor", "action", "target", "detail", "ip", "prev_hash", "hash"]
            w = csv.writer(buf)
            w.writerow(cols)
            for r in rows:
                w.writerow([_csv_safe(r[c]) for c in cols])
            return buf.getvalue()
        return json.dumps({"head": self.head(), "verification": self.verify(), "entries": rows},
                          indent=2, ensure_ascii=False)


def _csv_safe(v: Any) -> Any:
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v
