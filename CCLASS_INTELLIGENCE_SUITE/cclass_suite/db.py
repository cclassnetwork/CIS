"""SQLite storage layer with versioned migrations.

All SQL is parameterised.  Every connection enables foreign keys; schema
changes are applied transactionally through the ``MIGRATIONS`` list.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .models import SEVERITIES, TLP_LEVELS, normalise_tags, utcnow_iso, validate_due_date
from .utils import normalise_value, sha256_text

MIGRATIONS: List[Tuple[int, str, str]] = [
    (
        1,
        "core schema",
        """
        CREATE TABLE investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','archived')),
            priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high','critical')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX idx_investigations_status ON investigations(status);

        CREATE TABLE sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL DEFAULT 'public',
            url TEXT,
            reliability TEXT NOT NULL DEFAULT 'C' CHECK (reliability IN ('A','B','C','D','E','F')),
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            value_norm TEXT NOT NULL,
            label TEXT,
            attributes TEXT NOT NULL DEFAULT '{}',
            lat REAL,
            lon REAL,
            confidence REAL NOT NULL DEFAULT 0.5,
            sightings INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE (investigation_id, type, value_norm)
        );
        CREATE INDEX idx_entities_lookup ON entities(type, value_norm);
        CREATE INDEX idx_entities_inv ON entities(investigation_id);

        CREATE TABLE relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            src_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            dst_entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0.6,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            UNIQUE (investigation_id, src_entity_id, dst_entity_id, kind)
        );
        CREATE INDEX idx_rel_src ON relationships(src_entity_id);
        CREATE INDEX idx_rel_dst ON relationships(dst_entity_id);

        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            entity_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            module TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','low','medium','high','critical')),
            confidence REAL NOT NULL DEFAULT 0.5,
            data TEXT NOT NULL DEFAULT '{}',
            lat REAL,
            lon REAL,
            observed_at TEXT,
            created_at TEXT NOT NULL,
            seen_count INTEGER NOT NULL DEFAULT 1,
            fingerprint TEXT NOT NULL,
            UNIQUE (investigation_id, fingerprint)
        );
        CREATE INDEX idx_findings_inv_time ON findings(investigation_id, created_at);
        CREATE INDEX idx_findings_severity ON findings(severity);
        CREATE INDEX idx_findings_entity ON findings(entity_id);

        CREATE TABLE evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
            filename TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            mime_type TEXT,
            notes TEXT NOT NULL DEFAULT '',
            collected_by TEXT NOT NULL DEFAULT 'analyst',
            collected_at TEXT NOT NULL,
            UNIQUE (investigation_id, sha256)
        );
        CREATE INDEX idx_evidence_inv ON evidence(investigation_id);

        CREATE TABLE threat_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,
            feed TEXT NOT NULL,
            external_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('info','low','medium','high','critical')),
            cve_id TEXT,
            vendor TEXT,
            product TEXT,
            published_at TEXT,
            url TEXT,
            data TEXT NOT NULL DEFAULT '{}',
            matched_watchlists TEXT NOT NULL DEFAULT '[]',
            acknowledged INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            UNIQUE (feed, external_id)
        );
        CREATE INDEX idx_alerts_published ON threat_alerts(published_at);
        CREATE INDEX idx_alerts_severity ON threat_alerts(severity);
        CREATE INDEX idx_alerts_cve ON threat_alerts(cve_id);

        CREATE TABLE watchlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL CHECK (kind IN ('keyword','product','vendor','cve','domain','ip','email','username')),
            value TEXT NOT NULL,
            notes TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            UNIQUE (kind, value)
        );

        CREATE TABLE activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER REFERENCES investigations(id) ON DELETE CASCADE,
            actor TEXT NOT NULL DEFAULT 'system',
            action TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_activity_time ON activity_logs(created_at);
        CREATE INDEX idx_activity_inv ON activity_logs(investigation_id);

        CREATE TABLE scheduled_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            task_type TEXT NOT NULL CHECK (task_type IN ('feed_refresh','watchlist_scan')),
            params TEXT NOT NULL DEFAULT '{}',
            interval_minutes INTEGER NOT NULL CHECK (interval_minutes >= 1),
            enabled INTEGER NOT NULL DEFAULT 1,
            last_run TEXT,
            next_run TEXT NOT NULL,
            last_status TEXT,
            last_message TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_tasks_next ON scheduled_tasks(enabled, next_run);
        """,
    ),
    (
        2,
        "reports table and extra indexes",
        """
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            format TEXT NOT NULL,
            path TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_reports_inv ON reports(investigation_id);
        CREATE INDEX idx_findings_module ON findings(module);
        CREATE INDEX idx_alerts_ack ON threat_alerts(acknowledged);
        """,
    ),
    (
        3,
        "accounts, sessions, tamper-evident audit log, case management",
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')),
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            totp_last_step INTEGER NOT NULL DEFAULT 0,
            failed_logins INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            disabled INTEGER NOT NULL DEFAULT 0,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login TEXT
        );

        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX idx_sessions_user ON sessions(user_id);

        CREATE TABLE audit_log (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            actor_id INTEGER,
            action TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL
        );
        CREATE INDEX idx_audit_action ON audit_log(action);
        CREATE INDEX idx_audit_actor ON audit_log(actor);

        CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only');
        END;

        CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'audit_log is append-only');
        END;

        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            user_id INTEGER,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_comments_inv ON comments(investigation_id);

        ALTER TABLE investigations ADD COLUMN assignee_id INTEGER;
        ALTER TABLE investigations ADD COLUMN tlp TEXT NOT NULL DEFAULT 'AMBER';
        ALTER TABLE investigations ADD COLUMN due_date TEXT;
        ALTER TABLE investigations ADD COLUMN tags TEXT NOT NULL DEFAULT '';

        CREATE TABLE scheduled_tasks_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            task_type TEXT NOT NULL CHECK (task_type IN ('feed_refresh','watchlist_scan','backup','retention')),
            params TEXT NOT NULL DEFAULT '{}',
            interval_minutes INTEGER NOT NULL CHECK (interval_minutes >= 1),
            enabled INTEGER NOT NULL DEFAULT 1,
            last_run TEXT,
            next_run TEXT NOT NULL,
            last_status TEXT,
            last_message TEXT,
            created_at TEXT NOT NULL
        );
        INSERT INTO scheduled_tasks_new(id, name, task_type, params, interval_minutes, enabled, last_run,
                                        next_run, last_status, last_message, created_at)
            SELECT id, name, task_type, params, interval_minutes, enabled, last_run,
                   next_run, last_status, last_message, created_at FROM scheduled_tasks;
        DROP TABLE scheduled_tasks;
        ALTER TABLE scheduled_tasks_new RENAME TO scheduled_tasks;
        CREATE INDEX idx_tasks_next ON scheduled_tasks(enabled, next_run);
        """,
    ),
    (
        4,
        "graph lab: link-analysis graphs, nodes, edges and transform runs",
        """
        CREATE TABLE gl_graphs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE gl_nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            graph_id INTEGER NOT NULL REFERENCES gl_graphs(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            norm TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            x REAL NOT NULL DEFAULT 0,
            y REAL NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT '',
            attrs TEXT NOT NULL DEFAULT '{}',
            source TEXT NOT NULL DEFAULT 'manual',
            created_at TEXT NOT NULL,
            UNIQUE (graph_id, type, norm)
        );
        CREATE INDEX idx_gl_nodes_graph ON gl_nodes(graph_id);

        CREATE TABLE gl_edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            graph_id INTEGER NOT NULL REFERENCES gl_graphs(id) ON DELETE CASCADE,
            src INTEGER NOT NULL REFERENCES gl_nodes(id) ON DELETE CASCADE,
            dst INTEGER NOT NULL REFERENCES gl_nodes(id) ON DELETE CASCADE,
            label TEXT NOT NULL DEFAULT 'related_to',
            source TEXT NOT NULL DEFAULT 'manual',
            confidence REAL NOT NULL DEFAULT 1.0,
            created_at TEXT NOT NULL,
            UNIQUE (graph_id, src, dst, label)
        );
        CREATE INDEX idx_gl_edges_graph ON gl_edges(graph_id);

        CREATE TABLE gl_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            graph_id INTEGER NOT NULL REFERENCES gl_graphs(id) ON DELETE CASCADE,
            node_id INTEGER,
            transform TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT '',
            added_nodes INTEGER NOT NULL DEFAULT 0,
            added_edges INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'ok',
            message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_gl_runs_graph ON gl_runs(graph_id);
        """,
    ),
]

_JSON_FIELDS = ("attributes", "data", "params", "matched_watchlists")


def _like(term: str) -> str:
    esc = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{esc}%"


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    # ------------------------------------------------------------------
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _row(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
        if row is None:
            return None
        d = dict(row)
        for key in _JSON_FIELDS:
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except ValueError:
                    d[key] = {} if key != "matched_watchlists" else []
        return d

    def _rows(self, rows: List[sqlite3.Row]) -> List[Dict[str, Any]]:
        return [self._row(r) for r in rows]  # type: ignore[misc]

    # ------------------------------------------------------------------ migrations
    def schema_version(self) -> int:
        with self.connect() as c:
            try:
                row = c.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
                return int(row["v"] or 0)
            except sqlite3.OperationalError:
                return 0

    def migrate(self) -> List[int]:
        applied: List[int] = []
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
            done = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
            for version, name, script in MIGRATIONS:
                if version in done:
                    continue
                conn.execute("BEGIN")
                try:
                    buf = ""
                    for line in script.splitlines():
                        buf += line + "\n"
                        if sqlite3.complete_statement(buf):
                            conn.execute(buf)
                            buf = ""
                    conn.execute(
                        "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?,?,?)",
                        (version, name, utcnow_iso()),
                    )
                    conn.execute("COMMIT")
                    applied.append(version)
                except Exception:
                    conn.execute("ROLLBACK")
                    raise
        finally:
            conn.close()
        return applied

    # ------------------------------------------------------------------ investigations
    def create_investigation(self, name: str, description: str = "", priority: str = "medium",
                             tlp: str = "AMBER", tags: Any = "", due_date: Optional[str] = None,
                             assignee_id: Optional[int] = None) -> int:
        if tlp not in TLP_LEVELS:
            raise ValueError(f"tlp must be one of {', '.join(TLP_LEVELS)}")
        tags, due_date = normalise_tags(tags), validate_due_date(due_date)
        now = utcnow_iso()
        with self.connect() as c:
            if assignee_id is not None and not c.execute(
                    "SELECT 1 FROM users WHERE id=? AND disabled=0", (assignee_id,)).fetchone():
                raise ValueError("assignee must be an active user")
            cur = c.execute(
                "INSERT INTO investigations(name, description, priority, tlp, tags, due_date, assignee_id, "
                "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (name.strip()[:200], description.strip()[:5000], priority, tlp, tags, due_date, assignee_id, now, now),
            )
            inv_id = int(cur.lastrowid)
        self.log("investigation_created", name, inv_id)
        return inv_id

    def get_investigation(self, inv_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            row = c.execute(
                """SELECT i.*,
                    (SELECT COUNT(*) FROM entities e WHERE e.investigation_id=i.id) AS entity_count,
                    (SELECT COUNT(*) FROM findings f WHERE f.investigation_id=i.id) AS finding_count,
                    (SELECT COUNT(*) FROM evidence v WHERE v.investigation_id=i.id) AS evidence_count,
                    (SELECT COUNT(*) FROM comments m WHERE m.investigation_id=i.id) AS comment_count,
                    (SELECT username FROM users u WHERE u.id=i.assignee_id) AS assignee
                   FROM investigations i WHERE i.id=?""",
                (inv_id,),
            ).fetchone()
        return self._row(row)

    def list_investigations(self, status: Optional[str] = None, assignee_id: Optional[int] = None,
                            tag: Optional[str] = None, tlp: Optional[str] = None,
                            overdue: bool = False) -> List[Dict[str, Any]]:
        sql = """SELECT i.*,
                    (SELECT COUNT(*) FROM entities e WHERE e.investigation_id=i.id) AS entity_count,
                    (SELECT COUNT(*) FROM findings f WHERE f.investigation_id=i.id) AS finding_count,
                    (SELECT COUNT(*) FROM evidence v WHERE v.investigation_id=i.id) AS evidence_count,
                    (SELECT COUNT(*) FROM comments m WHERE m.investigation_id=i.id) AS comment_count,
                    (SELECT username FROM users u WHERE u.id=i.assignee_id) AS assignee
                 FROM investigations i WHERE 1=1"""
        params: list = []
        if status:
            sql += " AND i.status=?"
            params.append(status)
        if assignee_id is not None:
            sql += " AND i.assignee_id=?"
            params.append(assignee_id)
        if tag:
            sql += " AND (',' || i.tags || ',') LIKE ? ESCAPE '\\'"
            params.append(f"%,{_like(tag.strip().lower())[1:-1]},%")
        if tlp:
            sql += " AND i.tlp=?"
            params.append(tlp)
        if overdue:
            sql += " AND i.status='open' AND i.due_date IS NOT NULL AND i.due_date < ?"
            params.append(datetime.now(timezone.utc).date().isoformat())
        sql += " ORDER BY i.updated_at DESC, i.id DESC"
        with self.connect() as c:
            return self._rows(c.execute(sql, params).fetchall())

    _CLEARABLE = ("assignee_id", "due_date")

    def update_investigation(self, inv_id: int, **fields: Any) -> bool:
        """Update whitelisted columns. ``assignee_id`` and ``due_date`` may be set to None to clear them."""
        allowed = {"name", "description", "status", "priority", "tlp", "due_date", "tags", "assignee_id"}
        sets = {k: v for k, v in fields.items() if k in allowed and (v is not None or k in self._CLEARABLE)}
        if "tlp" in sets and sets["tlp"] not in TLP_LEVELS:
            raise ValueError(f"tlp must be one of {', '.join(TLP_LEVELS)}")
        if "tags" in sets:
            sets["tags"] = normalise_tags(sets["tags"])
        if "due_date" in sets:
            sets["due_date"] = validate_due_date(sets["due_date"])
        if "assignee_id" in sets and sets["assignee_id"] is not None:
            with self.connect() as c:
                if not c.execute("SELECT 1 FROM users WHERE id=? AND disabled=0", (sets["assignee_id"],)).fetchone():
                    raise ValueError("assignee must be an active user")
        if not sets:
            return False
        cols = ", ".join(f"{k}=?" for k in sets)
        with self.connect() as c:
            cur = c.execute(
                f"UPDATE investigations SET {cols}, updated_at=? WHERE id=?",  # noqa: S608 (whitelisted)
                (*sets.values(), utcnow_iso(), inv_id),
            )
            changed = cur.rowcount > 0
        if changed:
            self.log("investigation_updated", ", ".join(f"{k}={v}" for k, v in sets.items())[:300], inv_id)
        return changed

    # ------------------------------------------------------------------ case comments
    def add_comment(self, inv_id: int, user_id: Optional[int], author: str, body: str) -> int:
        body = "".join(ch for ch in (body or "") if ch.isprintable() or ch in "\n\t").strip()
        if not body:
            raise ValueError("comment is empty")
        if len(body) > 5000:
            raise ValueError("comment is longer than 5000 characters")
        with self.connect() as c:
            cur = c.execute(
                "INSERT INTO comments(investigation_id, user_id, author, body, created_at) VALUES (?,?,?,?,?)",
                (inv_id, user_id or None, author[:80], body, utcnow_iso()))
            c.execute("UPDATE investigations SET updated_at=? WHERE id=?", (utcnow_iso(), inv_id))
            return int(cur.lastrowid)

    def list_comments(self, inv_id: int) -> List[Dict[str, Any]]:
        with self.connect() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM comments WHERE investigation_id=? ORDER BY id", (inv_id,))]

    def get_comment(self, comment_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            row = c.execute("SELECT * FROM comments WHERE id=?", (comment_id,)).fetchone()
        return dict(row) if row else None

    def delete_comment(self, comment_id: int) -> bool:
        with self.connect() as c:
            return c.execute("DELETE FROM comments WHERE id=?", (comment_id,)).rowcount > 0

    def delete_investigation(self, inv_id: int) -> List[str]:
        """Delete an investigation; returns evidence/report file paths to remove from disk."""
        with self.connect() as c:
            paths = [r["stored_path"] for r in c.execute(
                "SELECT stored_path FROM evidence WHERE investigation_id=?", (inv_id,))]
            paths += [r["path"] for r in c.execute(
                "SELECT path FROM reports WHERE investigation_id=?", (inv_id,))]
            c.execute("DELETE FROM investigations WHERE id=?", (inv_id,))
        self.log("investigation_deleted", f"id={inv_id}")
        return paths

    def touch(self, inv_id: int) -> None:
        with self.connect() as c:
            c.execute("UPDATE investigations SET updated_at=? WHERE id=?", (utcnow_iso(), inv_id))

    # ------------------------------------------------------------------ sources
    def ensure_source(self, name: str, kind: str = "public", url: Optional[str] = None,
                      reliability: str = "C") -> int:
        with self.connect() as c:
            row = c.execute("SELECT id FROM sources WHERE name=?", (name,)).fetchone()
            if row:
                return int(row["id"])
            cur = c.execute(
                "INSERT INTO sources(name, kind, url, reliability, created_at) VALUES (?,?,?,?,?)",
                (name, kind, url, reliability, utcnow_iso()),
            )
            return int(cur.lastrowid)

    def list_sources(self) -> List[Dict[str, Any]]:
        with self.connect() as c:
            return self._rows(c.execute("SELECT * FROM sources ORDER BY name").fetchall())

    def get_source(self, source_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            return self._row(c.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone())

    def set_source_reliability(self, source_id: int, reliability: str) -> bool:
        with self.connect() as c:
            cur = c.execute("UPDATE sources SET reliability=? WHERE id=?", (reliability, source_id))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ entities
    def upsert_entity(self, investigation_id: int, type: str, value: str, label: Optional[str] = None,
                      attributes: Optional[Dict[str, Any]] = None, lat: Optional[float] = None,
                      lon: Optional[float] = None, confidence: float = 0.5) -> Tuple[int, bool]:
        norm = normalise_value(type, value)
        now = utcnow_iso()
        with self.connect() as c:
            row = c.execute(
                "SELECT * FROM entities WHERE investigation_id=? AND type=? AND value_norm=?",
                (investigation_id, type, norm),
            ).fetchone()
            if row is None:
                cur = c.execute(
                    """INSERT INTO entities(investigation_id, type, value, value_norm, label, attributes,
                       lat, lon, confidence, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (investigation_id, type, value.strip(), norm, label, json.dumps(attributes or {}),
                     lat, lon, confidence, now, now),
                )
                return int(cur.lastrowid), True
            merged = json.loads(row["attributes"] or "{}")
            merged.update(attributes or {})
            c.execute(
                """UPDATE entities SET attributes=?, label=COALESCE(?, label), lat=COALESCE(?, lat),
                   lon=COALESCE(?, lon), confidence=MAX(confidence, ?), sightings=sightings+1, last_seen=?
                   WHERE id=?""",
                (json.dumps(merged), label, lat, lon, confidence, now, row["id"]),
            )
            return int(row["id"]), False

    def get_entity(self, entity_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            return self._row(c.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone())

    def find_entity(self, investigation_id: int, type: str, value: str) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            return self._row(c.execute(
                "SELECT * FROM entities WHERE investigation_id=? AND type=? AND value_norm=?",
                (investigation_id, type, normalise_value(type, value))).fetchone())

    def list_entities(self, investigation_id: int, type: Optional[str] = None,
                      limit: int = 1000) -> List[Dict[str, Any]]:
        sql, params = "SELECT * FROM entities WHERE investigation_id=?", [investigation_id]
        if type:
            sql += " AND type=?"
            params.append(type)
        sql += " ORDER BY confidence DESC, id LIMIT ?"
        params.append(limit)
        with self.connect() as c:
            return self._rows(c.execute(sql, params).fetchall())

    def set_entity_confidence(self, entity_id: int, confidence: float) -> None:
        with self.connect() as c:
            c.execute("UPDATE entities SET confidence=? WHERE id=?", (round(confidence, 3), entity_id))

    # ------------------------------------------------------------------ relationships
    def add_relationship(self, investigation_id: int, src_id: int, dst_id: int, kind: str,
                         confidence: float = 0.6, source_id: Optional[int] = None) -> Tuple[Optional[int], bool]:
        if src_id == dst_id:
            return None, False
        with self.connect() as c:
            row = c.execute(
                """SELECT id FROM relationships WHERE investigation_id=? AND kind=? AND
                   ((src_entity_id=? AND dst_entity_id=?) OR (src_entity_id=? AND dst_entity_id=? AND ?))""",
                (investigation_id, kind, src_id, dst_id, dst_id, src_id, 1 if kind in SYMMETRIC_KINDS else 0),
            ).fetchone()
            if row:
                return int(row["id"]), False
            cur = c.execute(
                """INSERT INTO relationships(investigation_id, src_entity_id, dst_entity_id, kind,
                   confidence, source_id, created_at) VALUES (?,?,?,?,?,?,?)""",
                (investigation_id, src_id, dst_id, kind, confidence, source_id, utcnow_iso()),
            )
            return int(cur.lastrowid), True

    def list_relationships(self, investigation_id: int) -> List[Dict[str, Any]]:
        with self.connect() as c:
            return self._rows(c.execute(
                "SELECT * FROM relationships WHERE investigation_id=? ORDER BY id", (investigation_id,)).fetchall())

    # ------------------------------------------------------------------ findings
    @staticmethod
    def fingerprint(module: str, entity_key: str, title: str, summary: str) -> str:
        return sha256_text("|".join([module, entity_key, title.strip().lower(), summary.strip().lower()]))[:40]

    def add_finding(self, investigation_id: int, module: str, title: str, summary: str = "",
                    severity: str = "info", confidence: float = 0.5, entity_id: Optional[int] = None,
                    source_id: Optional[int] = None, data: Optional[Dict[str, Any]] = None,
                    lat: Optional[float] = None, lon: Optional[float] = None,
                    observed_at: Optional[str] = None, entity_key: str = "") -> Tuple[int, bool]:
        if severity not in SEVERITIES:
            severity = "info"
        fp = self.fingerprint(module, entity_key, title, summary)
        with self.connect() as c:
            row = c.execute(
                "SELECT id FROM findings WHERE investigation_id=? AND fingerprint=?", (investigation_id, fp)
            ).fetchone()
            if row:
                c.execute("UPDATE findings SET seen_count=seen_count+1 WHERE id=?", (row["id"],))
                return int(row["id"]), False
            cur = c.execute(
                """INSERT INTO findings(investigation_id, entity_id, source_id, module, title, summary, severity,
                   confidence, data, lat, lon, observed_at, created_at, fingerprint)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (investigation_id, entity_id, source_id, module, title[:300], summary[:5000], severity,
                 round(confidence, 3), json.dumps(data or {}, default=str), lat, lon, observed_at,
                 utcnow_iso(), fp),
            )
            return int(cur.lastrowid), True

    def list_findings(self, investigation_id: int, severity: Optional[str] = None, module: Optional[str] = None,
                      limit: int = 500, offset: int = 0) -> List[Dict[str, Any]]:
        sql = """SELECT f.*, e.type AS entity_type, e.value AS entity_value, s.name AS source_name,
                        s.reliability AS source_reliability
                 FROM findings f LEFT JOIN entities e ON e.id=f.entity_id
                 LEFT JOIN sources s ON s.id=f.source_id WHERE f.investigation_id=?"""
        params: List[Any] = [investigation_id]
        if severity:
            sql += " AND f.severity=?"
            params.append(severity)
        if module:
            sql += " AND f.module=?"
            params.append(module)
        sql += """ ORDER BY CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                   WHEN 'low' THEN 1 ELSE 0 END DESC, f.id DESC LIMIT ? OFFSET ?"""
        params += [limit, offset]
        with self.connect() as c:
            return self._rows(c.execute(sql, params).fetchall())

    # ------------------------------------------------------------------ evidence
    def add_evidence(self, investigation_id: int, filename: str, stored_path: str, sha256: str,
                     size_bytes: int, mime_type: Optional[str] = None, notes: str = "",
                     finding_id: Optional[int] = None, collected_by: str = "analyst") -> Tuple[int, bool]:
        with self.connect() as c:
            row = c.execute(
                "SELECT id FROM evidence WHERE investigation_id=? AND sha256=?", (investigation_id, sha256)
            ).fetchone()
            if row:
                return int(row["id"]), False
            cur = c.execute(
                """INSERT INTO evidence(investigation_id, finding_id, filename, stored_path, sha256, size_bytes,
                   mime_type, notes, collected_by, collected_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (investigation_id, finding_id, filename[:255], stored_path, sha256, size_bytes, mime_type,
                 notes[:2000], collected_by, utcnow_iso()),
            )
        self.log("evidence_added", f"{filename} sha256={sha256[:16]}", investigation_id)
        return int(cur.lastrowid), True

    def list_evidence(self, investigation_id: int) -> List[Dict[str, Any]]:
        with self.connect() as c:
            return self._rows(c.execute(
                "SELECT * FROM evidence WHERE investigation_id=? ORDER BY id DESC", (investigation_id,)).fetchall())

    def get_evidence(self, evidence_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            return self._row(c.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone())

    def delete_evidence(self, evidence_id: int) -> Optional[str]:
        with self.connect() as c:
            row = c.execute("SELECT stored_path, investigation_id, filename FROM evidence WHERE id=?",
                            (evidence_id,)).fetchone()
            if not row:
                return None
            c.execute("DELETE FROM evidence WHERE id=?", (evidence_id,))
        self.log("evidence_deleted", row["filename"], row["investigation_id"])
        return row["stored_path"]

    # ------------------------------------------------------------------ threat alerts
    def upsert_alert(self, feed: str, external_id: str, title: str, description: str = "",
                     severity: str = "medium", cve_id: Optional[str] = None, vendor: Optional[str] = None,
                     product: Optional[str] = None, published_at: Optional[str] = None,
                     url: Optional[str] = None, data: Optional[Dict[str, Any]] = None,
                     source_id: Optional[int] = None) -> Tuple[int, bool]:
        if severity not in SEVERITIES:
            severity = "medium"
        with self.connect() as c:
            row = c.execute("SELECT id FROM threat_alerts WHERE feed=? AND external_id=?",
                            (feed, external_id)).fetchone()
            if row:
                return int(row["id"]), False
            cur = c.execute(
                """INSERT INTO threat_alerts(source_id, feed, external_id, title, description, severity, cve_id,
                   vendor, product, published_at, url, data, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (source_id, feed, external_id[:200], title[:300], description[:4000], severity, cve_id, vendor,
                 product, published_at, url, json.dumps(data or {}, default=str), utcnow_iso()),
            )
            return int(cur.lastrowid), True

    def list_alerts(self, severity: Optional[str] = None, matched_only: bool = False, q: Optional[str] = None,
                    include_acknowledged: bool = True, limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
        sql, params = "SELECT * FROM threat_alerts WHERE 1=1", []
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if matched_only:
            sql += " AND matched_watchlists != '[]'"
        if not include_acknowledged:
            sql += " AND acknowledged=0"
        if q:
            sql += " AND (title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR cve_id LIKE ? ESCAPE '\\'" \
                   " OR vendor LIKE ? ESCAPE '\\' OR product LIKE ? ESCAPE '\\')"
            params += [_like(q)] * 5
        sql += " ORDER BY COALESCE(published_at, created_at) DESC, id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self.connect() as c:
            return self._rows(c.execute(sql, params).fetchall())

    def get_alert_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            return self._row(c.execute(
                "SELECT * FROM threat_alerts WHERE cve_id=? ORDER BY id LIMIT 1", (cve_id.upper(),)).fetchone())

    def acknowledge_alert(self, alert_id: int, acknowledged: bool = True) -> bool:
        with self.connect() as c:
            cur = c.execute("UPDATE threat_alerts SET acknowledged=? WHERE id=?",
                            (1 if acknowledged else 0, alert_id))
            return cur.rowcount > 0

    def set_alert_matches(self, alert_id: int, matches: List[str]) -> None:
        with self.connect() as c:
            c.execute("UPDATE threat_alerts SET matched_watchlists=? WHERE id=?",
                      (json.dumps(matches), alert_id))

    # ------------------------------------------------------------------ watchlists
    def add_watchlist(self, kind: str, value: str, notes: str = "") -> Tuple[int, bool]:
        value = value.strip()
        with self.connect() as c:
            row = c.execute("SELECT id FROM watchlists WHERE kind=? AND value=?", (kind, value)).fetchone()
            if row:
                return int(row["id"]), False
            cur = c.execute("INSERT INTO watchlists(kind, value, notes, created_at) VALUES (?,?,?,?)",
                            (kind, value, notes[:500], utcnow_iso()))
            wid = int(cur.lastrowid)
        self.log("watchlist_added", f"{kind}:{value}")
        return wid, True

    def list_watchlists(self, active_only: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM watchlists" + (" WHERE active=1" if active_only else "") + " ORDER BY id"
        with self.connect() as c:
            return self._rows(c.execute(sql).fetchall())

    def set_watchlist_active(self, watch_id: int, active: bool) -> bool:
        with self.connect() as c:
            return c.execute("UPDATE watchlists SET active=? WHERE id=?",
                             (1 if active else 0, watch_id)).rowcount > 0

    def delete_watchlist(self, watch_id: int) -> bool:
        with self.connect() as c:
            return c.execute("DELETE FROM watchlists WHERE id=?", (watch_id,)).rowcount > 0

    # ------------------------------------------------------------------ activity
    def log(self, action: str, detail: str = "", investigation_id: Optional[int] = None,
            actor: str = "system") -> None:
        try:
            with self.connect() as c:
                c.execute(
                    "INSERT INTO activity_logs(investigation_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                    (investigation_id, actor, action, detail[:1000], utcnow_iso()),
                )
        except sqlite3.Error:
            pass  # logging must never break the caller

    def list_activity(self, limit: int = 100, investigation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql, params = "SELECT * FROM activity_logs", []
        if investigation_id is not None:
            sql += " WHERE investigation_id=?"
            params.append(investigation_id)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self.connect() as c:
            return self._rows(c.execute(sql, params).fetchall())

    # ------------------------------------------------------------------ scheduled tasks
    def add_task(self, name: str, task_type: str, interval_minutes: int,
                 params: Optional[Dict[str, Any]] = None, enabled: bool = True) -> int:
        now = datetime.now(timezone.utc)
        with self.connect() as c:
            cur = c.execute(
                """INSERT INTO scheduled_tasks(name, task_type, params, interval_minutes, enabled, next_run, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (name[:120], task_type, json.dumps(params or {}), interval_minutes, 1 if enabled else 0,
                 now.isoformat(timespec="seconds"), utcnow_iso()),
            )
            return int(cur.lastrowid)

    def list_tasks(self) -> List[Dict[str, Any]]:
        with self.connect() as c:
            return self._rows(c.execute("SELECT * FROM scheduled_tasks ORDER BY id").fetchall())

    def get_task(self, task_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            return self._row(c.execute("SELECT * FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone())

    def due_tasks(self, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
        stamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
        with self.connect() as c:
            return self._rows(c.execute(
                "SELECT * FROM scheduled_tasks WHERE enabled=1 AND next_run<=? ORDER BY next_run", (stamp,)
            ).fetchall())

    def record_task_run(self, task_id: int, status: str, message: str) -> None:
        task = self.get_task(task_id)
        if not task:
            return
        now = datetime.now(timezone.utc)
        nxt = now + timedelta(minutes=int(task["interval_minutes"]))
        with self.connect() as c:
            c.execute(
                "UPDATE scheduled_tasks SET last_run=?, next_run=?, last_status=?, last_message=? WHERE id=?",
                (now.isoformat(timespec="seconds"), nxt.isoformat(timespec="seconds"), status, message[:500], task_id),
            )

    def set_task_enabled(self, task_id: int, enabled: bool) -> bool:
        with self.connect() as c:
            return c.execute("UPDATE scheduled_tasks SET enabled=? WHERE id=?",
                             (1 if enabled else 0, task_id)).rowcount > 0

    def delete_task(self, task_id: int) -> bool:
        with self.connect() as c:
            return c.execute("DELETE FROM scheduled_tasks WHERE id=?", (task_id,)).rowcount > 0

    # ------------------------------------------------------------------ reports
    def add_report(self, investigation_id: int, title: str, fmt: str, path: str) -> int:
        with self.connect() as c:
            cur = c.execute("INSERT INTO reports(investigation_id, title, format, path, created_at) VALUES (?,?,?,?,?)",
                            (investigation_id, title[:200], fmt, path, utcnow_iso()))
            rid = int(cur.lastrowid)
        self.log("report_generated", f"{fmt}: {title}", investigation_id)
        return rid

    def list_reports(self, investigation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql, params = "SELECT * FROM reports", []
        if investigation_id is not None:
            sql += " WHERE investigation_id=?"
            params.append(investigation_id)
        sql += " ORDER BY id DESC"
        with self.connect() as c:
            return self._rows(c.execute(sql, params).fetchall())

    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as c:
            return self._row(c.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone())

    # ------------------------------------------------------------------ search
    def search(self, term: str, limit: int = 25) -> Dict[str, List[Dict[str, Any]]]:
        term = term.strip()
        if not term:
            return {"investigations": [], "entities": [], "findings": [], "alerts": [], "evidence": []}
        pat = _like(term)
        with self.connect() as c:
            inv = c.execute(
                "SELECT id, name, description, status, updated_at FROM investigations "
                "WHERE name LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' LIMIT ?", (pat, pat, limit)).fetchall()
            ent = c.execute(
                """SELECT e.id, e.investigation_id, i.name AS investigation_name, e.type, e.value, e.label,
                   e.confidence FROM entities e JOIN investigations i ON i.id=e.investigation_id
                   WHERE e.value LIKE ? ESCAPE '\\' OR e.label LIKE ? ESCAPE '\\' OR e.attributes LIKE ? ESCAPE '\\'
                   ORDER BY e.confidence DESC LIMIT ?""", (pat, pat, pat, limit)).fetchall()
            fin = c.execute(
                """SELECT f.id, f.investigation_id, f.module, f.title, f.summary, f.severity, f.confidence
                   FROM findings f WHERE f.title LIKE ? ESCAPE '\\' OR f.summary LIKE ? ESCAPE '\\'
                   ORDER BY f.id DESC LIMIT ?""", (pat, pat, limit)).fetchall()
            alr = c.execute(
                """SELECT id, feed, title, severity, cve_id, vendor, product, published_at FROM threat_alerts
                   WHERE title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR cve_id LIKE ? ESCAPE '\\'
                   OR vendor LIKE ? ESCAPE '\\' OR product LIKE ? ESCAPE '\\'
                   ORDER BY COALESCE(published_at, created_at) DESC LIMIT ?""", (pat,) * 5 + (limit,)).fetchall()
            evi = c.execute(
                """SELECT id, investigation_id, filename, sha256, notes FROM evidence
                   WHERE filename LIKE ? ESCAPE '\\' OR sha256 LIKE ? ESCAPE '\\' OR notes LIKE ? ESCAPE '\\' LIMIT ?""",
                (pat, pat, pat, limit)).fetchall()
        return {
            "investigations": self._rows(inv), "entities": self._rows(ent), "findings": self._rows(fin),
            "alerts": self._rows(alr), "evidence": self._rows(evi),
        }

    # ------------------------------------------------------------------ analytics
    def timeline(self, investigation_id: int, limit: int = 500) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        with self.connect() as c:
            for r in c.execute(
                "SELECT id, module, title, summary, severity, COALESCE(observed_at, created_at) AS ts "
                "FROM findings WHERE investigation_id=?", (investigation_id,)):
                events.append({"time": r["ts"], "kind": "finding", "title": r["title"],
                               "detail": r["summary"], "severity": r["severity"], "module": r["module"],
                               "ref_id": r["id"]})
            for r in c.execute("SELECT id, filename, notes, collected_at FROM evidence WHERE investigation_id=?",
                               (investigation_id,)):
                events.append({"time": r["collected_at"], "kind": "evidence", "title": f"Evidence: {r['filename']}",
                               "detail": r["notes"], "severity": "info", "module": "EVIDENCE", "ref_id": r["id"]})
            for r in c.execute("SELECT id, action, detail, actor, created_at FROM activity_logs "
                               "WHERE investigation_id=?", (investigation_id,)):
                events.append({"time": r["created_at"], "kind": "activity", "title": r["action"].replace("_", " "),
                               "detail": r["detail"], "severity": "info", "module": r["actor"], "ref_id": r["id"]})
        events.sort(key=lambda e: (e["time"] or "", e["ref_id"]), reverse=True)
        return events[:limit]

    def graph(self, investigation_id: int) -> Dict[str, List[Dict[str, Any]]]:
        entities = self.list_entities(investigation_id, limit=2000)
        rels = self.list_relationships(investigation_id)
        ids = {e["id"] for e in entities}
        nodes = [{"data": {"id": f"e{e['id']}", "label": e["label"] or e["value"], "type": e["type"],
                           "value": e["value"], "confidence": e["confidence"]}} for e in entities]
        edges = [{"data": {"id": f"r{r['id']}", "source": f"e{r['src_entity_id']}",
                           "target": f"e{r['dst_entity_id']}", "label": r["kind"], "confidence": r["confidence"]}}
                 for r in rels if r["src_entity_id"] in ids and r["dst_entity_id"] in ids]
        return {"nodes": nodes, "edges": edges}

    def map_points(self, investigation_id: Optional[int] = None) -> List[Dict[str, Any]]:
        params: List[Any] = []
        where = ""
        if investigation_id is not None:
            where = " AND e.investigation_id=?"
            params.append(investigation_id)
        pts: List[Dict[str, Any]] = []
        with self.connect() as c:
            for r in c.execute(
                f"""SELECT e.id, e.investigation_id, e.type, e.value, e.label, e.lat, e.lon, e.confidence
                    FROM entities e WHERE e.lat IS NOT NULL AND e.lon IS NOT NULL{where}""", params):  # noqa: S608
                pts.append({"kind": "entity", "id": r["id"], "investigation_id": r["investigation_id"],
                            "type": r["type"], "title": r["label"] or r["value"], "lat": r["lat"],
                            "lon": r["lon"], "confidence": r["confidence"]})
            fwhere = where.replace("e.investigation_id", "f.investigation_id")
            for r in c.execute(
                f"""SELECT f.id, f.investigation_id, f.title, f.severity, f.lat, f.lon, f.confidence
                    FROM findings f WHERE f.lat IS NOT NULL AND f.lon IS NOT NULL{fwhere}""", params):  # noqa: S608
                pts.append({"kind": "finding", "id": r["id"], "investigation_id": r["investigation_id"],
                            "type": r["severity"], "title": r["title"], "lat": r["lat"], "lon": r["lon"],
                            "confidence": r["confidence"]})
        return pts

    def cross_investigation_overlaps(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.connect() as c:
            rows = c.execute(
                """SELECT type, value_norm, MIN(value) AS value, COUNT(DISTINCT investigation_id) AS n,
                          GROUP_CONCAT(DISTINCT investigation_id) AS inv_ids
                   FROM entities GROUP BY type, value_norm HAVING n > 1 ORDER BY n DESC LIMIT ?""", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["investigation_ids"] = [int(x) for x in (d.pop("inv_ids") or "").split(",") if x]
            out.append(d)
        return out

    def stats(self) -> Dict[str, Any]:
        with self.connect() as c:
            one = lambda sql, *p: c.execute(sql, p).fetchone()[0]  # noqa: E731
            totals = {
                "investigations": one("SELECT COUNT(*) FROM investigations"),
                "open_investigations": one("SELECT COUNT(*) FROM investigations WHERE status='open'"),
                "entities": one("SELECT COUNT(*) FROM entities"),
                "findings": one("SELECT COUNT(*) FROM findings"),
                "evidence": one("SELECT COUNT(*) FROM evidence"),
                "alerts": one("SELECT COUNT(*) FROM threat_alerts"),
                "unacknowledged_alerts": one("SELECT COUNT(*) FROM threat_alerts WHERE acknowledged=0"),
                "watchlists": one("SELECT COUNT(*) FROM watchlists WHERE active=1"),
                "watchlist_hits": one("SELECT COUNT(*) FROM threat_alerts WHERE matched_watchlists != '[]'"),
            }
            sev = {s: 0 for s in SEVERITIES}
            for r in c.execute("SELECT severity, COUNT(*) n FROM findings GROUP BY severity"):
                sev[r["severity"]] = r["n"]
            alert_sev = {s: 0 for s in SEVERITIES}
            for r in c.execute("SELECT severity, COUNT(*) n FROM threat_alerts GROUP BY severity"):
                alert_sev[r["severity"]] = r["n"]
            types = {r["type"]: r["n"] for r in c.execute(
                "SELECT type, COUNT(*) n FROM entities GROUP BY type ORDER BY n DESC")}
            since = (datetime.now(timezone.utc) - timedelta(days=13)).date().isoformat()
            per_day = {r["d"]: r["n"] for r in c.execute(
                "SELECT substr(created_at,1,10) d, COUNT(*) n FROM findings WHERE substr(created_at,1,10)>=? "
                "GROUP BY d", (since,))}
        days = [(datetime.now(timezone.utc).date() - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
        return {
            "totals": totals, "findings_by_severity": sev, "alerts_by_severity": alert_sev,
            "entities_by_type": types, "findings_per_day": [{"day": d, "count": per_day.get(d, 0)} for d in days],
        }


SYMMETRIC_KINDS = {"shares_infrastructure", "same_username", "related_to", "co_located"}
