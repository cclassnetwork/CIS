import sqlite3

import pytest

from cclass_suite.db import Database
from cclass_suite.scoring import age_factor, combine, confidence_label, finding_confidence


def test_migrations_idempotent_and_tables(tmp_path):
    path = tmp_path / "x.db"
    db = Database(path)
    assert db.schema_version() == len(__import__("cclass_suite.db", fromlist=["x"]).MIGRATIONS)
    assert Database(path).migrate() == []
    names = {r[0] for r in sqlite3.connect(path).execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for t in ("investigations", "entities", "findings", "evidence", "sources", "threat_alerts", "watchlists",
              "activity_logs", "scheduled_tasks", "relationships", "reports", "users", "sessions", "audit_log",
              "comments"):
        assert t in names


def test_foreign_keys_cascade(ctx, inv):
    eid, _ = ctx.db.upsert_entity(inv, "domain", "a.example")
    ctx.db.add_finding(inv, "T", "t", entity_id=eid)
    ctx.db.add_evidence(inv, "f.txt", "/x", "ab" * 32, 1)
    ctx.delete_investigation(inv)
    with ctx.db.connect() as c:
        for t in ("entities", "findings", "evidence"):
            assert c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] == 0


def test_entity_dedup_and_normalisation(ctx, inv):
    a, new_a = ctx.db.upsert_entity(inv, "email", "Admin@Example.COM")
    b, new_b = ctx.db.upsert_entity(inv, "email", "admin@example.com", attributes={"k": 1})
    assert a == b and new_a and not new_b
    e = ctx.db.get_entity(a)
    assert e["sightings"] == 2 and e["attributes"] == {"k": 1}


def test_finding_duplicate_detection(ctx, inv):
    f1, c1 = ctx.db.add_finding(inv, "M", "Title", "same", entity_key="k")
    f2, c2 = ctx.db.add_finding(inv, "M", "title", "SAME", entity_key="k")
    f3, c3 = ctx.db.add_finding(inv, "M", "Title", "same", entity_key="other")
    assert f1 == f2 and c1 and not c2 and c3
    assert ctx.db.list_findings(inv)[-1]["seen_count"] >= 1


def test_evidence_duplicate_by_hash(ctx, inv):
    _, c1 = ctx.db.add_evidence(inv, "a", "/p", "cd" * 32, 5)
    _, c2 = ctx.db.add_evidence(inv, "b", "/q", "cd" * 32, 5)
    assert c1 and not c2


def test_constraints_reject_bad_values(ctx, inv):
    with pytest.raises(sqlite3.IntegrityError):
        with ctx.db.connect() as c:
            c.execute("INSERT INTO watchlists(kind,value,created_at) VALUES('bogus','x','now')")


def test_search_is_injection_safe_and_escaped(ctx, inv):
    ctx.db.upsert_entity(inv, "domain", "100%-real.example")
    assert ctx.db.search("'; DROP TABLE entities;--")["entities"] == []
    assert len(ctx.db.search("100%")["entities"]) == 1
    ctx.db.upsert_entity(inv, "domain", "plain.example")
    found = [e["value"] for e in ctx.db.search("%")["entities"]]
    assert found == ["100%-real.example"]  # '%' is matched literally, not as a wildcard for every row
    assert [e["value"] for e in ctx.db.search("_lain")["entities"]] == []  # '_' is not a single-char wildcard
    with ctx.db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM entities").fetchone()[0] == 2


def test_watchlist_and_tasks(ctx):
    wid, created = ctx.db.add_watchlist("keyword", "Citrix")
    assert created and not ctx.db.add_watchlist("keyword", "Citrix")[1]
    tid = ctx.db.add_task("t", "feed_refresh", 5)
    assert [t["id"] for t in ctx.db.due_tasks()] == [tid]
    ctx.db.record_task_run(tid, "ok", "done")
    assert ctx.db.due_tasks() == [] and ctx.db.get_task(tid)["last_status"] == "ok"


def test_scoring_math():
    assert combine([0.5, 0.5]) == 0.75 and combine([]) == 0.0 and combine([1.0]) <= 0.99
    assert finding_confidence("A", 1.0) > finding_confidence("C", 1.0) > finding_confidence("E", 1.0)
    assert age_factor("2000-01-01T00:00:00+00:00") == 0.6 and age_factor(None) == 1.0
    assert confidence_label(0.9) == "High" and confidence_label(0.6) == "Medium" and confidence_label(0.1) == "Low"


def test_upgrade_from_v2_keeps_existing_data(tmp_path, monkeypatch):
    """A database created by the previous release must upgrade in place without data loss."""
    from cclass_suite import db as dbmod
    path = tmp_path / "old.db"
    monkeypatch.setattr(dbmod, "MIGRATIONS", dbmod.MIGRATIONS[:2])
    old = Database(path)
    with old.connect() as c:   # raw insert: the v2 schema has no tlp/tags columns
        inv = c.execute(
            "INSERT INTO investigations(name, description, priority, created_at, updated_at) "
            "VALUES (?,?,?,?,?)",
            ("legacy case", "made before accounts existed", "high", "2026-01-01T00:00:00+00:00",
             "2026-01-01T00:00:00+00:00")).lastrowid
    assert old.schema_version() == 2
    monkeypatch.undo()
    new = Database(path)
    assert new.schema_version() == len(dbmod.MIGRATIONS)
    row = new.get_investigation(inv)
    assert row["name"] == "legacy case" and row["tlp"] == "AMBER" and row["tags"] == "" and row["assignee_id"] is None
