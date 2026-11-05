import json
import sqlite3
import zipfile

from cclass_suite.db import MIGRATIONS
from pathlib import Path

import pytest

from cclass_suite import backup
from cclass_suite.audit import AuditLog
from cclass_suite.backup import BackupError


def seed(ctx):
    inv = ctx.db.create_investigation("case A", "d")
    ev = ctx.settings.evidence_dir / "note.txt"
    ev.write_text("evidence body")
    rep = ctx.settings.reports_dir / "r.html"
    rep.write_text("<html>r</html>")
    ctx.audit.append("alice", "login.ok")
    ctx.settings.save()
    return inv


def test_backup_verify_roundtrip(ctx):
    seed(ctx)
    p = backup.create_backup(ctx.settings)
    assert p.exists() and backup.NAME_RE.match(p.name) and (p.stat().st_mode & 0o077) == 0
    v = backup.verify_backup(p)
    assert v["ok"] and v["files"] >= 4 and v["schema_version"] == max(m[0] for m in MIGRATIONS)
    names = zipfile.ZipFile(p).namelist()
    assert {"database.db", "settings.json", "evidence/note.txt", "reports/r.html", "MANIFEST.json"} <= set(names)


def test_two_backups_in_one_second_do_not_collide(ctx):
    seed(ctx)
    a, b = backup.create_backup(ctx.settings), backup.create_backup(ctx.settings)
    assert a != b and len(backup.list_backups(ctx.settings)) == 2


def test_tampered_backup_detected(ctx, tmp_path):
    seed(ctx)
    p = backup.create_backup(ctx.settings)
    bad = tmp_path / "cclass_backup_20200101T000000Z.zip"
    with zipfile.ZipFile(p) as src, zipfile.ZipFile(bad, "w") as out:
        for n in src.namelist():
            data = src.read(n)
            if n == "evidence/note.txt":
                data = b"tampered"
            out.writestr(n, data)
    v = backup.verify_backup(bad)
    assert not v["ok"] and any("checksum" in x for x in v["problems"])


def test_zip_slip_and_foreign_entries_rejected(ctx, tmp_path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as out:
        out.writestr("MANIFEST.json", json.dumps({"files": {}}))
        out.writestr("../../etc/cron.d/x", "boom")
    v = backup.verify_backup(z)
    assert not v["ok"] and "unsafe" in v["problems"][0]
    assert not backup.verify_backup(tmp_path / "missing.zip")["ok"]
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not a zip")
    assert not backup.verify_backup(junk)["ok"]


def test_restore_replaces_data_and_makes_safety_backup(ctx):
    inv = seed(ctx)
    p = backup.create_backup(ctx.settings)
    # change things after the backup
    ctx.db.create_investigation("case B after backup")
    (ctx.settings.evidence_dir / "note.txt").write_text("changed")
    (ctx.settings.evidence_dir / "extra.txt").write_text("new")
    ctx.audit.append("alice", "later.event")
    res = backup.restore_backup(p, ctx.settings)
    assert res["safety_backup"] and backup.verify_backup(ctx.settings.backups_dir / res["safety_backup"])["ok"]
    names = [i["name"] for i in __import__("cclass_suite.db", fromlist=["Database"]).Database(ctx.settings.db_path).list_investigations()]
    assert names == ["case A"]
    assert (ctx.settings.evidence_dir / "note.txt").read_text() == "evidence body"
    assert not (ctx.settings.evidence_dir / "extra.txt").exists()
    from cclass_suite.db import Database
    audit = AuditLog(Database(ctx.settings.db_path))
    assert audit.verify()["ok"] and audit.count() == 1


def test_restore_refuses_bad_or_newer_backup(ctx, tmp_path):
    seed(ctx)
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"nope")
    with pytest.raises(BackupError):
        backup.restore_backup(junk, ctx.settings)
    p = backup.create_backup(ctx.settings)
    newer = tmp_path / "cclass_backup_20990101T000000Z.zip"
    with zipfile.ZipFile(p) as src, zipfile.ZipFile(newer, "w") as out:
        for n in src.namelist():
            d = src.read(n)
            if n == "MANIFEST.json":
                m = json.loads(d)
                m["schema_version"] = 999
                d = json.dumps(m).encode()
            out.writestr(n, d)
    with pytest.raises(BackupError, match="newer"):
        backup.restore_backup(newer, ctx.settings)


def test_restore_refuses_while_database_locked(ctx):
    seed(ctx)
    p = backup.create_backup(ctx.settings)
    holder = sqlite3.connect(ctx.settings.db_path, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(BackupError, match="in use"):
            backup.restore_backup(p, ctx.settings)
    finally:
        holder.execute("ROLLBACK")
        holder.close()


def test_prune_keeps_newest_and_resolve_is_strict(ctx):
    seed(ctx)
    made = [backup.create_backup(ctx.settings) for _ in range(4)]
    removed = backup.prune_backups(ctx.settings, keep=2)
    assert len(removed) == 2 and len(backup.list_backups(ctx.settings)) == 2
    kept = backup.list_backups(ctx.settings)[0]["name"]
    assert backup.resolve_backup(ctx.settings, kept).is_file()
    for bad in ("../x.zip", "cclass_backup_x.zip", "/etc/passwd", ""):
        with pytest.raises(BackupError):
            backup.resolve_backup(ctx.settings, bad)


def test_retention_only_removes_what_it_should(ctx, inv):
    from datetime import datetime, timedelta, timezone
    old = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat(timespec="seconds")
    new = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with ctx.db.connect() as c:
        for i, (ack, ts) in enumerate([(1, old), (0, old), (1, new)]):
            c.execute("INSERT INTO threat_alerts(feed, external_id, title, acknowledged, created_at) VALUES ('f',?,?,?,?)",
                      (str(i), f"a{i}", ack, ts))
        c.execute("INSERT INTO activity_logs(action, created_at) VALUES ('x', ?)", (old,))
    ctx.audit.append("a", "keep.me")
    assert backup.apply_retention(ctx.db, 30, 30, dry_run=True) == {"alerts": 1, "activity": 1, "sessions": 0}
    assert len(ctx.db.list_alerts(limit=10)) == 3          # dry run changed nothing
    res = backup.apply_retention(ctx.db, 30, 30)
    assert res["alerts"] == 1 and res["activity"] == 1
    titles = {a["title"] for a in ctx.db.list_alerts(limit=10)}
    assert titles == {"a1", "a2"}                           # unacknowledged-old and recent survive
    assert backup.apply_retention(ctx.db, 0, 0) == {"alerts": 0, "activity": 0, "sessions": 0}
    assert ctx.audit.count() == 1 and ctx.audit.verify()["ok"]
    assert ctx.db.get_investigation(inv)                    # cases untouched
