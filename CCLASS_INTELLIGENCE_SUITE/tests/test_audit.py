import sqlite3
import threading

import pytest

from cclass_suite.audit import GENESIS, AuditLog
from cclass_suite.db import Database


@pytest.fixture()
def audit(tmp_path):
    return AuditLog(Database(tmp_path / "a.db"))


def _fill(a, n=5):
    for i in range(n):
        a.append("alice", "test.event", actor_id=1, target=f"t{i}", detail=f"d{i}", ip="127.0.0.1")


def test_empty_log_verifies(audit):
    assert audit.verify()["ok"] and audit.head()["hash"] == GENESIS


def test_chain_links_and_verifies(audit):
    _fill(audit)
    v = audit.verify()
    assert v["ok"] and v["entries"] == 5
    rows = audit.list()
    assert rows[0]["prev_hash"] == rows[1]["hash"]
    assert audit.head()["hash"] == rows[0]["hash"]


def test_update_and_delete_blocked_by_triggers(audit):
    _fill(audit, 2)
    with audit.db.connect() as c:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            c.execute("UPDATE audit_log SET actor='mallory' WHERE seq=1")
    with audit.db.connect() as c:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            c.execute("DELETE FROM audit_log WHERE seq=1")
    assert audit.verify()["ok"]


def _bypass(audit, sql):
    """Simulate an attacker with file access who drops the triggers first."""
    conn = sqlite3.connect(audit.db.path)
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("DROP TRIGGER audit_no_delete")
    conn.execute(sql)
    conn.commit()
    conn.close()


def test_detects_altered_row(audit):
    _fill(audit)
    _bypass(audit, "UPDATE audit_log SET detail='nothing happened' WHERE seq=3")
    v = audit.verify()
    assert not v["ok"] and v["first_bad_seq"] == 3 and "altered" in v["problem"]


def test_detects_deleted_row(audit):
    _fill(audit)
    _bypass(audit, "DELETE FROM audit_log WHERE seq=3")
    v = audit.verify()
    assert not v["ok"] and v["first_bad_seq"] == 4


def test_detects_truncation_with_external_head(audit):
    _fill(audit)
    head = audit.head()["hash"]
    _bypass(audit, "DELETE FROM audit_log WHERE seq=5")
    assert audit.verify()["ok"]                     # internal chain alone cannot see tail removal
    assert not audit.verify(expected_head=head)["ok"]


def test_concurrent_appends_keep_chain_intact(audit):
    def work(k):
        for i in range(10):
            audit.append(f"u{k}", "c.event", detail=str(i))
    ts = [threading.Thread(target=work, args=(k,)) for k in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    v = audit.verify()
    assert v["ok"] and v["entries"] == 40


def test_filters_pagination_and_export(audit):
    _fill(audit, 3)
    audit.append("bob", "auth.login", detail="=HYPERLINK(\"http://x\")")
    assert len(audit.list(actor="bob")) == 1
    assert len(audit.list(action="auth.")) == 1
    assert len(audit.list(action="%")) == 0          # wildcard is escaped, not interpreted
    assert len(audit.list(limit=2)) == 2
    csv_text = audit.export("csv")
    assert "'=HYPERLINK" in csv_text and ",=HYPERLINK" not in csv_text
    assert '"verification"' in audit.export("json")


def test_long_fields_are_truncated(audit):
    audit.append("a" * 500, "x", detail="d" * 10000)
    row = audit.list()[0]
    assert len(row["actor"]) == 80 and len(row["detail"]) == 2000
    assert audit.verify()["ok"]
