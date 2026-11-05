from datetime import date, timedelta

import pytest

from cclass_suite.models import normalise_tags, validate_due_date

PW = "Tr1cky-Passphrase!"


def test_defaults_for_new_and_legacy_cases(ctx):
    iid = ctx.db.create_investigation("plain")
    inv = ctx.db.get_investigation(iid)
    assert inv["tlp"] == "AMBER" and inv["tags"] == "" and inv["due_date"] is None
    assert inv["assignee"] is None and inv["comment_count"] == 0


def test_create_with_case_fields(ctx):
    uid = ctx.accounts.create_user("ana", PW, "analyst")
    iid = ctx.db.create_investigation("full", "d", "high", "RED", ["Phishing", "apt-29", "phishing"],
                                      "2030-01-31", uid)
    inv = ctx.db.get_investigation(iid)
    assert inv["tlp"] == "RED" and inv["tags"] == "phishing,apt-29" and inv["due_date"] == "2030-01-31"
    assert inv["assignee"] == "ana"


@pytest.mark.parametrize("kwargs", [
    {"tlp": "PURPLE"}, {"tags": ["bad tag!"]}, {"tags": [f"t{i}" for i in range(11)]},
    {"due_date": "31/01/2030"}, {"due_date": "2030-02-30"}, {"assignee_id": 9999},
])
def test_invalid_case_fields_rejected(ctx, kwargs):
    with pytest.raises(ValueError):
        ctx.db.create_investigation("x", **kwargs)
    iid = ctx.db.create_investigation("y")
    with pytest.raises(ValueError):
        ctx.db.update_investigation(iid, **kwargs)


def test_update_and_clear_fields(ctx):
    uid = ctx.accounts.create_user("ana", PW, "analyst")
    iid = ctx.db.create_investigation("c")
    assert ctx.db.update_investigation(iid, assignee_id=uid, due_date="2031-05-01", tlp="GREEN", tags="a, b")
    inv = ctx.db.get_investigation(iid)
    assert (inv["assignee"], inv["due_date"], inv["tlp"], inv["tags"]) == ("ana", "2031-05-01", "GREEN", "a,b")
    assert ctx.db.update_investigation(iid, assignee_id=None, due_date=None)      # explicit clear
    inv = ctx.db.get_investigation(iid)
    assert inv["assignee"] is None and inv["due_date"] is None and inv["tlp"] == "GREEN"
    assert not ctx.db.update_investigation(iid, name=None)                          # None never blanks a name


def test_cannot_assign_to_disabled_user(ctx):
    ctx.accounts.create_user("root1", PW, "admin")
    uid = ctx.accounts.create_user("ana", PW, "analyst")
    ctx.accounts.update_user(uid, disabled=True)
    iid = ctx.db.create_investigation("c")
    with pytest.raises(ValueError):
        ctx.db.update_investigation(iid, assignee_id=uid)


def test_deleting_user_unassigns_cases(ctx):
    ctx.accounts.create_user("root1", PW, "admin")
    uid = ctx.accounts.create_user("ana", PW, "analyst")
    iid = ctx.db.create_investigation("c", assignee_id=uid)
    ctx.accounts.delete_user(uid)
    assert ctx.db.get_investigation(iid)["assignee_id"] is None


def test_filters(ctx):
    a = ctx.accounts.create_user("ana", PW, "analyst")
    past = (date.today() - timedelta(days=3)).isoformat()
    future = (date.today() + timedelta(days=30)).isoformat()
    one = ctx.db.create_investigation("one", tags="phishing,apt", assignee_id=a, due_date=past, tlp="RED")
    two = ctx.db.create_investigation("two", tags="phishing-kit", due_date=future)
    three = ctx.db.create_investigation("three", due_date=past)
    ctx.db.update_investigation(three, status="closed")
    ids = lambda **k: {i["id"] for i in ctx.db.list_investigations(**k)}  # noqa: E731
    assert ids(tag="phishing") == {one}                    # whole-tag match, not substring
    assert ids(tag="PHISHING") == {one}
    assert ids(assignee_id=a) == {one}
    assert ids(tlp="RED") == {one}
    assert ids(overdue=True) == {one}                      # closed and future cases are not overdue
    assert ids() == {one, two, three}
    assert ids(tag="%") == set()


def test_tag_and_date_helpers():
    assert normalise_tags(None) == "" and normalise_tags(" A , b ,, a ") == "a,b"
    assert normalise_tags("two words") == "two-words"
    assert validate_due_date("") is None and validate_due_date("2030-12-31") == "2030-12-31"


def test_comments(ctx, inv):
    uid = ctx.accounts.create_user("ana", PW, "analyst")
    cid = ctx.db.add_comment(inv, uid, "Ana", "First note\nsecond line <b>x</b>")
    ctx.db.add_comment(inv, uid, "Ana", "second")
    rows = ctx.db.list_comments(inv)
    assert [r["body"] for r in rows][1] == "second" and "<b>x</b>" in rows[0]["body"]   # stored verbatim; UI escapes
    assert ctx.db.get_investigation(inv)["comment_count"] == 2
    with pytest.raises(ValueError):
        ctx.db.add_comment(inv, uid, "Ana", "   ")
    with pytest.raises(ValueError):
        ctx.db.add_comment(inv, uid, "Ana", "x" * 5001)
    assert ctx.db.delete_comment(cid) and not ctx.db.delete_comment(cid)
    ctx.delete_investigation(inv)                                                       # cascades
    assert ctx.db.list_comments(inv) == []


@pytest.mark.parametrize("fmt", ["html", "txt", "csv", "json"])
def test_tlp_marking_in_reports(ctx, inv, fmt):
    ctx.db.update_investigation(inv, tlp="AMBER+STRICT", tags="x")
    ctx.db.add_finding(inv, "A finding", "s")
    text = ctx.reports.generate(inv, fmt).read_text()
    assert "AMBER+STRICT" in text
    if fmt == "html":
        assert "TLP:AMBER+STRICT" in text and "tlp-AMBER-STRICT" in text


def test_tlp_marking_in_pdf(ctx, inv):
    pytest.importorskip("reportlab")
    ctx.db.update_investigation(inv, tlp="RED")
    path = ctx.reports.generate(inv, "pdf")
    assert path.read_bytes()[:4] == b"%PDF"
