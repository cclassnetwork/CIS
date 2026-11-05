import csv
import json

import pytest

from cclass_suite.demo import load_demo
from cclass_suite.modules.reportgen import FORMATS, _csv_safe


def test_xkeysearch_plan(ctx):
    x = ctx.xkey
    assert x.plan("a@b.example") == [("EMAILINTEL", "a@b.example")]
    assert x.plan("203.0.113.9") == [("IPINTEL", "203.0.113.9")]
    assert x.plan("https://github.com/octocat") == [("DOMAININTEL", "github.com"), ("SOCIALINTEL", "octocat")]
    assert x.plan("CVE-2021-44228") == [("THREATMONITOR", "CVE-2021-44228")]
    assert x.plan("Lagos") == [("GEOINT", "Lagos"), ("THREATMONITOR", "Lagos")]
    assert x.plan("10.0.0.0/24") == []


def test_investigate_pivots_and_correlates(ctx):
    out = ctx.xkey.investigate("admin@demo-corp.example")
    mods = [m["module"] for m in out["modules"]]
    assert mods[:2] == ["EMAILINTEL", "DOMAININTEL"] or "DOMAININTEL" in mods
    assert "IPINTEL" in mods                       # domain -> resolved address pivot
    inv = out["investigation_id"]
    kinds = {i["title"].split(":")[0] for i in out["insights"]}
    assert any("Shared infrastructure" in i["title"] for i in out["insights"]), kinds
    assert ctx.db.graph(inv)["edges"]
    again = ctx.xkey.investigate("admin@demo-corp.example", investigation_id=inv)
    assert all(m["stats"]["findings_new"] == 0 for m in again["modules"] if m["ok"])  # no duplicates on rerun


def test_investigate_rejects_bad_input(ctx):
    for q in ("", "x" * 501):
        with pytest.raises(ValueError):
            ctx.xkey.investigate(q)
    with pytest.raises(ValueError):
        ctx.xkey.investigate("a@b.example", modules=["NOPE"])
    with pytest.raises(ValueError):
        ctx.xkey.investigate("10.0.0.0/24", modules=["NETWORKINTEL"])  # active modules can't be launched from search
    with pytest.raises(ValueError):
        ctx.xkey.investigate("a@b.example", investigation_id=999)


def test_confidence_reflects_source_reliability(ctx):
    ctx.xkey.investigate("demo-corp.example", pivot=False)
    findings = ctx.db.list_findings(1, limit=100)
    assert findings and all(f["confidence"] <= 0.4 for f in findings if f["source_reliability"] == "F")
    src = next(s for s in ctx.db.list_sources() if s["name"] == "Offline sample dataset")
    ctx.db.set_source_reliability(src["id"], "A")
    ctx.xkey.investigate("demo-secure.example", pivot=False)
    assert max(f["confidence"] for f in ctx.db.list_findings(2, limit=100)) > 0.5


def test_demo_loads_and_is_repeatable(ctx):
    r = load_demo(ctx)
    inv = r["investigation_id"]
    t1 = ctx.db.stats()["totals"]
    assert t1["entities"] > 15 and t1["findings"] > 20 and t1["alerts"] == 6 and t1["evidence"] == 1 and t1["watchlist_hits"] >= 2
    assert ctx.db.map_points(inv), "demo should produce map points (IP geolocation + EXIF GPS)"
    assert ctx.db.timeline(inv) and ctx.db.graph(inv)["nodes"]
    r2 = load_demo(ctx)
    assert r2["investigation_id"] == inv
    t2 = ctx.db.stats()["totals"]
    assert (t2["findings"], t2["entities"], t2["evidence"], t2["alerts"]) == (t1["findings"], t1["entities"], t1["evidence"], t1["alerts"])


def test_evidence_store_duplicate_and_path_safety(ctx, inv, tmp_path):
    f = tmp_path / "doc.txt"
    f.write_text("hello")
    a = ctx.add_evidence_from_path(inv, f, "../../etc/passwd")
    assert a["filename"] == "passwd" or "/" not in a["filename"]
    g = tmp_path / "doc2.txt"
    g.write_text("hello")
    b = ctx.add_evidence_from_path(inv, g, "other.txt")
    assert b["duplicate"] and b["id"] == a["id"] and not g.exists()
    stored = ctx.db.get_evidence(a["id"])
    assert str(ctx.settings.evidence_dir) in stored["stored_path"]
    assert (ctx.db.get_evidence(a["id"])["sha256"]) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert ctx.delete_evidence(a["id"]) and not ctx.delete_evidence(a["id"])
    with pytest.raises(ValueError):
        ctx.add_evidence_from_path(9999, f, "x")
    assert ctx.safe_filename("..\\..\\a b$.txt") == "a_b_.txt"


@pytest.mark.parametrize("fmt", FORMATS)
def test_reports_all_formats(ctx, fmt):
    r = load_demo(ctx)
    path = ctx.reports.generate(r["investigation_id"], fmt)
    assert path.exists() and path.stat().st_size > 200
    text = path.read_bytes()
    if fmt == "pdf":
        assert text.startswith(b"%PDF")
    if fmt == "json":
        assert json.loads(text)["inv"]["id"] == r["investigation_id"]
    if fmt == "html":
        assert b"demo-corp.example" in text
    assert ctx.db.list_reports(r["investigation_id"])[0]["format"] == fmt


def test_report_escapes_hostile_content_and_csv_injection(ctx, inv):
    ctx.db.add_finding(inv, "T", "<script>alert(1)</script>", "=HYPERLINK(\"http://evil.example\")")
    html = ctx.reports.generate(inv, "html").read_text()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    rows = list(csv.reader(ctx.reports.generate(inv, "csv").open()))
    assert rows[1][5].startswith("'=") and _csv_safe("+1") == "'+1" and _csv_safe("ok") == "ok"
    with pytest.raises(ValueError):
        ctx.reports.generate(inv, "docx")
    with pytest.raises(ValueError):
        ctx.reports.generate(424242, "txt")


def test_scheduler_runs_tasks(ctx):
    ctx.db.add_watchlist("keyword", "citrix")
    ctx.db.add_watchlist("domain", "demo-corp.example")
    t1 = ctx.db.add_task("feeds", "feed_refresh", 5)
    t2 = ctx.db.add_task("watch", "watchlist_scan", 5)
    assert ctx.scheduler.run_due() == 2
    assert ctx.db.get_task(t1)["last_status"] in ("ok", "partial") and ctx.db.get_task(t2)["last_status"] == "ok"
    assert ctx.db.stats()["totals"]["alerts"] == 6
    assert any(i["name"] == "Watchlist monitoring" for i in ctx.db.list_investigations())
    assert ctx.scheduler.run_due() == 0  # not due again until the interval passes
    assert ctx.scheduler.run_task(9999)[0] == "error"


def test_scheduler_thread_lifecycle(ctx):
    ctx.scheduler.start()
    assert ctx.scheduler.running
    ctx.scheduler.stop()
    assert not ctx.scheduler.running


def test_correlation_username_reuse_and_overlap(ctx):
    a = ctx.db.create_investigation("a")
    b = ctx.db.create_investigation("b")
    ctx.xkey.investigate("demo_user", investigation_id=a)
    ctx.xkey.investigate("demo_user", investigation_id=b)
    titles = [f["title"] for f in ctx.db.list_findings(b, module="CORRELATION")]
    assert any("appears on" in t for t in titles) and any("also appears in investigation" in t for t in titles)
