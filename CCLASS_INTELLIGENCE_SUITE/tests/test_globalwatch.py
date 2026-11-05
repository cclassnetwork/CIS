from datetime import datetime, timedelta, timezone

import pytest

from cclass_suite.modules import REGISTRY
from cclass_suite.modules.globalwatch import (build_event, classify_severity, dedupe, find_term, format_report,
                                              parse_rss_items, select_events, split_title_source)
from cclass_suite.utils import HttpResult

NOW = datetime.now(timezone.utc)


def ev(title, cat="X"):
    return build_event(cat, title, "https://x.example", NOW)


def test_severity_levels():
    assert classify_severity("Militants attack base") == "HIGH"
    assert classify_severity("Officials warn of tension") == "MEDIUM"
    assert classify_severity("Minister opens new school") == "LOW"


def test_split_title_source():
    assert split_title_source("Big news - Some Outlet") == ("Big news", "Some Outlet")
    assert split_title_source("A - B - Outlet") == ("A - B", "Outlet")
    assert split_title_source("No source") == ("No source", None)


def test_country_and_region_detection():
    e = ev("Militants attack military base in Borno - Wire")
    assert (e["country"], e["region"], e["severity"], e["source"]) == ("Nigeria", "Borno", "HIGH", "Wire")
    assert ev("UK launches preparedness campaign")["country"] == "United Kingdom"
    assert ev("Airstrike hits Gaza")["country"] == "Palestine"
    assert ev("Calm headline with no place")["country"] == "Unknown"


def test_fixes_over_original_script():
    # the pronoun "us" must not be read as the United States, but the abbreviation "US" must
    assert ev("Parliament asks the public: tell us what you think")["country"] == "Unknown"
    assert ev("US sanctions announced")["country"] == "United States"
    # "Niger Delta" is a Nigerian region, not the country Niger
    d = ev("Pipeline sabotage in Niger Delta")
    assert (d["country"], d["region"]) == ("Nigeria", "Niger Delta")
    assert ev("Floods hit Niger and Mali")["country"] == "Niger"


def test_filters_dedupe_sort_cap():
    raw = [("A", "Gunmen attack village in Kano - W1", "", NOW), ("A", "Gunmen attack village in Kano - W2", "", NOW),
           ("A", "Officials warn of threat in Kano - W", "", NOW - timedelta(hours=1)),
           ("A", "Opening of new school in Kano - W", "", NOW), ("A", "Bomb blast in Kenya - W", "", NOW)]
    out = select_events(raw, "Nigeria", "Kano", "MEDIUM", 5)
    assert [e["severity"] for e in out] == ["HIGH", "MEDIUM"]          # deduped, LOW hidden, Kenya filtered out
    assert len(select_events(raw, None, None, "LOW", 2)) == 2          # per-category cap
    assert len(dedupe([ev("Same Headline!"), ev("same   headline")])) == 1
    # a user supplied state not in the built-in list is still recognised
    custom = select_events([("A", "Attack in Enugu city", "", NOW)], "Nigeria", "Enugu", "LOW", 3)
    assert custom and custom[0]["region"] == "Enugu" and custom[0]["country"] == "Nigeria"


RSS = b"""<?xml version="1.0" encoding="UTF-8"?><rss><channel>
<item><title>Rebels attack Gao in Mali - Wire</title><link>https://news.example/a</link><pubDate>%s</pubDate></item>
<item><title>Old story - Wire</title><link>https://news.example/old</link><pubDate>Mon, 01 Jan 2001 10:00:00 +0000</pubDate></item>
<item><title>Bad link - Wire</title><link>javascript:alert(1)</link></item>
<item><title></title></item></channel></rss>"""


def test_rss_parsing_age_and_link_safety():
    stamp = NOW.strftime("%a, %d %b %Y %H:%M:%S +0000").encode()
    items = parse_rss_items(RSS % stamp, "CAT", 3, 10)
    assert [i[1] for i in items] == ["Rebels attack Gao in Mali - Wire", "Bad link - Wire"]  # old and empty dropped
    assert items[1][2] == ""                                                                    # non-http link removed
    assert parse_rss_items(b"<<not xml", "CAT", 3, 10) == []
    assert parse_rss_items(b'<!DOCTYPE x [<!ENTITY a "b">]><rss/>', "CAT", 3, 10) == []


def test_offline_run_stores_events(ctx, inv):
    from cclass_suite.ingest import persist_result
    r = REGISTRY["GLOBALWATCH"].safe_run("global", ctx.mctx, min_severity="LOW", max_per_category=10)
    assert r.ok and r.offline and len(r.raw["events"]) >= 8
    assert "Sample Wire" in r.raw["events"][0]["source"]               # clearly marked as sample data
    stats = persist_result(ctx.db, inv, r)
    assert stats["findings_new"] >= 8
    assert persist_result(ctx.db, inv, r)["findings_new"] == 0          # rerun creates no duplicates
    assert any(e["type"] == "event" for e in ctx.db.list_entities(inv))
    assert ctx.db.graph(inv)["edges"]
    findings = ctx.db.list_findings(inv, limit=50)
    assert max(f["confidence"] for f in findings) < 0.5                 # headline keywords are low confidence


def test_offline_country_state_filters(ctx):
    r = REGISTRY["GLOBALWATCH"].safe_run("Nigeria | Borno", ctx.mctx, min_severity="LOW")
    assert r.ok and r.raw["events"] and all(e["region"] == "Borno" and e["country"] == "Nigeria" for e in r.raw["events"])
    none = REGISTRY["GLOBALWATCH"].safe_run("Narnia", ctx.mctx)
    assert none.ok and not none.raw["events"] and none.warnings


@pytest.mark.parametrize("kw", [{"days": 0}, {"days": 31}, {"days": "x"}, {"max_per_category": 11}, {"min_severity": "ULTRA"}])
def test_option_validation(ctx, kw):
    assert not REGISTRY["GLOBALWATCH"].safe_run("global", ctx.mctx, **kw).ok


@pytest.mark.parametrize("q", ["Nigeria\" OR site:evil.example", "Ni<script>", "x"])
def test_place_input_is_restricted(ctx, q):
    assert not REGISTRY["GLOBALWATCH"].safe_run(q, ctx.mctx).ok          # blocks search-operator / markup injection


def test_online_fetch_and_failure_modes(settings, monkeypatch):
    from cclass_suite.context import AppContext
    settings.offline_mode = False
    c = AppContext(settings, console_log=False)
    calls = []
    stamp = NOW.strftime("%a, %d %b %Y %H:%M:%S +0000").encode()

    def fake_get(url, params=None, **kw):
        calls.append(params["q"])
        return HttpResult(True, 200, None, (RSS % stamp).decode(), None, url)

    monkeypatch.setattr(c.http, "get", fake_get)
    r = REGISTRY["GLOBALWATCH"].safe_run("Mali", c.mctx, state="Gao")
    assert r.ok and len(calls) == 4 and all('"Gao" "Mali"' in q and "when:3d" in q for q in calls)
    assert r.raw["events"] and not r.offline

    monkeypatch.setattr(c.http, "get", lambda url, **kw: HttpResult(False, None, None, "", "boom", url))
    failed = REGISTRY["GLOBALWATCH"].safe_run("Mali", c.mctx)
    assert not failed.ok and "unavailable" in failed.error and "boom" in failed.error

    flaky = iter([HttpResult(False, None, None, "", "boom", "u")] + [HttpResult(True, 200, None, (RSS % stamp).decode(), None, "u")] * 3)
    monkeypatch.setattr(c.http, "get", lambda url, **kw: next(flaky))
    partial = REGISTRY["GLOBALWATCH"].safe_run("Mali", c.mctx)
    assert partial.ok and any("could not fetch" in w for w in partial.warnings)   # one failed feed does not kill the run


def test_report_format_matches_original_layout():
    text = format_report([ev("Militants attack base in Borno - Wire")], "Nigeria", "Borno", True)
    for needle in ("GLOBAL WATCH 2026", "INTERNATIONAL OSINT", "Filter: Borno, Nigeria", "[HIGH] X", "Country: Nigeria",
                   "Region: Borno", "Source: Wire", "Link: https://x.example", "TOTAL EVENTS: 1", "HIGH: 1"):
        assert needle in text
    assert "No events found" in format_report([])


def test_cli_globalwatch(tmp_path, monkeypatch, capsys):
    import cclass
    monkeypatch.setenv("CCLASS_HOME", str(tmp_path))
    assert cclass.main(["--offline", "globalwatch", "--min-severity", "LOW", "--links"]) == 0
    out = capsys.readouterr().out
    assert "GLOBAL WATCH 2026" in out and "Saved to investigation #1" in out
    assert cclass.main(["--offline", "globalwatch", "--min-severity", "LOW", "--no-save"]) == 0
    assert cclass.main(["--offline", "globalwatch", "--days", "99"]) == 1
