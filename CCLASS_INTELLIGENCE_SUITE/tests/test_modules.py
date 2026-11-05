import ipaddress
import json
import zipfile

import pytest

from cclass_suite.modules import CATALOG, REGISTRY
from cclass_suite.modules.domainintel import parse_ct_rows
from cclass_suite.modules.emailintel import analyze_dmarc, analyze_spf
from cclass_suite.modules.geoint import bearing_deg, compass, haversine_km
from cclass_suite.modules.ipintel import classify_ip, cymru_name
from cclass_suite.modules.socialintel import username_from_url, username_variants
from cclass_suite.modules.threatmonitor import parse_kev, parse_nvd, parse_rss


def titles(result):
    return [f.title for f in result.findings]


def test_catalog_has_all_required_modules_plus_globalwatch():
    names = {m["name"] for m in CATALOG}
    assert names == {"GLOBALWATCH", "XKEYSEARCH", "EMAILINTEL", "IPINTEL", "DOMAININTEL", "SOCIALINTEL", "GEOINT", "THREATMONITOR",
                     "METADATA", "NETWORKINTEL", "REPORTGEN"}


def test_emailintel_offline(ctx):
    r = REGISTRY["EMAILINTEL"].safe_run("admin@demo-corp.example", ctx.mctx)
    assert r.ok and r.offline
    t = " | ".join(titles(r))
    assert "Role-based account" in t and "MX record" in t and "SPF soft-fail" in t and "DMARC policy: none" in t
    assert any(e.type == "domain" and e.value == "demo-corp.example" for e in r.entities)


def test_emailintel_rejects_bad_input(ctx):
    for bad in ("not-an-email", "a@b", "", "x@@y.example"):
        r = REGISTRY["EMAILINTEL"].safe_run(bad, ctx.mctx)
        assert not r.ok and "invalid" in r.error


def test_spf_dmarc_parsers():
    spf = analyze_spf(["v=spf1 include:a.example mx -all"])
    assert spf["all"] == "-" and spf["lookups"] == 2
    assert analyze_spf(["unrelated"])["present"] is False
    assert analyze_spf(["v=spf1 +all"])["all"] == "+"
    d = analyze_dmarc(["v=DMARC1; p=reject; pct=50; rua=mailto:x@y.example"])
    assert d["policy"] == "reject" and d["pct"] == 50 and d["rua"]


def test_ipintel_offline_and_classification(ctx):
    r = REGISTRY["IPINTEL"].safe_run("203.0.113.10", ctx.mctx)
    assert r.ok
    assert any(e.type == "asn" and e.value == "AS64500" for e in r.entities)
    assert any(e.type == "place" and e.lat is not None for e in r.entities)
    assert classify_ip(ipaddress.ip_address("10.1.2.3")) == "private"
    p = REGISTRY["IPINTEL"].safe_run("192.168.1.5", ctx.mctx)
    assert p.ok and "Non-public" in p.findings[0].title and not any(e.type == "asn" for e in p.entities)
    assert not REGISTRY["IPINTEL"].safe_run("999.1.1.1", ctx.mctx).ok


def test_cymru_names():
    assert cymru_name(ipaddress.ip_address("203.0.113.10")) == "10.113.0.203.origin.asn.cymru.com"
    assert cymru_name(ipaddress.ip_address("2001:db8::1")).endswith(".origin6.asn.cymru.com")


def test_domainintel_offline(ctx):
    r = REGISTRY["DOMAININTEL"].safe_run("demo-corp.example", ctx.mctx)
    assert r.ok
    subs = {e.value for e in r.entities if e.type == "domain"}
    assert {"www.demo-corp.example", "vpn.demo-corp.example", "dev.demo-corp.example"} <= subs
    assert any(rel.kind == "subdomain_of" for rel in r.relations)
    assert "Sub-domains with sensitive-sounding names are publicly logged" in titles(r)


def test_domainintel_new_domain_flag(ctx):
    r = REGISTRY["DOMAININTEL"].safe_run("demo-new.example", ctx.mctx)
    assert "Newly registered domain" in titles(r)


def test_domainintel_unknown_degrades_gracefully(ctx):
    r = REGISTRY["DOMAININTEL"].safe_run("never-heard-of-it.example", ctx.mctx)
    assert r.ok and r.warnings  # no crash, explains what was unavailable
    assert not REGISTRY["DOMAININTEL"].safe_run("bad_domain", ctx.mctx).ok


def test_ct_parser_filters_foreign_names():
    rows = [{"name_value": "a.example.com\n*.example.com\nevil.other.com", "issuer_name": "C=US, O=LE, CN=R3"}, "junk"]
    names, issuers, count, wildcard = parse_ct_rows(rows, "example.com")
    assert names == {"a.example.com", "example.com"} and wildcard and issuers["LE"] == 1 and count == 1
    assert parse_ct_rows({"not": "a list"}, "example.com")[2] == 0


def test_socialintel(ctx):
    r = REGISTRY["SOCIALINTEL"].safe_run("demo_user", ctx.mctx)
    assert r.ok and any("3 platform" in t for t in titles(r))
    none = REGISTRY["SOCIALINTEL"].safe_run("nobody_here", ctx.mctx)
    assert none.ok and none.warnings
    assert not REGISTRY["SOCIALINTEL"].safe_run("x", ctx.mctx).ok
    assert username_from_url("https://github.com/octocat/hello") == {"platform": "GitHub", "username": "octocat"}
    assert username_from_url("https://example.com/octocat") is None
    assert "demo.user" in username_variants("demo_user")


def test_socialintel_unknown_platform_status_not_treated_as_found(settings):
    from cclass_suite.modules.socialintel import PLATFORMS, UNKNOWN
    from cclass_suite.utils import HttpResult
    assert all(p.check(HttpResult(False, 429, None, "", "HTTP 429", "u")) != "found" for p in PLATFORMS)
    assert UNKNOWN


def test_geoint(ctx):
    r = REGISTRY["GEOINT"].safe_run("Lagos", ctx.mctx)
    assert r.ok and any(e.type == "place" and abs(e.lat - 6.5244) < 1e-3 for e in r.entities)
    d = REGISTRY["GEOINT"].safe_run("Lagos | London", ctx.mctx)
    km = d.findings[0].data["km"]
    assert 4950 < km < 5100
    c = REGISTRY["GEOINT"].safe_run("6.45,3.4", ctx.mctx)
    assert "Nearest known city: Lagos" in c.findings[0].title
    assert REGISTRY["GEOINT"].safe_run("Atlantisville", ctx.mctx).findings[0].title == "Place not found"
    assert not REGISTRY["GEOINT"].safe_run("A | B | C", ctx.mctx).ok


def test_geo_math():
    assert abs(haversine_km(0, 0, 0, 1) - 111.19) < 0.1
    assert haversine_km(10, 10, 10, 10) == 0
    assert compass(bearing_deg(0, 0, 10, 0)) == "N" and compass(bearing_deg(0, 0, 0, 10)) == "E"


def test_threat_parsers():
    feed = json.loads(open("sample_data/sample_threat_feed.json").read())
    items = parse_kev(feed)
    assert len(items) == 6 and items[0]["severity"] in ("critical", "high")
    assert parse_kev(None) == [] and parse_kev({"vulnerabilities": [None, {}]}) == []
    nvd = parse_nvd({"vulnerabilities": [{"cve": {"id": "CVE-2030-0001", "published": "2030-01-01T00:00:00",
                     "descriptions": [{"lang": "en", "value": "bad thing"}],
                     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]})
    assert nvd[0]["severity"] == "critical" and nvd[0]["data"]["cvss"] == 9.8
    rss = parse_rss("<rss><channel><item><title>Alert CVE-2030-1111 hits</title><link>https://x.example/a</link>"
                    "<pubDate>Mon, 01 Jan 2030 10:00:00 +0000</pubDate><description>&lt;b&gt;desc&lt;/b&gt;</description></item></channel></rss>")
    assert rss[0]["cve_id"] == "CVE-2030-1111" and rss[0]["published_at"].startswith("2030-01-01")
    assert parse_rss("<<<not xml") == []
    assert parse_rss('<!DOCTYPE x [<!ENTITY a "b">]><rss/>') == []  # entity declarations are refused


def test_threat_feed_refresh_and_watchlist(ctx):
    ctx.db.add_watchlist("keyword", "citrix")
    out = ctx.feeds.refresh(offline_sample=True)
    assert out["new_alerts"] == 6 and out["matched"] >= 1
    assert ctx.feeds.refresh(offline_sample=True)["new_alerts"] == 0  # duplicates not re-added
    hits = ctx.db.list_alerts(matched_only=True)
    assert hits and all("keyword:citrix" in a["matched_watchlists"] for a in hits)
    r = REGISTRY["THREATMONITOR"].safe_run("CVE-2021-44228", ctx.mctx)
    assert r.ok and r.findings[0].severity in ("critical", "high")


def test_feed_failure_is_reported_not_raised(settings, monkeypatch):
    from cclass_suite.context import AppContext
    settings.offline_mode = False
    ctx = AppContext(settings, console_log=False)
    monkeypatch.setattr(ctx.http, "get", lambda *a, **k: __import__("cclass_suite.utils", fromlist=["HttpResult"]).HttpResult(False, None, None, "", "boom", "u"))
    out = ctx.feeds.refresh()
    assert out["new_alerts"] == 0 and all(not f["ok"] and f["error"] == "boom" for f in out["feeds"].values())


def test_http_client_offline_and_bad_scheme(settings):
    from cclass_suite.utils import HttpClient
    assert "offline" in HttpClient(settings).get("https://example.com").error
    settings.offline_mode = False
    assert "only http" in HttpClient(settings).get("file:///etc/passwd").error
    assert "only http" in HttpClient(settings).get("ftp://example.com/x").error


def test_module_crash_is_contained(ctx):
    from cclass_suite.modules.base import Module

    class Boom(Module):
        name = "BOOM"

        def run(self, query, ctx, **o):
            raise RuntimeError("secret internals")

    r = Boom().safe_run("x", ctx.mctx)
    assert not r.ok and "secret internals" not in r.error
