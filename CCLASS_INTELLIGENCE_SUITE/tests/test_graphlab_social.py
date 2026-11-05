import socket

import pytest

from cclass_suite.graphlab import engine, netsafe, social
from cclass_suite.graphlab.store import GraphError, validate_value


@pytest.fixture()
def gid(ctx):
    return ctx.graphs.create_graph("social")


# ------------------------------------------------------------------ URL parsing
@pytest.mark.parametrize("url,platform,handle", [
    ("https://twitter.com/jdoe_demo", "X (Twitter)", "jdoe_demo"),
    ("https://x.com/jdoe", "X (Twitter)", "jdoe"),
    ("https://www.instagram.com/democorp/", "Instagram", "democorp"),
    ("https://www.linkedin.com/in/jane-doe-123/", "LinkedIn", "jane-doe-123"),
    ("https://www.linkedin.com/company/demo-corp", "LinkedIn", "demo-corp"),
    ("https://t.me/durov", "Telegram", "durov"),
    ("https://www.tiktok.com/@someone", "TikTok", "someone"),
    ("https://www.youtube.com/@Chan", "YouTube", "Chan"),
    ("https://www.reddit.com/user/bob", "Reddit", "bob"),
    ("https://bsky.app/profile/alice.bsky.social", "Bluesky", "alice.bsky.social"),
    ("https://news.ycombinator.com/user?id=pg", "Hacker News", "pg"),
])
def test_parse_profile_url(url, platform, handle):
    p = social.parse_profile_url(url)
    assert p and p["platform"] == platform and p["handle"] == handle


@pytest.mark.parametrize("url", [
    "https://x.com/home", "https://www.instagram.com/p/abc/", "https://github.com/orgs", "https://evil.example/@x",
    "https://www.facebook.com/profile.php?id=1", "javascript:alert(1)", "ftp://github.com/x", "https://twitter.com.evil.example/bob",
    "https://notgithub.com/bob", "",
])
def test_parse_rejects_non_profiles_and_lookalikes(url):
    assert social.parse_profile_url(url) is None


def test_extract_links_from_html():
    html = '''<a href="https://twitter.com/acme">x</a><a href="/relative">r</a><link rel="me" href="https://github.com/acme">
              <a href="https://twitter.com/acme">dup</a><a href="javascript:alert(1)">j</a><a href="https://example.org/">o</a>'''
    got = social.extract_social_links(html)
    assert [g["handle"] for g in got] == ["acme", "acme"] and {g["platform"] for g in got} == {"X (Twitter)", "GitHub"}
    assert social.extract_social_links("<<<not html") == []


# ------------------------------------------------------------------ transforms (offline, via the real engine)
def test_url_profile_to_handle_and_pivot(ctx, gid):
    u, _ = ctx.graphs.add_node(gid, "profile", "https://twitter.com/demo_user")
    r = engine.run_on_nodes(ctx.graphs, ctx, gid, "url.profile", [u["id"]], "t")
    assert [n["value"] for n in r["added_nodes"]] == ["demo_user"] and r["added_edges"][0]["label"] == "handle_on_X (Twitter)"
    bad, _ = ctx.graphs.add_node(gid, "url", "https://example.org/x")
    assert engine.run_on_nodes(ctx.graphs, ctx, gid, "url.profile", [bad["id"]], "t")["results"][0]["status"] == "error"


def test_domain_social_offline(ctx, gid):
    d, _ = ctx.graphs.add_node(gid, "domain", "demo-corp.example")
    r = engine.run_on_nodes(ctx.graphs, ctx, gid, "domain.social", [d["id"]], "t")
    types = [n["type"] for n in r["added_nodes"]]
    assert types.count("profile") == 5 and "username" in types           # the plain /about link is ignored
    other, _ = ctx.graphs.add_node(gid, "domain", "unknown.example")
    assert engine.run_on_nodes(ctx.graphs, ctx, gid, "domain.social", [other["id"]], "t")["results"][0]["status"] == "error"


def test_gravatar_offline_then_pivot_to_profiles(ctx, gid):
    e, _ = ctx.graphs.add_node(gid, "email", "Admin@Demo-Corp.example")
    r = engine.run_on_nodes(ctx.graphs, ctx, gid, "email.gravatar", [e["id"]], "t")
    got = {(n["type"], n["value"]) for n in r["added_nodes"]}
    assert ("person", "Demo Admin") in got and ("username", "demo_user") in got and ("url", "https://demo-corp.example/") in got
    h = next(n for n in r["added_nodes"] if n["value"] == "demo_user")
    r2 = engine.run_on_nodes(ctx.graphs, ctx, gid, "username.profiles", [h["id"]], "t")      # pivot across modules
    assert r2["results"][0]["status"] == "ok" and any(n["type"] == "profile" for n in r2["added_nodes"])
    nobody, _ = ctx.graphs.add_node(gid, "email", "nobody@demo-corp.example")
    assert engine.run_on_nodes(ctx.graphs, ctx, gid, "email.gravatar", [nobody["id"]], "t")["results"][0]["status"] == "error"


def test_username_variants_marked_unverified(ctx, gid):
    u, _ = ctx.graphs.add_node(gid, "username", "john_doe.x")
    r = engine.run_on_nodes(ctx.graphs, ctx, gid, "username.variants", [u["id"]], "t")
    assert r["added_nodes"] and all(n["attrs"].get("status") == "unverified candidate" for n in r["added_nodes"])
    assert all(e["confidence"] <= 0.3 for e in r["added_edges"])


@pytest.mark.parametrize("value,country", [("+234 803 000 0000", "Nigeria"), ("+44 20 7946 0000", "United Kingdom"),
                                           ("+1 202 555 0100", "United States / Canada (NANP)"), ("+254712345678", "Kenya")])
def test_phone_region(ctx, gid, value, country):
    p, _ = ctx.graphs.add_node(gid, "phone", value)
    r = engine.run_on_nodes(ctx.graphs, ctx, gid, "phone.region", [p["id"]], "t")
    assert r["added_nodes"][0]["value"] == country
    assert r["results"][0]["warnings"], "must warn that this is not the holder's location"


@pytest.mark.parametrize("bad", ["12", "abc", "+", "+" + "9" * 20, "++234803"])
def test_phone_validation_rejects(bad):
    with pytest.raises(GraphError):
        validate_value("phone", bad)


def test_phone_merge_normalised(ctx, gid):
    a, c1 = ctx.graphs.add_node(gid, "phone", "+234 803 000 0000")
    b, c2 = ctx.graphs.add_node(gid, "phone", "+2348030000000")
    assert c1 and not c2 and a["id"] == b["id"]


def test_no_transform_logs_in_or_reads_private_data():
    from cclass_suite.graphlab.transforms import TRANSFORMS
    text = " ".join((t.name + " " + t.description).lower() for t in TRANSFORMS.values())
    for forbidden in ("password", "login to", "credential", "private message", "scrape followers", "owner lookup of phone"):
        assert forbidden not in text


# ------------------------------------------------------------------ SSRF guard
def _resolve(mapping):
    def fake(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], port))]
    return fake


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost/", "http://10.0.0.5/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/",
    "http://192.168.1.1:80/", "https://example.org:8443/", "file:///etc/passwd", "ftp://example.org/", "http:///x",
])
def test_unsafe_urls_refused(url, monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolve({"localhost": "127.0.0.1", "example.org": "93.184.216.34"}))
    with pytest.raises(netsafe.UnsafeURL):
        netsafe.check_public_url(url)


def test_dns_pointing_at_private_range_refused(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolve({"evil.example": "10.1.2.3"}))
    with pytest.raises(netsafe.UnsafeURL):
        netsafe.check_public_url("https://evil.example/")


class _Resp:
    def __init__(self, status=200, headers=None, body=b"<html></html>"):
        self.status_code, self.headers, self._body, self.encoding = status, headers or {"Content-Type": "text/html"}, body, "utf-8"

    def __enter__(self): return self
    def __exit__(self, *a): return False
    def iter_content(self, n): yield self._body


def test_redirect_to_internal_address_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolve({"good.example": "93.184.216.34", "metadata.internal": "169.254.169.254"}))
    calls = []

    def fake_get(url, **kw):
        calls.append((url, kw.get("allow_redirects")))
        return _Resp(302, {"Location": "http://metadata.internal/latest"}) if "good.example" in url else _Resp()
    monkeypatch.setattr(netsafe.requests, "get", fake_get)
    html, final, err = netsafe.fetch_public_html("https://good.example/", "ua")
    assert html is None and "non-public" in err and len(calls) == 1 and calls[0][1] is False


def test_fetch_happy_path_and_content_type(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _resolve({"good.example": "93.184.216.34"}))
    monkeypatch.setattr(netsafe.requests, "get", lambda url, **kw: _Resp(body=b'<a href="https://x.com/acme">a</a>'))
    html, _, err = netsafe.fetch_public_html("https://good.example/", "ua")
    assert err is None and "x.com/acme" in html
    monkeypatch.setattr(netsafe.requests, "get", lambda url, **kw: _Resp(headers={"Content-Type": "application/octet-stream"}))
    assert netsafe.fetch_public_html("https://good.example/", "ua")[2] == "not an HTML page"
    monkeypatch.setattr(netsafe.requests, "get", lambda url, **kw: _Resp(302, {"Location": "https://good.example/"}))
    assert netsafe.fetch_public_html("https://good.example/", "ua")[2] == "too many redirects"


def test_online_domain_social_uses_guarded_fetch(ctx, gid, monkeypatch):
    ctx.settings.offline_mode = False
    seen = []
    monkeypatch.setattr(netsafe, "fetch_public_html", lambda url, ua, t=8: (seen.append(url) or ('<a href="https://github.com/acme">g</a>', url, None)))
    d, _ = ctx.graphs.add_node(gid, "domain", "acme.example")
    r = engine.run_on_nodes(ctx.graphs, ctx, gid, "domain.social", [d["id"]], "t")
    assert seen == ["https://acme.example/"] and {n["value"] for n in r["added_nodes"]} >= {"acme", "https://github.com/acme"}
    monkeypatch.setattr(netsafe, "fetch_public_html", lambda url, ua, t=8: (None, url, "non-public"))
    r = engine.run_on_nodes(ctx.graphs, ctx, gid, "domain.social", [d["id"]], "t")
    assert r["results"][0]["status"] == "error" and "non-public" in r["results"][0]["message"]
