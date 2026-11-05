"""Graph Lab HTTP API behind the real auth middleware (plain Starlette, no FastAPI needed)."""
import json

import pytest

pytest.importorskip("httpx")
from starlette.applications import Starlette  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from cclass_suite.graphlab.routes import build_graphlab_routes  # noqa: E402
from cclass_suite.web.auth import AuthMiddleware, build_auth_routes  # noqa: E402

PW = "Tr1cky-Passphrase!"
XHR = {"X-Requested-With": "cclass"}


@pytest.fixture()
def ctx(ctx):
    ctx.settings.auth_enabled = True
    ctx.accounts.create_user("viewer1", PW, "viewer")
    ctx.accounts.create_user("analyst1", PW, "analyst")
    return ctx


@pytest.fixture()
def app(ctx):
    a = Starlette(routes=build_auth_routes(ctx) + build_graphlab_routes(ctx))
    a.add_middleware(AuthMiddleware, ctx=ctx)
    return a


def login(app, user):
    c = TestClient(app, base_url="http://localhost", headers=XHR, client=("127.0.0.1", 5000))
    r = c.post("/api/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return c


def test_requires_login_and_csrf(app):
    c = TestClient(app, base_url="http://localhost", headers=XHR)
    assert c.get("/api/graphlab/graphs").status_code == 401
    a = login(app, "analyst1")
    bare = TestClient(app, base_url="http://localhost", cookies=a.cookies)
    assert bare.post("/api/graphlab/graphs", json={"name": "x"}).status_code == 403   # no CSRF header


def test_viewer_is_read_only(app):
    a, v = login(app, "analyst1"), login(app, "viewer1")
    gid = a.post("/api/graphlab/graphs", json={"name": "G"}).json()["id"]
    assert v.get("/api/graphlab/graphs").status_code == 200
    assert v.get(f"/api/graphlab/graphs/{gid}").status_code == 200
    assert v.get("/api/graphlab/meta").status_code == 200
    for method, path in [("post", "/api/graphlab/graphs"), ("post", f"/api/graphlab/graphs/{gid}/nodes"),
                         ("post", f"/api/graphlab/graphs/{gid}/transform"), ("delete", f"/api/graphlab/graphs/{gid}"),
                         ("post", f"/api/graphlab/graphs/{gid}/import")]:
        assert v.request(method.upper(), path, json={}).status_code == 403, (method, path)


def test_full_analyst_flow(app, ctx):
    c = login(app, "analyst1")
    meta = c.get("/api/graphlab/meta").json()
    assert "domain" in meta["types"] and any(t["id"] == "domain.dns" for t in meta["transforms"])
    gid = c.post("/api/graphlab/graphs", json={"name": "Case graph"}).json()["id"]

    r = c.post(f"/api/graphlab/graphs/{gid}/nodes", json={"type": "auto", "value": "demo-corp.example", "x": 5, "y": 6})
    assert r.status_code == 201 and r.json()["node"]["type"] == "domain"
    nid = r.json()["node"]["id"]
    assert c.post(f"/api/graphlab/graphs/{gid}/nodes", json={"type": "domain", "value": "DEMO-corp.example"}).status_code == 200
    bad = c.post(f"/api/graphlab/graphs/{gid}/nodes", json={"type": "ip", "value": "nope"})
    assert bad.status_code == 400 and "valid IP" in bad.json()["detail"]

    t = c.post(f"/api/graphlab/graphs/{gid}/transform", json={"transform": "domain.dns", "node_ids": [nid]})
    assert t.status_code == 200, t.text
    body = t.json()
    assert len(body["added_nodes"]) >= 5 and body["results"][0]["status"] == "ok"

    snap = c.get(f"/api/graphlab/graphs/{gid}").json()
    assert len(snap["nodes"]) == len(body["added_nodes"]) + 1 and snap["edges"]

    ip = next(n for n in snap["nodes"] if n["type"] == "ip")
    assert c.patch(f"/api/graphlab/nodes/{ip['id']}", json={"label": "Web server", "notes": "checked"}).json()["label"] == "Web server"
    e = c.post(f"/api/graphlab/graphs/{gid}/edges", json={"src": nid, "dst": ip["id"], "label": "analyst_link"})
    assert e.status_code == 201
    assert c.patch(f"/api/graphlab/edges/{e.json()['edge']['id']}", json={"label": "owns"}).json()["label"] == "owns"
    assert c.post(f"/api/graphlab/graphs/{gid}/positions", json={"nodes": [{"id": nid, "x": 1, "y": 2}]}).json() == {"saved": 1}
    assert c.get(f"/api/graphlab/graphs/{gid}/runs").json()[0]["transform"] == "domain.dns"

    exp = c.get(f"/api/graphlab/graphs/{gid}/export?format=json")
    assert exp.status_code == 200 and "attachment" in exp.headers["content-disposition"]
    g2 = c.post("/api/graphlab/graphs", json={"name": "Imported"}).json()["id"]
    res = c.post(f"/api/graphlab/graphs/{g2}/import", content=exp.content)
    assert res.json()["nodes"] == len(snap["nodes"])
    assert c.get(f"/api/graphlab/graphs/{gid}/export?format=csv&part=edges").status_code == 200
    assert c.get(f"/api/graphlab/graphs/{gid}/export?format=bogus").status_code == 400

    assert c.delete(f"/api/graphlab/nodes/{ip['id']}").status_code == 200
    assert c.delete(f"/api/graphlab/graphs/{g2}").status_code == 200
    assert c.get(f"/api/graphlab/graphs/{g2}").status_code == 404

    # every state change is attributed in the tamper-evident audit log, and the chain stays valid
    actions = {r["action"] for r in ctx.audit.list(limit=200, actor="analyst1")}
    assert "graphlab.transform" in actions and "api.post" in actions
    assert ctx.audit.verify()["ok"]


def test_malformed_requests(app):
    c = login(app, "analyst1")
    gid = c.post("/api/graphlab/graphs", json={"name": "G"}).json()["id"]
    assert c.post("/api/graphlab/graphs", content=b"{not json").status_code == 400
    assert c.post("/api/graphlab/graphs", content=b"[1]").status_code == 400
    assert c.post(f"/api/graphlab/graphs/{gid}/transform", json={"transform": "domain.dns", "node_ids": "x"}).status_code == 400
    assert c.post(f"/api/graphlab/graphs/{gid}/transform", json={"transform": "nope", "node_ids": [1]}).status_code == 400
    assert c.post(f"/api/graphlab/graphs/{gid}/edges", json={"src": "a", "dst": 2}).status_code == 400
    assert c.get("/api/graphlab/graphs/99999").status_code == 404
    assert c.post(f"/api/graphlab/graphs/{gid}/import", content=b"x" * (5 * 1024 * 1024 + 9000)).status_code == 400
    xss = c.post(f"/api/graphlab/graphs/{gid}/nodes", json={"type": "person", "value": "<img src=x onerror=alert(1)>"})
    assert xss.status_code == 201          # stored verbatim as data; the UI escapes it on output


def test_auto_detect_phone_and_social_profile(app):
    c = login(app, "analyst1")
    gid = c.post("/api/graphlab/graphs", json={"name": "G"}).json()["id"]
    for value, expected in [("+234 803 000 0000", "phone"), ("https://twitter.com/jdoe", "profile"),
                            ("https://example.org/page", "url"), ("a@b.example", "email"), ("203.0.113.9", "ip")]:
        r = c.post(f"/api/graphlab/graphs/{gid}/nodes", json={"type": "auto", "value": value})
        assert r.status_code == 201 and r.json()["node"]["type"] == expected, (value, r.text)
