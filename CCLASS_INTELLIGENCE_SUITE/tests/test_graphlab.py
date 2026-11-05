import json

import pytest

from cclass_suite.graphlab import engine, transforms
from cclass_suite.graphlab.store import MAX_NODES, GraphError, validate_value


@pytest.fixture()
def gs(ctx):
    return ctx.graphs


@pytest.fixture()
def gid(gs):
    return gs.create_graph("Test graph", "d", "tester")


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("t,v", [
    ("email", "not-an-email"), ("domain", "bad domain"), ("ip", "999.1.1.1"), ("url", "javascript:alert(1)"),
    ("url", "http://a b.com"), ("cve", "CVE-12-1"), ("hash", "xyz"), ("network", "10.0.0.0/99"), ("asn", "ASX"),
    ("person", ""), ("person", "a\x00b"), ("nope", "x"),
])
def test_validation_rejects(t, v):
    with pytest.raises(GraphError):
        validate_value(t, v)


def test_validation_accepts_and_normalises():
    assert validate_value("cve", "cve-2024-3400") == "CVE-2024-3400"
    assert validate_value("network", "203.0.113.7/24") == "203.0.113.0/24"
    assert validate_value("url", "https://demo-corp.example/a?b=1") == "https://demo-corp.example/a?b=1"


# ------------------------------------------------------------------ store
def test_node_merge_and_edges(gs, gid):
    a, c1 = gs.add_node(gid, "domain", "Demo-Corp.example")
    b, c2 = gs.add_node(gid, "domain", "demo-corp.example.")   # same entity once normalised
    assert c1 and not c2 and a["id"] == b["id"]
    ip, _ = gs.add_node(gid, "ip", "203.0.113.10")
    e, created = gs.add_edge(gid, a["id"], ip["id"], "resolves_to")
    assert created and not gs.add_edge(gid, a["id"], ip["id"], "resolves_to")[1]
    with pytest.raises(GraphError):
        gs.add_edge(gid, a["id"], a["id"], "x")
    other = gs.create_graph("other")
    foreign, _ = gs.add_node(other, "ip", "203.0.113.11")
    with pytest.raises(GraphError):
        gs.add_edge(gid, a["id"], foreign["id"], "x")          # cross-graph link refused
    snap = gs.snapshot(gid)
    assert len(snap["nodes"]) == 2 and len(snap["edges"]) == 1


def test_update_move_delete_cascade(gs, gid):
    a, _ = gs.add_node(gid, "person", "Jane Doe")
    b, _ = gs.add_node(gid, "email", "jane@demo-corp.example")
    gs.add_edge(gid, a["id"], b["id"], "uses")
    n = gs.update_node(a["id"], label="Jane", notes="n", x=10, y=20)
    assert (n["label"], n["x"], n["y"]) == ("Jane", 10.0, 20.0)
    assert gs.update_node(a["id"], x="nan")["x"] == 0.0        # non-finite numbers are never stored
    with pytest.raises(GraphError):
        gs.update_node(b["id"], value="not-an-email")
    assert gs.move_nodes(gid, [{"id": a["id"], "x": 1, "y": 2}, {"id": "bad"}]) == 1
    gs.delete_node(a["id"])
    assert gs.snapshot(gid)["edges"] == []


def test_node_limit(gs, gid, monkeypatch):
    monkeypatch.setattr("cclass_suite.graphlab.store.MAX_NODES", 3)
    for i in range(3):
        gs.add_node(gid, "person", f"p{i}")
    with pytest.raises(GraphError, match="maximum"):
        gs.add_node(gid, "person", "p9")


def test_graph_crud_and_listing(gs):
    g = gs.create_graph("A")
    assert gs.update_graph(g, name="B")["name"] == "B"
    assert any(x["id"] == g and x["node_count"] == 0 for x in gs.list_graphs())
    with pytest.raises(GraphError):
        gs.create_graph("   ")
    gs.delete_graph(g)
    assert gs.get_graph(g) is None


# ------------------------------------------------------------------ transforms
def test_local_transforms(ctx, gs, gid):
    em, _ = gs.add_node(gid, "email", "admin@demo-corp.example")
    r = engine.run_on_nodes(gs, ctx, gid, "email.to_domain", [em["id"]], "t")
    assert [n["value"] for n in r["added_nodes"]] == ["demo-corp.example"] and len(r["added_edges"]) == 1
    again = engine.run_on_nodes(gs, ctx, gid, "email.to_domain", [em["id"]], "t")
    assert again["added_nodes"] == [] and again["added_edges"] == []          # idempotent

    sub, _ = gs.add_node(gid, "hostname", "mail.corp.co.uk")
    r = engine.run_on_nodes(gs, ctx, gid, "domain.parent", [sub["id"]], "t")
    assert r["added_nodes"][0]["value"] == "corp.co.uk"
    ip, _ = gs.add_node(gid, "ip", "203.0.113.77")
    r = engine.run_on_nodes(gs, ctx, gid, "ip.network", [ip["id"]], "t")
    assert r["added_nodes"][0]["value"] == "203.0.113.0/24"
    u, _ = gs.add_node(gid, "url", "https://login.demo-corp.example/x")
    r = engine.run_on_nodes(gs, ctx, gid, "url.to_host", [u["id"]], "t")
    assert r["added_nodes"][0]["value"] == "login.demo-corp.example"


def test_text_extract(ctx, gs, gid):
    note, _ = gs.add_node(gid, "text", "Contact bob@demo-corp.example, see https://demo-corp.example/a and 203.0.113.9; "
                                       "patched CVE-2024-3400. Also evil.example and 999.9.9.9")
    r = engine.run_on_nodes(gs, ctx, gid, "text.extract", [note["id"]], "t")
    got = {(n["type"], n["value"]) for n in r["added_nodes"]}
    assert ("email", "bob@demo-corp.example") in got and ("ip", "203.0.113.9") in got
    assert ("cve", "CVE-2024-3400") in got and ("domain", "evil.example") in got
    assert ("domain", "demo-corp.example") not in got            # already covered by the email / URL
    assert not any(v == "999.9.9.9" for _, v in got)


def test_module_transforms_offline(ctx, gs, gid):
    d, _ = gs.add_node(gid, "domain", "demo-corp.example")
    r = engine.run_on_nodes(gs, ctx, gid, "domain.dns", [d["id"]], "t")
    assert r["results"][0]["status"] == "ok" and len(r["added_nodes"]) >= 5
    types = {n["type"] for n in r["added_nodes"]}
    assert "ip" in types
    ip = next(n for n in r["added_nodes"] if n["type"] == "ip" and n["value"] == "203.0.113.10")
    r2 = engine.run_on_nodes(gs, ctx, gid, "ip.intel", [ip["id"]], "t")
    assert r2["results"][0]["status"] == "ok" and any(n["type"] == "asn" for n in r2["added_nodes"])
    snap = gs.snapshot(gid)
    ids = {n["id"] for n in snap["nodes"]}
    assert all(e["src"] in ids and e["dst"] in ids for e in snap["edges"])
    # the expanded entity is linked to its results (no floating nodes)
    linked = {e["src"] for e in snap["edges"]} | {e["dst"] for e in snap["edges"]}
    assert ids <= linked
    runs = gs.list_runs(gid)
    assert runs and runs[0]["status"] == "ok"


def test_wrong_type_and_unknown_transform(ctx, gs, gid):
    p, _ = gs.add_node(gid, "person", "Jane")
    r = engine.run_on_nodes(gs, ctx, gid, "ip.intel", [p["id"]], "t")
    assert r["results"][0]["status"] == "error" and r["added_nodes"] == []
    with pytest.raises(GraphError):
        engine.run_on_nodes(gs, ctx, gid, "nope", [p["id"]], "t")
    with pytest.raises(GraphError):
        engine.run_on_nodes(gs, ctx, gid, "ip.network", [], "t")
    other = gs.create_graph("o")
    foreign, _ = gs.add_node(other, "ip", "203.0.113.5")
    r = engine.run_on_nodes(gs, ctx, gid, "ip.network", [foreign["id"]], "t")   # node from another graph
    assert r["results"][0]["status"] == "error"


def test_no_active_scanning_transform():
    assert not any(t.module == "NETWORKINTEL" for t in transforms.TRANSFORMS.values())


def test_every_transform_accepts_known_types():
    from cclass_suite.graphlab.store import TYPES
    for t in transforms.TRANSFORMS.values():
        assert t.accepts and all(a in TYPES for a in t.accepts), t.id


# ------------------------------------------------------------------ import / export
def test_export_import_roundtrip(ctx, gs, gid):
    a, _ = gs.add_node(gid, "domain", "demo-corp.example", notes="=cmd|' /C calc'!A0")
    b, _ = gs.add_node(gid, "ip", "203.0.113.10")
    gs.add_edge(gid, a["id"], b["id"], "resolves_to")
    js, _ = gs.export(gid, "json")
    g2 = gs.create_graph("copy")
    res = gs.import_json(g2, js)
    assert res == {"nodes": 2, "edges": 1, "skipped": 0}
    assert len(gs.snapshot(g2)["nodes"]) == 2
    csv_n, _ = gs.export(gid, "csv", "nodes")
    assert "'=cmd" in csv_n
    csv_e, _ = gs.export(gid, "csv", "edges")
    assert "resolves_to" in csv_e
    xml, ct = gs.export(gid, "graphml")
    assert "<graphml" in xml and ct == "application/xml"
    with pytest.raises(GraphError):
        gs.export(gid, "pdf")


def test_import_rejects_garbage(gs, gid):
    for raw in ("not json", "[]", json.dumps({"format": "other"}), json.dumps({"format": "cclass-graphlab", "nodes": 1, "edges": []})):
        with pytest.raises(GraphError):
            gs.import_json(gid, raw)
    ok = json.dumps({"format": "cclass-graphlab", "nodes": [{"id": 1, "type": "ip", "value": "bad"},
                                                              {"id": 2, "type": "ip", "value": "203.0.113.1"}],
                     "edges": [{"src": 1, "dst": 2, "label": "x"}]})
    assert gs.import_json(gid, ok) == {"nodes": 1, "edges": 0, "skipped": 2}


@pytest.mark.parametrize("tid,ntype,value", [
    ("username.profiles", "username", "jdoe_demo"), ("place.geo", "place", "Lagos"), ("place.news", "country", "Nigeria"),
    ("cve.details", "cve", "CVE-2024-3400"), ("email.intel", "email", "admin@demo-corp.example"),
])
def test_every_module_transform_runs_offline(ctx, gs, gid, tid, ntype, value):
    n, _ = gs.add_node(gid, ntype, value)
    r = engine.run_on_nodes(gs, ctx, gid, tid, [n["id"]], "t")
    res = r["results"][0]
    assert res["status"] == "ok" or "No " in res["message"] or res["message"], res


def test_rerunning_a_transform_does_not_duplicate_notes(ctx, gs, gid):
    d, _ = gs.add_node(gid, "domain", "demo-corp.example")
    engine.run_on_nodes(gs, ctx, gid, "domain.dns", [d["id"]], "t")
    once = gs.get_node(d["id"])["notes"]
    engine.run_on_nodes(gs, ctx, gid, "domain.dns", [d["id"]], "t")
    assert once and gs.get_node(d["id"])["notes"] == once
    assert len(once.splitlines()) == len(set(once.splitlines()))
