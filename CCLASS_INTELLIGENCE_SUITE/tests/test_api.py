"""Web API tests.  They need FastAPI + httpx (installed by install.sh); skipped otherwise."""
import io

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from cclass_suite.web.app import create_app  # noqa: E402


@pytest.fixture()
def client(ctx):
    ctx.settings.scheduler_enabled = False
    ctx.settings.auth_enabled = False      # authentication has its own suite: test_auth_web.py
    with TestClient(create_app(ctx), headers={"X-Requested-With": "cclass"}) as c:
        yield c


def test_health_and_index(client):
    r = client.get("/api/health")
    assert r.json()["status"] == "ok"
    assert r.headers["referrer-policy"] != "no-referrer"  # OSM tile servers reject requests without a Referer
    html = client.get("/").text
    assert "CCLASS" in html and "cclass.js" in html


def test_host_header_and_origin_guard(client):
    assert client.get("/api/health", headers={"host": "evil.example"}).status_code == 403
    assert client.post("/api/investigations", json={"name": "x"}, headers={"origin": "http://evil.example"}).status_code == 403


def test_full_investigation_workflow(client):
    assert client.post("/api/demo").status_code == 200
    inv = client.get("/api/investigations").json()[0]
    iid = inv["id"]
    assert client.get(f"/api/investigations/{iid}/findings?severity=medium").status_code == 200
    assert client.get(f"/api/investigations/{iid}/graph").json()["nodes"]
    assert client.get(f"/api/map?investigation_id={iid}").json()
    assert client.get(f"/api/investigations/{iid}/timeline").json()
    for fmt in ("html", "csv", "json", "txt", "pdf"):
        r = client.post("/api/reports", json={"investigation_id": iid, "format": fmt})
        assert r.status_code == 201, r.text
        d = client.get(f"/api/reports/{r.json()['id']}/download")
        assert d.status_code == 200 and len(d.content) > 100
    assert client.post("/api/reports", json={"investigation_id": iid, "format": "exe"}).status_code == 400
    assert client.get("/api/search?q=demo-corp").json()["total"] > 0
    ov = client.get("/api/overview").json()
    assert ov["totals"]["findings"] > 0


def test_validation_and_errors(client):
    assert client.post("/api/investigations", json={"name": ""}).status_code == 422
    assert client.post("/api/investigations", json={"name": "x", "priority": "urgent"}).status_code == 422
    assert client.get("/api/investigations/999").status_code == 404
    assert client.post("/api/investigate", json={"query": "x" * 600}).status_code == 422
    assert client.post("/api/modules/NOPE/run", json={"query": "x"}).status_code == 404
    assert client.post("/api/modules/METADATA/run", json={"query": "/etc/passwd"}).status_code == 400  # no server-side file paths
    assert client.put("/api/settings", json={"port": 0}).status_code == 400
    assert client.put("/api/settings", json={"nvd_api_key": "k"}).status_code == 400  # secrets are not settable via the API
    assert client.get("/api/evidence/12345/download").status_code == 404


def test_network_module_requires_authorisation(client):
    r = client.post("/api/modules/NETWORKINTEL/run", json={"query": "127.0.0.1"})
    assert r.status_code == 400
    r = client.post("/api/modules/NETWORKINTEL/run", json={"query": "8.8.8.8", "authorized": True})
    assert r.status_code == 200 and r.json()["result"]["ok"] is False


def test_evidence_upload(client):
    iid = client.post("/api/investigations", json={"name": "ev"}).json()["id"]
    files = {"file": ("note.txt", io.BytesIO(b"evidence body"), "text/plain")}
    r = client.post(f"/api/investigations/{iid}/evidence", files=files, data={"notes": "n"})
    assert r.status_code == 201 and not r.json()["duplicate"]
    r2 = client.post(f"/api/investigations/{iid}/evidence", files={"file": ("again.txt", io.BytesIO(b"evidence body"))})
    assert r2.json()["duplicate"] is True
    ev = client.get(f"/api/investigations/{iid}/evidence").json()
    assert len(ev) == 1 and client.get(f"/api/evidence/{ev[0]['id']}/download").content == b"evidence body"
    assert client.post(f"/api/investigations/{iid}/evidence", files={"file": ("e", io.BytesIO(b""))}).status_code == 400


def test_upload_size_limit(client, ctx):
    ctx.settings.max_upload_mb = 1
    iid = client.post("/api/investigations", json={"name": "big"}).json()["id"]
    r = client.post(f"/api/investigations/{iid}/evidence", files={"file": ("b.bin", io.BytesIO(b"0" * (1024 * 1024 + 5)))})
    assert r.status_code == 413


def test_watchlists_alerts_tasks(client):
    client.post("/api/feeds/refresh?sample=true")
    assert client.post("/api/watchlists", json={"kind": "keyword", "value": "citrix"}).json()["alerts_matched"] >= 1
    assert client.get("/api/alerts?matched_only=true").json()
    assert client.post("/api/watchlists", json={"kind": "bogus", "value": "xx"}).status_code == 422
    tid = client.post("/api/tasks", json={"name": "t", "task_type": "feed_refresh", "interval_minutes": 10}).json()["id"]
    assert client.post(f"/api/tasks/{tid}/run").json()["status"] in ("ok", "partial", "error")
    assert client.delete(f"/api/tasks/{tid}").json()["deleted"]


def test_authentication_is_on_by_default_and_refuses_unsafe_exposure(ctx, monkeypatch):
    ctx.settings.scheduler_enabled = False
    with TestClient(create_app(ctx), headers={"X-Requested-With": "cclass"}) as c:
        assert c.get("/api/health").status_code == 200           # public
        assert c.get("/api/overview").status_code == 401         # everything else needs a session
        assert c.get("/api/auth/status").json()["setup_required"] is True
        assert c.get("/").status_code == 200                     # SPA shell renders the login screen
    ctx.settings.auth_enabled = False
    ctx.settings.host = "0.0.0.0"
    monkeypatch.delenv("CCLASS_ALLOW_INSECURE", raising=False)
    with pytest.raises(RuntimeError, match="authentication disabled"):
        create_app(ctx)
