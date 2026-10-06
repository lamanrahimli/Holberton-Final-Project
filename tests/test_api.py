"""HTTP API tests against a fully wired server object (no sockets: FastAPI TestClient)."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from kharibulbul.common.config import deep_merge, load_server_config
from kharibulbul.server.main import KharibulbulServer
from kharibulbul.simulate.scenarios import generate
from tests.conftest import ROOT

RULE_YAML = """
id: T-API-1
title: api test rule
severity: high
mitre: [{technique: T1110}]
detection:
  selection:
    event.action: ssh-login-failed
  condition: selection
threshold: {count: 2, window: 5m, group_by: [source.ip]}
"""


@pytest.fixture
def server(tmp_path):
    cfg = load_server_config(os.path.join(ROOT, "config", "server.yml"))
    cfg = deep_merge(cfg, {"data_dir": str(tmp_path), "store": {"sqlite": {"path": str(tmp_path / "api.db")}},
                          "custom_dir": str(tmp_path / "custom"),
                          "alerts": {"notify": {"console": {"enabled": False}, "file": {"enabled": True, "path": str(tmp_path / "alerts.jsonl")}}},
                          "api": {"token": "secret-token"}})
    srv = KharibulbulServer(cfg)
    yield srv
    srv.notifier.close()
    srv.store.close()


@pytest.fixture
def client(server):
    return TestClient(server.app)


AUTH = {"Authorization": "Bearer secret-token"}


def test_health_and_auth(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/api/stats").status_code == 401
    assert client.get("/api/stats", headers={"X-API-Key": "secret-token"}).status_code == 200
    assert client.get("/").status_code in (200, 307)
    assert client.get("/ui/").status_code == 200
    assert "Kharibulbul" in client.get("/ui/").text


def test_dashboard_is_never_served_stale(client):
    """A browser must not keep an old app.js after the server was updated (it used to, for hours)."""
    build = client.get("/api/health").json()["ui"]
    assert build.startswith("1.") and "-" in build
    redirect = client.get("/", follow_redirects=False)
    assert redirect.status_code == 307 and redirect.headers["location"] == f"/ui/?v={build}"
    for url in ("/ui/", "/ui/index.html"):
        page = client.get(url)
        assert "no-store" in page.headers["cache-control"]
        for asset in ("app.js", "style.css", "favicon.png", "logo.png"):
            assert f'"{asset}?v={build}"' in page.text
    for asset in ("app.js", "style.css", "logo.png"):
        r = client.get(f"/ui/{asset}?v={build}")
        assert r.status_code == 200 and r.headers["cache-control"] == "no-cache"
    assert "Add agent" in client.get("/ui/app.js").text


def test_ingest_search_alerts_flow(client, server):
    envelopes = generate(["ssh-brute-force", "windows-brute-force"], seed=3)
    r = client.post("/api/ingest", json={"events": envelopes}, headers=AUTH)
    assert r.status_code == 200 and r.json()["stored"] == len(envelopes)
    server.store.flush()
    r = client.get("/api/events", params={"q": "event.action:ssh-login-failed", "limit": 5}, headers=AUTH)
    body = r.json()
    assert body["total"] >= 10 and len(body["hits"]) == 5
    first = body["hits"][0]
    assert client.get(f"/api/events/{first['event.id']}", headers=AUTH).json()["event.id"] == first["event.id"]
    assert client.get("/api/events", params={"q": "(bad"}, headers=AUTH).status_code == 400
    hist = client.get("/api/events/histogram", params={"from": "now-1h"}, headers=AUTH).json()
    assert sum(b["count"] for b in hist["buckets"]) == len(envelopes)
    terms = client.get("/api/events/terms", params={"field": "event.dataset"}, headers=AUTH).json()["buckets"]
    assert {t["key"] for t in terms} >= {"linux.auth", "windows.security"}

    alerts = client.get("/api/alerts", headers=AUTH).json()["hits"]
    ids = {a["rule.id"] for a in alerts}
    assert {"KB-LNX-001", "KB-COR-002", "KB-WIN-001", "KB-COR-001"} <= ids
    alert = alerts[0]
    assert alert["status"] == "new" and alert["sample_events"]
    r = client.patch(f"/api/alerts/{alert['id']}", json={"status": "acknowledged", "assignee": "aysel", "notes": "checking"}, headers=AUTH)
    assert r.json()["status"] == "acknowledged" and r.json()["assignee"] == "aysel"
    assert client.patch(f"/api/alerts/{alert['id']}", json={"status": "bogus"}, headers=AUTH).status_code == 400
    summary = client.get("/api/alerts/summary", headers=AUTH).json()
    assert summary["total"] == len(alerts) and summary["by_status"]["acknowledged"] == 1

    overview = client.get("/api/dashboard/overview", headers=AUTH).json()
    assert overview["events_total"] == len(envelopes)
    assert overview["alerts"]["open"] >= 4
    assert overview["auth_failures"] >= 20
    assert any(t["key"] == "Lab-Workstations" or t["key"] for t in overview["top_countries"])

    assert os.path.exists(server.notifier._file_path)


def test_rules_endpoints(client, server):
    rules = client.get("/api/rules", headers=AUTH).json()
    assert rules["count"] >= 60
    rid = rules["rules"][0]["id"]
    detail = client.get(f"/api/rules/{rid}", headers=AUTH).json()
    assert detail["id"] == rid and "yaml" in detail
    assert client.post(f"/api/rules/{rid}/disable", headers=AUTH).json()["enabled"] is False
    assert client.post(f"/api/rules/{rid}/enable", headers=AUTH).json()["enabled"] is True
    assert client.post("/api/rules/reload", headers=AUTH).json()["loaded"] >= 60
    assert client.get("/api/rules/NOPE", headers=AUTH).status_code == 404

    lines = ["Sep 27 10:00:01 srv sshd[1]: Failed password for root from 10.10.99.10 port 1 ssh2",
             "Sep 27 10:00:02 srv sshd[1]: Failed password for root from 10.10.99.10 port 2 ssh2"]
    r = client.post("/api/rules/test", json={"rule": RULE_YAML, "events": lines}, headers=AUTH).json()
    assert r["valid"] and len(r["alerts"]) == 1 and r["alerts"][0]["count"] == 2
    r = client.post("/api/rules/test", json={"rule": "id: X\ntitle: y\n", "events": []}, headers=AUTH).json()
    assert r["valid"] is False and r["errors"]

    pbs = client.get("/api/playbooks", headers=AUTH).json()["playbooks"]
    assert pbs and pbs[0].endswith(".md")
    assert client.get(f"/api/playbooks/{pbs[0]}", headers=AUTH).status_code == 200
    assert client.get("/api/playbooks/../secret.md", headers=AUTH).status_code == 404
    agents = client.get("/api/agents", headers=AUTH).json()["agents"]
    assert isinstance(agents, list)
    schema = client.get("/api/schema", headers=AUTH).json()
    assert "source.ip" in schema["fields"]
