"""Dashboard features: date search without a limit, alert escalation, agent enrolment + IPs, custom rules,
custom playbooks, GeoIP country table, ECS normalisation."""
from __future__ import annotations

import gzip
import json
import os

import pytest
from fastapi.testclient import TestClient

from kharibulbul.common import ecs
from kharibulbul.common.config import SERVER_DEFAULTS, deep_merge, load_server_config
from kharibulbul.common.util import local_ips
from kharibulbul.detect.matchers import check_selection
from kharibulbul.pipeline.countries import COUNTRIES, continent, country_name
from kharibulbul.pipeline.geoip import CountryDB, GeoIP
from kharibulbul.server.api import _interval_for
from kharibulbul.server.main import KharibulbulServer
from kharibulbul.simulate.scenarios import SCENARIOS, generate
from tests.conftest import ROOT

AUTH = {"Authorization": "Bearer secret-token"}
SSH_FAIL = "Sep 27 10:00:0{i} srv sshd[1]: Failed password for root from 10.10.99.10 port {i} ssh2"

CUSTOM_RULE = """
id: KB-CUS-001
title: Custom - failed SSH burst
description: "Test rule written from the dashboard."
severity: low
tags: [custom]
mitre: [{technique: T1110, tactic: credential-access}]
logsource: {dataset: linux.auth}
detection:
  selection:
    event.action: ssh-login-failed
    source.ip|cidr: 10.10.99.0/24
  condition: selection
threshold: {count: 2, window: 5m, group_by: [source.ip]}
playbook: playbooks/PB-001-brute-force.md
"""


@pytest.fixture
def server(tmp_path):
    cfg = load_server_config(os.path.join(ROOT, "config", "server.yml"))
    cfg = deep_merge(cfg, {"data_dir": str(tmp_path), "store": {"sqlite": {"path": str(tmp_path / "f.db")}},
                          "custom_dir": str(tmp_path / "custom"),
                          "alerts": {"notify": {"console": {"enabled": False}, "file": {"enabled": True, "path": str(tmp_path / "alerts.jsonl")}}},
                          "api": {"token": "secret-token"}})
    srv = KharibulbulServer(cfg)
    yield srv
    srv.notifier.close()
    srv.store.close()


@pytest.fixture
def client(server):
    return TestClient(server.app, headers=AUTH)


def _line(raw: str, dataset: str = "linux.auth") -> dict:
    return {"raw": raw, "dataset": dataset}


def _json_event(ts: str, action: str, **extra) -> dict:
    return {"raw": json.dumps({"@timestamp": ts, "event.action": action, "message": action, "host.name": "h1", **extra}), "dataset": "json"}


# --------------------------------------------------------------------------- #
# 1. no date limit, search by date
# --------------------------------------------------------------------------- #

def test_events_can_be_searched_by_date_without_a_limit(client, server):
    assert SERVER_DEFAULTS["store"]["retention_days"] == 0 and server.cfg["store"]["retention_days"] == 0
    old = [_json_event("2024-03-10T08:00:00Z", "two-years-ago"), _json_event("2025-06-01T12:30:00Z", "last-year")]
    recent = generate(["ssh-brute-force"], seed=3)
    assert client.post("/api/ingest", json={"events": old + recent}).json()["stored"] == len(old) + len(recent)
    server.store.flush()

    def total(**params):
        r = client.get("/api/events", params=params)
        assert r.status_code == 200, r.text
        return r.json()["total"]

    assert total(**{"from": "now-30d"}) == len(recent)                       # the old 30-day view
    assert total(**{"from": "all"}) == len(old) + len(recent)                # everything that is stored
    assert total(**{"from": "2024-03-01", "to": "2024-03-31"}) == 1          # a month, by date
    assert total(**{"from": "2025-06-01T12:00:00Z", "to": "2025-06-01T13:00:00Z", "q": "event.action:last-year"}) == 1
    assert total(**{"from": "2024-01-01", "to": "2025-12-31"}) == 2
    assert client.get("/api/events", params={"from": "31/31/2024"}).status_code == 400

    hist = client.get("/api/events/histogram", params={"from": "all"}).json()
    assert sum(b["count"] for b in hist["buckets"]) == len(old) + len(recent)
    assert len(hist["buckets"]) <= 80 and hist["interval_seconds"] >= 86400   # years of data still fit one chart
    assert client.get("/api/events/histogram", params={"from": "2025-01-01", "to": "2024-01-01"}).status_code == 400
    over = client.get("/api/dashboard/overview", params={"from": "2024-03-01", "to": "2024-03-31"}).json()
    assert over["events_total"] == 1 and over["top_actions"][0]["key"] == "two-years-ago"
    assert client.get("/api/stats").json()["server"]["retention_days"] == 0


def test_interval_scales_from_minutes_to_years():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    for span in (timedelta(minutes=15), timedelta(days=1), timedelta(days=30), timedelta(days=365), timedelta(days=3650)):
        step = _interval_for(now - span, now)
        assert span.total_seconds() / step <= 61


# --------------------------------------------------------------------------- #
# 2. escalation
# --------------------------------------------------------------------------- #

def test_alert_escalation(client, server):
    client.post("/api/ingest", json={"events": generate(["ssh-brute-force"], seed=3)})
    alert = next(a for a in client.get("/api/alerts").json()["hits"] if a["rule.id"] == "KB-LNX-001")
    assert alert["severity"] == "high"

    r = client.post(f"/api/alerts/{alert['id']}/escalate", json={"reason": "root targeted from the attacker zone", "by": "aysel"})
    esc = r.json()
    assert r.status_code == 200 and esc["status"] == "escalated"
    assert esc["escalation"]["level"] == 1 and esc["escalation"]["to"] == "Tier 2 analyst" and esc["escalation"]["by"] == "aysel"
    assert esc["severity"] == "critical" and esc["escalation"]["severity_before"] == "high"
    assert esc["history"][-1]["status"] == "escalated" and esc["history"][-1]["reason"].startswith("root targeted")

    # second escalation through PATCH: next level, named recipient, severity untouched
    r = client.patch(f"/api/alerts/{alert['id']}", json={"status": "escalated", "to": "CSIRT lead", "raise_severity": False, "assignee": "tural"})
    assert r.json()["escalation"]["level"] == 2 and r.json()["escalation"]["to"] == "CSIRT lead" and r.json()["assignee"] == "tural"

    # an escalated alert is still open: new matching events update it instead of opening a second alert
    client.post("/api/ingest", json={"events": generate(["ssh-brute-force"], seed=3)})
    same_rule = [a for a in client.get("/api/alerts", params={"rule": "KB-LNX-001"}).json()["hits"]]
    assert len(same_rule) == 1 and same_rule[0]["status"] == "escalated" and same_rule[0]["count"] > alert["count"]
    assert client.get("/api/alerts", params={"status": "escalated"}).json()["count"] == 1
    assert client.get("/api/alerts/summary").json()["by_status"]["escalated"] == 1

    # closed alerts must be reopened first
    other = next(a for a in client.get("/api/alerts").json()["hits"] if a["id"] != alert["id"])
    client.patch(f"/api/alerts/{other['id']}", json={"status": "closed"})
    assert client.post(f"/api/alerts/{other['id']}/escalate", json={}).status_code == 400
    assert client.post("/api/alerts/nope/escalate", json={}).status_code == 404

    server.notifier.close()                                  # flush the notification queue
    lines = [json.loads(line) for line in open(server.notifier._file_path, encoding="utf-8")]
    assert sum(1 for a in lines if a["id"] == alert["id"] and a["status"] == "escalated") == 2
    assert server.notifier.sent["escalations"] == 2 and client.get("/api/stats").json()["alerts"]["escalated"] == 2


# --------------------------------------------------------------------------- #
# 3 + 4. add an agent from the dashboard, agent IP addresses
# --------------------------------------------------------------------------- #

def test_agent_enrolment_and_ip_addresses(client, server):
    info = client.get("/api/agents/enroll/info").json()
    assert info["port"] == 5044 and "windows" in info["profiles"] and "linux-journald" in info["profiles"]

    r = client.post("/api/agents/enroll", json={"name": "ws02", "profile": "windows-admin", "server_host": "10.10.10.5", "zone": "workstations"})
    assert r.status_code == 200, r.text
    body = r.json()
    agent_id = body["agent"]["id"]
    cfg = __import__("yaml").safe_load(body["config"])                      # the generated file is valid agent YAML
    assert cfg["agent"] == {"name": "ws02", "id": agent_id, "id_file": "data/agent-ws02/agent.id",
                            "labels": {"zone": "workstations", "os": "windows", "enrolled": "dashboard"}}
    assert cfg["server"]["host"] == "10.10.10.5" and cfg["server"]["port"] == 5044
    assert "Security" in cfg["inputs"][0]["channels"] and cfg["inputs"][1]["paths"][0].endswith("pfirewall.log")
    assert body["filename"] == "agent-ws02.yml" and len(body["steps"]) >= 6
    assert any("python -m kharibulbul agent -c config\\agent-ws02.yml" in c for s in body["steps"] for c in s["commands"])

    listed = {a["name"]: a for a in client.get("/api/agents").json()["agents"]}
    assert listed["ws02"]["status"] == "pending" and listed["ws02"]["ip_primary"] is None
    assert client.get("/api/dashboard/overview").json()["agents"] == {"total": 1, "online": 0, "silent": 0, "pending": 1}
    assert client.post("/api/agents/enroll", json={"name": "WS02", "profile": "windows", "server_host": "10.10.10.5"}).status_code == 409
    assert client.post("/api/agents/enroll", json={"name": "bad name!", "profile": "windows", "server_host": "10.10.10.5"}).status_code == 400
    assert client.post("/api/agents/enroll", json={"name": "x", "profile": "solaris", "server_host": "10.10.10.5"}).status_code == 400

    # the agent starts with the issued id: same row, now online, with its addresses
    server.handle_agent_hello({"id": agent_id, "name": "ws02", "host": "WS02", "os": "windows", "version": "1.0.0",
                               "ip": ["fe80::1c2:3", "10.10.20.7", "192.168.56.1"]}, "10.10.20.7")
    agents = client.get("/api/agents").json()["agents"]
    assert len(agents) == 1 and agents[0]["status"] == "online"
    assert agents[0]["ip"] == ["fe80::1c2:3", "10.10.20.7", "192.168.56.1"] and agents[0]["ip_primary"] == "10.10.20.7"
    assert agents[0]["remote"] == "10.10.20.7"

    linux = client.post("/api/agents/enroll", json={"name": "srv-web01", "profile": "linux-journald", "server_host": "siem.lab.local", "port": 5045}).json()
    lcfg = __import__("yaml").safe_load(linux["config"])
    assert lcfg["inputs"] == [{"type": "journald", "dataset": "linux.journald", "units": []}] and lcfg["server"]["port"] == 5045
    assert client.delete(f"/api/agents/{linux['agent']['id']}").json()["deleted"] is True
    assert client.delete(f"/api/agents/{linux['agent']['id']}").status_code == 404
    assert [a["name"] for a in client.get("/api/agents").json()["agents"]] == ["ws02"]


def test_agent_reads_the_issued_id_and_reports_routable_ips(tmp_path):
    from kharibulbul.agent.main import Agent
    from kharibulbul.common.config import AGENT_DEFAULTS
    cfg = deep_merge(AGENT_DEFAULTS, {"agent": {"name": "t", "id": "issued-by-server", "id_file": str(tmp_path / "agent.id")},
                                      "spool": {"dir": str(tmp_path / "spool")}})
    cfg["_base_dir"] = str(tmp_path)
    assert Agent(cfg).id == "issued-by-server"
    ips = local_ips("127.0.0.1")
    assert all(not ip.startswith("127.") and ip != "::1" for ip in ips)
    link_local = [i for i, ip in enumerate(ips) if ip.lower().startswith("fe80:") or ip.startswith("169.254.")]
    assert link_local == list(range(len(ips) - len(link_local), len(ips)))   # link-local addresses come last


# --------------------------------------------------------------------------- #
# 5. custom rules
# --------------------------------------------------------------------------- #

def test_custom_rules_written_from_the_dashboard(client, server, tmp_path):
    shipped = client.get("/api/rules").json()
    assert shipped["custom"] == 0
    tpl = client.get("/api/rules/template").json()
    assert tpl["id"] == "KB-CUS-001" and "id: KB-CUS-001" in tpl["yaml"]
    assert client.post("/api/rules/test", json={"rule": tpl["yaml"], "events": []}).json()["valid"] is True

    r = client.post("/api/rules", json={"rule": CUSTOM_RULE})
    assert r.status_code == 200, r.text
    assert r.json()["rule"]["custom"] is True and r.json()["loaded"] == shipped["count"] + 1
    path = tmp_path / "custom" / "rules" / "KB-CUS-001.yml"
    assert path.read_text(encoding="utf-8").strip() == CUSTOM_RULE.strip()
    detail = client.get("/api/rules/KB-CUS-001").json()
    assert detail["custom"] is True and detail["yaml"].strip() == CUSTOM_RULE.strip()
    assert client.get("/api/rules/template").json()["id"] == "KB-CUS-002"

    # it is live: the next matching events raise its alert
    assert client.post("/api/ingest", json={"events": [_line(SSH_FAIL.format(i=1)), _line(SSH_FAIL.format(i=2))]}).json()["stored"] == 2
    assert client.get("/api/alerts", params={"rule": "KB-CUS-001"}).json()["count"] == 1

    # rejected: duplicate id, a shipped id, broken YAML, unknown modifier, bad regex, missing playbook, two rules in one file
    assert client.post("/api/rules", json={"rule": CUSTOM_RULE}).status_code == 409
    assert client.post("/api/rules", json={"rule": CUSTOM_RULE.replace("KB-CUS-001", "KB-LNX-001")}).status_code == 409
    for broken, needle in ((CUSTOM_RULE.replace("KB-CUS-001", "KB-CUS-009").replace("detection:", "detection: [", 1), "yaml"),
                           (CUSTOM_RULE.replace("KB-CUS-001", "KB-CUS-009").replace("|cidr", "|cdir"), "unknown modifier"),
                           (CUSTOM_RULE.replace("KB-CUS-001", "KB-CUS-009").replace("event.action: ssh-login-failed", "message|re: '(unclosed'"), "bad regex"),
                           (CUSTOM_RULE.replace("KB-CUS-001", "KB-CUS-009").replace("PB-001-brute-force.md", "PB-404.md"), "does not exist"),
                           (CUSTOM_RULE.replace("KB-CUS-001", "../../evil"), "id:"),
                           (CUSTOM_RULE.replace("KB-CUS-001", "KB-CUS-009") + "---\n" + CUSTOM_RULE.replace("KB-CUS-001", "KB-CUS-010"), "one rule per file")):
        bad = client.post("/api/rules", json={"rule": broken})
        assert bad.status_code == 400 and needle in bad.json()["detail"], (needle, bad.text)
    assert sorted(os.listdir(tmp_path / "custom" / "rules")) == ["KB-CUS-001.yml"]

    # edit, then the shipped rules stay read-only
    edited = CUSTOM_RULE.replace("severity: low", "severity: critical")
    assert client.put("/api/rules/KB-CUS-001", json={"rule": edited}).json()["rule"]["severity"] == "critical"
    assert client.put("/api/rules/KB-CUS-001", json={"rule": edited.replace("KB-CUS-001", "KB-CUS-777")}).status_code == 400
    assert client.put("/api/rules/KB-LNX-001", json={"rule": edited.replace("KB-CUS-001", "KB-LNX-001")}).status_code == 403
    assert client.delete("/api/rules/KB-LNX-001").status_code == 403
    assert client.put("/api/rules/KB-NOPE-1", json={"rule": edited}).status_code == 404

    # a reload from disk keeps it; delete removes file and rule
    assert client.post("/api/rules/reload").json()["loaded"] == shipped["count"] + 1
    assert client.delete("/api/rules/KB-CUS-001").json()["loaded"] == shipped["count"]
    assert not path.exists() and client.get("/api/rules/KB-CUS-001").status_code == 404
    single = client.get("/api/rules/KB-LNX-001").json()["yaml"]             # a shipped rule is shown alone (clone source)
    assert single.count("\nid: ") + single.startswith("id: ") == 1


def test_selection_checks():
    assert check_selection({"process.name|endswith": "x.exe", "destination.port|gte": 1024, "source.ip|cidr": "10.0.0.0/8"}) == []
    assert "unknown modifier" in check_selection({"process.name|endwith": "x"})[0]
    assert "bad regex" in check_selection([{"message|re": "("}])[0]
    assert "not a CIDR" in check_selection({"source.ip|cidr": "10.0.0.0/99"})[0]
    assert "not a number" in check_selection({"destination.port|gt": "many"})[0]


# --------------------------------------------------------------------------- #
# 6. custom playbooks
# --------------------------------------------------------------------------- #

def test_custom_playbooks_written_from_the_dashboard(client, tmp_path):
    before = client.get("/api/playbooks").json()
    assert all(not i["custom"] for i in before["items"]) and "## 1. Triage" in before["template"]
    md = "# PB-C01 - Phishing\n\n```kql\nevent.action:process-created AND process.parent.name:outlook.exe\n```\n"

    r = client.post("/api/playbooks", json={"name": "PB-C01-phishing", "content": md})
    assert r.status_code == 200 and r.json() == {"name": "PB-C01-phishing.md", "custom": True}
    assert (tmp_path / "custom" / "playbooks" / "PB-C01-phishing.md").read_text(encoding="utf-8") == md
    after = client.get("/api/playbooks").json()
    assert after["playbooks"] == before["playbooks"] + ["PB-C01-phishing.md"] and after["items"][-1]["custom"] is True
    got = client.get("/api/playbooks/PB-C01-phishing.md")
    assert got.text == md and got.headers["x-kharibulbul-custom"] == "1"

    assert client.post("/api/playbooks", json={"name": "PB-C01-phishing.md", "content": md}).status_code == 409
    assert client.post("/api/playbooks", json={"name": before["playbooks"][0], "content": md}).status_code == 409
    assert client.post("/api/playbooks", json={"name": "../evil.md", "content": md}).status_code == 400
    assert client.post("/api/playbooks", json={"name": "empty.md", "content": "  "}).status_code == 400
    assert client.put("/api/playbooks/PB-C01-phishing.md", json={"content": md + "\nmore\n"}).status_code == 200
    assert client.get("/api/playbooks/PB-C01-phishing.md").text.endswith("more\n")
    assert client.put("/api/playbooks/unknown.md", json={"content": md}).status_code == 404
    assert client.put(f"/api/playbooks/{before['playbooks'][0]}", json={"content": md}).status_code == 403
    assert client.delete(f"/api/playbooks/{before['playbooks'][0]}").status_code == 403

    # a custom rule may point at a custom playbook
    rule = CUSTOM_RULE.replace("playbooks/PB-001-brute-force.md", "custom/playbooks/PB-C01-phishing.md")
    assert client.post("/api/rules", json={"rule": rule}).status_code == 200
    assert client.delete("/api/playbooks/PB-C01-phishing.md").json()["deleted"] is True
    assert client.get("/api/playbooks/PB-C01-phishing.md").status_code == 404
    assert client.get("/api/playbooks").json()["playbooks"] == before["playbooks"]


# --------------------------------------------------------------------------- #
# 7. GeoIP enrichment
# --------------------------------------------------------------------------- #

COUNTRY_CSV = "\n".join([
    "0.0.0.0,0.255.255.255,ZZ", "8.8.4.0,8.8.4.255,US", "94.20.0.0,94.20.255.255,AZ", "185.220.100.0,185.220.103.255,DE",
    "::,1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ", "2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US",
    "2a02:6b8::,2a02:6b8:ffff:ffff:ffff:ffff:ffff:ffff,RU"]) + "\n"


@pytest.mark.parametrize("compressed", [False, True])
def test_country_table_lookup(tmp_path, compressed):
    path = tmp_path / ("c.csv.gz" if compressed else "c.csv")
    path.write_bytes(gzip.compress(COUNTRY_CSV.encode()) if compressed else COUNTRY_CSV.encode())
    import ipaddress
    db = CountryDB.open(str(path))
    assert len(db) == 7 and CountryDB.open(str(path)) is db                  # loaded once per process
    look = lambda ip: db.country(ipaddress.ip_address(ip))                   # noqa: E731
    assert look("8.8.4.4") == "US" and look("94.20.0.0") == "AZ" and look("94.20.255.255") == "AZ"
    assert look("185.220.101.7") == "DE" and look("185.220.104.0") is None and look("8.8.5.1") is None
    assert look("0.1.2.3") is None                                           # ZZ = unallocated
    assert look("2001:4860:4860::8888") == "US" and look("2a02:6b8::feed:ff") == "RU" and look("2a03::1") is None


def test_geoip_sources_in_order(tmp_path):
    table = tmp_path / "c.csv"
    table.write_text(COUNTRY_CSV, encoding="utf-8")
    geo = GeoIP(custom_csv=os.path.join(ROOT, "geoip", "custom_ranges.csv"), lab_networks=["10.10.0.0/16"], country_db=str(table))
    assert geo.lookup("10.10.99.10")["name"] == "Lab-Attacker" and geo.lookup("10.10.99.10")["country_iso_code"] == "XL"
    assert geo.lookup("10.10.77.1") == {"name": "Lab-Network", "country_iso_code": "XL", "country_name": "Lab (private range)"}
    assert geo.lookup("192.168.1.9")["name"] == "Lab-Private"
    assert geo.lookup("8.8.8.8")["city_name"] == "Mountain View"            # hand-made range wins over the table
    assert geo.lookup("8.8.4.4") == {"name": "United States", "country_iso_code": "US", "country_name": "United States",
                                     "continent_code": "NA", "continent_name": "North America"}
    assert geo.lookup("94.20.20.20")["country_name"] == "Azerbaijan" and geo.lookup("94.20.20.20")["continent_code"] == "AS"
    assert geo.lookup("9.9.9.9") == {"name": "Unknown"} and geo.lookup("224.0.0.1") == {"name": "Reserved"}
    assert geo.lookup("not-an-ip") is None
    doc = {"source.ip": "185.220.101.7", "destination.ip": "10.10.30.5"}
    geo.apply(doc, "source"), geo.apply(doc, "destination")
    assert doc["source.geo.country_iso_code"] == "DE" and doc["source.geo.country_name"] == "Germany"
    assert doc["destination.geo.name"] == "Lab-Servers" and doc["destination.as.organization.name"] == "Kharibulbul Lab"
    snap = geo.snapshot()
    assert snap["custom_ranges"] >= 10 and snap["country_db"]["ipv4_ranges"] == 4 and snap["country_db"]["ipv6_ranges"] == 3


def test_country_table_covers_iso_codes():
    assert len(COUNTRIES) == 250 and country_name("az") == "Azerbaijan" and continent("AZ") == ("AS", "Asia")
    assert country_name("ZZ") is None and all(len(c) == 2 and cont in ("AF", "AN", "AS", "EU", "NA", "OC", "SA") for c, (_, cont) in COUNTRIES.items())


def test_public_addresses_get_a_country_end_to_end(client, server):
    table = os.path.join(ROOT, "geoip", "dbip-country-lite.csv.gz")
    if not os.path.exists(table):
        pytest.skip("geoip/dbip-country-lite.csv.gz not downloaded (kharibulbul geoip update)")
    line = "Sep 27 10:00:01 srv sshd[1]: Failed password for root from 77.88.8.8 port 1 ssh2"
    assert client.post("/api/ingest", json={"events": [_line(line)]}).json()["stored"] == 1
    server.store.flush()
    doc = client.get("/api/events", params={"q": "source.ip:77.88.8.8"}).json()["hits"][0]
    assert doc["source.geo.country_iso_code"] == "RU" and doc["source.geo.country_name"] == "Russia"
    assert doc["source.geo.continent_name"] == "Europe" and doc["network.direction"] == "inbound"
    assert client.get("/api/events", params={"q": 'source.geo.country_name:"Russia"'}).json()["total"] == 1
    assert client.get("/api/dashboard/overview", params={"from": "all"}).json()["top_countries"] == [{"key": "Russia", "count": 1}]
    assert client.get("/api/geoip/lookup", params={"ip": "8.8.4.4"}).json()["geo"]["country_iso_code"] == "US"
    assert client.get("/api/geoip/lookup", params={"ip": "nonsense"}).status_code == 400
    assert client.get("/api/stats").json()["geoip"]["country_db"]["ipv4_ranges"] > 100000


# --------------------------------------------------------------------------- #
# 8. ECS-style normalisation
# --------------------------------------------------------------------------- #

def test_every_scenario_event_is_ecs_conformant(pipeline):
    docs = pipeline.process_many(generate(list(SCENARIOS), seed=7))
    assert len(docs) > 600
    problems = {(d["event.dataset"], p) for d in docs for p in ecs.validate(d)}
    assert not problems, sorted(problems)[:10]
    assert all(d["ecs.version"] == ecs.ECS_VERSION and "ecs-nonconformant" not in d["tags"] for d in docs)
    assert all(d["event.category"] in ecs.EVENT_CATEGORIES for d in docs if "event.category" in d)
    assert any("related.hosts" in d for d in docs) and any("related.hash" in d for d in docs)


def test_ecs_conform_validate_and_nested_view():
    doc = {"@timestamp": "2026-09-30T10:00:00.000Z", "event.kind": "Event", "event.category": "Auth", "event.type": "Create",
           "event.outcome": "Failed", "event.dataset": "linux.auth", "host.name": "SRV", "source.ip": "10.0.0.5", "source.port": 22,
           "process.hash.sha256": "ab" * 32, "source.geo.location": {"lat": 1.0, "lon": 2.0}, "tags": []}
    ecs.conform(doc)
    assert (doc["event.kind"], doc["event.category"], doc["event.type"], doc["event.outcome"]) == ("event", "authentication", "creation", "failure")
    assert doc["ecs.version"] == ecs.ECS_VERSION and doc["related.hosts"] == ["srv"] and doc["related.hash"] == ["ab" * 32]
    assert ecs.validate(doc) == []

    bad = dict(doc, **{"event.category": "weather", "source.ip": "999.1.1.1", "source.port": "22", "tags": "x",
                       "source.geo.country_iso_code": "LAB", "myfield": 1, "@timestamp": "yesterday"})
    found = " | ".join(ecs.validate(bad))
    for needle in ("event.category: weather", "source.ip", "source.port", "tags must be a list", "alpha-2", "myfield", "@timestamp"):
        assert needle in found

    nested = ecs.to_nested(doc)
    assert nested["event"]["category"] == ["authentication"] and nested["event"]["type"] == ["creation"]      # arrays in ECS
    assert nested["source"] == {"ip": "10.0.0.5", "port": 22, "geo": {"location": {"lat": 1.0, "lon": 2.0}}}
    assert nested["process"]["hash"]["sha256"] == "ab" * 32 and nested["@timestamp"] == doc["@timestamp"]
    assert ecs.to_nested({"a": 1, "a.b": 2}) == {"a": {"value": 1, "b": 2}}


def test_nonconformant_events_are_tagged_and_ecs_format_is_served(client, server):
    good = "Sep 27 10:00:01 srv sshd[1]: Failed password for root from 10.10.99.10 port 1 ssh2"
    odd = {"raw": json.dumps({"event.category": "weather", "event.action": "rain", "message": "odd", "host.name": "h1"}), "dataset": "json"}
    assert client.post("/api/ingest", json={"events": [_line(good), odd]}).json()["stored"] == 2
    server.store.flush()
    flagged = client.get("/api/events", params={"q": "tags:ecs-nonconformant"}).json()["hits"]
    assert len(flagged) == 1 and "event.category: weather" in flagged[0]["kharibulbul.ecs.problems"][0]
    assert client.get("/api/stats").json()["pipeline"]["ecs_nonconformant"] == 1

    flat = client.get("/api/events", params={"q": "event.action:ssh-login-failed"}).json()["hits"][0]
    nested = client.get("/api/events", params={"q": "event.action:ssh-login-failed", "format": "ecs"}).json()["hits"][0]
    assert flat["source.ip"] == "10.10.99.10" and flat["event.category"] == "authentication"
    assert nested["source"]["ip"] == "10.10.99.10" and nested["event"]["category"] == ["authentication"]
    assert nested["ecs"]["version"] == ecs.ECS_VERSION and nested["source"]["geo"]["country_iso_code"] == "XL"
    assert client.get(f"/api/events/{flat['event.id']}", params={"format": "ecs"}).json()["host"]["name"] == "srv"
    schema = client.get("/api/schema").json()
    assert schema["ecs"]["version"] == ecs.ECS_VERSION and "authentication" in schema["ecs"]["event.category"]
    assert schema["fields"]["source.ip"]["ecs"] is True and schema["fields"]["kharibulbul.asset.criticality"]["ecs"] is False
