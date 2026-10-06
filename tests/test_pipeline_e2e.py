"""End-to-end: synthetic scenarios -> pipeline -> detection engine -> expected rules fire."""
from __future__ import annotations

import pytest

from kharibulbul.detect.engine import DetectionEngine
from kharibulbul.detect.rules import load_rules
from kharibulbul.simulate.scenarios import SCENARIOS, generate

EXPECTED = {
    "windows-brute-force": {"KB-WIN-001", "KB-COR-001"},
    "ssh-brute-force": {"KB-LNX-001", "KB-LNX-002", "KB-COR-002"},
    "port-scan": {"KB-NET-001", "KB-NET-002"},
    "lolbin": {"KB-SYS-010", "KB-SYS-011", "KB-SYS-012", "KB-SYS-013", "KB-SYS-014", "KB-SYS-015", "KB-SYS-016", "KB-SYS-018"},
    "encoded-powershell": {"KB-SYS-020", "KB-PS-001", "KB-PS-002"},
    "new-admin-user": {"KB-WIN-010", "KB-WIN-011", "KB-COR-003"},
    "log-cleared": {"KB-WIN-020"},
    "suspicious-service": {"KB-WIN-030", "KB-WIN-031"},
    "scheduled-task": {"KB-WIN-032", "KB-WIN-033"},
    "suspicious-dns": {"KB-NET-010", "KB-TI-002"},
    "intel-hit": {"KB-TI-001", "KB-TI-002", "KB-NET-021"},
    "linux-privilege": {"KB-LNX-010", "KB-LNX-011", "KB-LNX-012", "KB-LNX-013", "KB-LNX-017", "KB-COR-003"},
    "web-scan": {"KB-WEB-001", "KB-WEB-002", "KB-WEB-003", "KB-WEB-004"},
    "office-spawn": {"KB-SYS-030"},
    "credential-access": {"KB-SYS-040"},
    # Week 3 team rules (rules/team/*.yml)
    "after-hours-logon": {"KB-WIN-007"},
    "multi-host-logon": {"KB-WIN-008"},
    "rdp-then-service": {"KB-COR-006", "KB-WIN-030", "KB-WIN-031"},
    "download-then-execute": {"KB-COR-007", "KB-SYS-050"},
    "dns-beacon": {"KB-NET-014", "KB-NET-011"},
    "defender-exclusion": {"KB-SYS-072"},
    "web-errors": {"KB-WEB-006", "KB-WEB-007"},
    "fail2ban": {"KB-NET-030", "KB-NET-033"},
    "auditd": {"KB-LNX-021", "KB-LNX-020"},
    "firewall-outbound-burst": {"KB-NET-005"},
    "dhcp": {"KB-NET-031", "KB-NET-032"},
    # coverage pack (kharibulbul/simulate/coverage_pack.py)
    "password-spray": {"KB-WIN-002", "KB-WIN-001"},
    "account-lockout": {"KB-WIN-003"},
    "logon-outside-lab": {"KB-WIN-004"},
    "explicit-credentials": {"KB-WIN-005"},
    "kerberos-failures": {"KB-WIN-006"},
    "account-lifecycle": {"KB-WIN-012", "KB-WIN-013"},
    "audit-tampering": {"KB-WIN-021", "KB-WIN-024", "KB-WIN-022"},
    "defender-detection": {"KB-WIN-023"},
    "injection-and-tampering": {"KB-SYS-041", "KB-SYS-060"},
    "ransomware-precursor": {"KB-SYS-061"},
    "registry-persistence": {"KB-SYS-070", "KB-SYS-071"},
    "recon-burst": {"KB-SYS-017"},
    "powershell-offensive-keywords": {"KB-PS-003"},
    "intel-hash": {"KB-TI-003"},
    "ssh-outside-lab": {"KB-LNX-003", "KB-LNX-004"},
    "ssh-slow-brute": {"KB-LNX-005"},
    "su-and-cron": {"KB-LNX-014", "KB-LNX-016"},
    "auditd-tamper": {"KB-LNX-022"},
    "host-sweep": {"KB-NET-004"},
    "windows-firewall-scan": {"KB-NET-003"},
    "dns-tunnel": {"KB-NET-012", "KB-NET-014"},
    "web-injection": {"KB-WEB-005", "KB-WEB-008"},
    "scan-then-logon": {"KB-COR-004", "KB-NET-002"},
    "download-then-beacon": {"KB-COR-005", "KB-SYS-010"},
    "agent-silent": {"KB-KB-001"},
}


def _run(pipeline, rules, scenarios, memory_alerts):
    engine = DetectionEngine(rules, memory_alerts, default_suppress=600)
    docs = pipeline.process_many(generate(scenarios, seed=7))
    for doc in docs:
        engine.evaluate(doc)
    return docs, engine


@pytest.mark.parametrize("scenario", sorted(EXPECTED))
def test_scenario_triggers_expected_rules(pipeline, rules_dir, memory_alerts, scenario):
    rules = load_rules(rules_dir, strict=True)
    docs, _ = _run(pipeline, rules, [scenario], memory_alerts)
    assert docs, "scenario produced no documents"
    fired = memory_alerts.ids()
    missing = EXPECTED[scenario] - fired
    assert not missing, f"{scenario}: rules did not fire: {sorted(missing)}; fired={sorted(fired)}"


def test_baseline_is_quiet(pipeline, rules_dir, memory_alerts):
    rules = load_rules(rules_dir, strict=True)
    docs, engine = _run(pipeline, rules, ["baseline"], memory_alerts)
    assert len(docs) >= 60
    assert memory_alerts.alerts == [], f"baseline traffic raised alerts: {sorted(memory_alerts.ids())}"
    assert not engine.snapshot()["errors"]


def test_all_scenarios_parse_cleanly(pipeline, rules_dir, memory_alerts):
    rules = load_rules(rules_dir, strict=True)
    envelopes = generate(["all"], seed=1)
    docs = pipeline.process_many(envelopes)
    assert len(docs) == len(envelopes), "every synthetic event must parse"
    assert not [d for d in docs if "parser-error" in d.get("tags", [])]
    assert {d["kharibulbul.pipeline.parser"] for d in docs} >= {"windows", "syslog", "web"}
    engine = DetectionEngine(rules, memory_alerts, default_suppress=600)
    for d in docs:
        engine.evaluate(d)
    assert not engine.snapshot()["errors"], engine.snapshot()["errors"]
    assert len(memory_alerts.ids()) >= 30


def test_every_scenario_is_documented():
    for name, (desc, fn) in SCENARIOS.items():
        assert desc and callable(fn), name
