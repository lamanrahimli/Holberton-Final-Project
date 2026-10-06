"""Rule loader, matchers, condition parser and engine semantics."""
from __future__ import annotations

import pytest

from kharibulbul.detect.condition import ConditionError, compile_condition
from kharibulbul.detect.engine import DetectionEngine
from kharibulbul.detect.matchers import match_field, match_selection
from kharibulbul.detect.rules import build_rule, load_rules, validate_rule


def test_repository_rules_load_strict(rules_dir):
    rules = load_rules(rules_dir, strict=True)
    assert len(rules) >= 60
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    for r in rules:
        assert r.title and r.severity in ("informational", "low", "medium", "high", "critical")
        assert r.mitre or r.id.startswith("KB-KB"), f"{r.id} has no MITRE mapping"
        if r.playbook:
            import os
            assert os.path.exists(os.path.join(rules_dir, "..", r.playbook)), f"{r.id}: playbook {r.playbook} missing"


def test_validate_rule_errors():
    assert "missing 'id'" in validate_rule({"title": "x", "detection": {"sel": {"a": 1}}})[0]
    errs = validate_rule({"id": "X", "title": "x", "severity": "huge", "detection": {"sel": {"a": 1}, "condition": "nope"}})
    assert any("severity" in e for e in errs) and any("condition" in e for e in errs)
    assert validate_rule({"id": "X", "title": "x"}) == ["rule needs 'detection' or 'sequence'"]
    assert validate_rule({"id": "X", "title": "x", "detection": {"sel": {"a": 1}}, "threshold": {"count": 0}})[0].startswith("threshold.count")


def test_matchers_modifiers():
    doc = {"process.name": "certutil.exe", "process.command_line": "certutil -URLCache -split -f http://x", "destination.port": 4444,
           "source.ip": "10.10.99.10", "tags": ["a", "invalid-user"], "user.name": "WS01$", "flag": True}
    assert match_field(doc, "process.name", "CERTUTIL.EXE")
    assert match_field(doc, "process.name|cs", "CERTUTIL.EXE") is False
    assert match_field(doc, "process.name", "cert*")
    assert match_field(doc, "process.command_line|contains", "urlcache")
    assert match_field(doc, "process.command_line|contains|all", ["urlcache", "http"])
    assert match_field(doc, "process.command_line|contains|all", ["urlcache", "ftp"]) is False
    assert match_field(doc, "process.command_line|contains", ["ftp", "http"])
    assert match_field(doc, "process.command_line|startswith", "certutil")
    assert match_field(doc, "process.command_line|re", r"-f\s+http")
    assert match_field(doc, "destination.port|gt", 1024) and match_field(doc, "destination.port|lte", 4444)
    assert match_field(doc, "destination.port", [80, 4444])
    assert match_field(doc, "source.ip|cidr", "10.10.0.0/16") and not match_field(doc, "source.ip|cidr", "192.168.0.0/16")
    assert match_field(doc, "tags", "invalid-user")
    assert match_field(doc, "user.name|endswith", "$")
    assert match_field(doc, "user.name|endswith|not", "$") is False
    assert match_field(doc, "missing", None) and match_field(doc, "process.name", None) is False
    assert match_field(doc, "process.name|exists", True) and match_field(doc, "missing|exists", False)
    assert match_field(doc, "flag", True)
    assert match_selection([{"process.name": "x.exe"}, {"process.name": "certutil.exe"}], doc)
    assert match_selection({"process.name": "certutil.exe", "destination.port": 1}, doc) is False
    assert match_selection("urlcache", doc)


def test_condition_parser():
    names = ["selection", "filter", "sel_a", "sel_b"]
    f = compile_condition("selection and not filter", names)
    assert f({"selection": True, "filter": False}) and not f({"selection": True, "filter": True})
    f = compile_condition("1 of sel_*", names)
    assert f({"sel_a": False, "sel_b": True}) and not f({"sel_a": False, "sel_b": False})
    f = compile_condition("all of sel_* or (selection and filter)", names)
    assert f({"sel_a": True, "sel_b": True}) and f({"selection": True, "filter": True}) and not f({"sel_a": True})
    f = compile_condition("2 of them", names)
    assert f({"sel_a": True, "filter": True}) and not f({"sel_a": True})
    with pytest.raises(ConditionError):
        compile_condition("selection and unknown", names)
    with pytest.raises(ConditionError):
        compile_condition("(selection", names)


def _rule(**over):
    data = {"id": "T-1", "title": "test", "severity": "medium", "detection": {"selection": {"event.action": "logon-failed"}}}
    data.update(over)
    return build_rule(data)


def _event(ts, **fields):
    from kharibulbul.common.timeutil import from_epoch, to_iso
    doc = {"@timestamp": to_iso(from_epoch(ts)), "event.id": f"e{ts}", "event.action": "logon-failed", "host.name": "ws01", "source.ip": "10.10.99.10"}
    doc.update(fields)
    return doc


def test_match_rule_alerts_once_per_group_with_suppression(memory_alerts):
    rule = _rule(group_by=["host.name"], suppress="5m")
    engine = DetectionEngine([rule], memory_alerts, default_suppress=600)
    engine.evaluate(_event(1000))
    engine.evaluate(_event(1001))          # suppressed -> touch
    engine.evaluate(_event(1002, **{"host.name": "ws02"}))  # different group -> new alert
    engine.evaluate(_event(1400))          # after suppress window -> alert again
    assert len(memory_alerts.alerts) == 3
    assert len(memory_alerts.touched) == 1
    assert engine.snapshot()["hits"]["T-1"] == 4


def test_threshold_rule_counts_inside_window(memory_alerts):
    rule = _rule(threshold={"count": 3, "window": "1m", "group_by": ["source.ip"]})
    engine = DetectionEngine([rule], memory_alerts, default_suppress=0)
    engine.evaluate(_event(1000))
    engine.evaluate(_event(1010))
    assert memory_alerts.alerts == []
    engine.evaluate(_event(1020))
    assert len(memory_alerts.alerts) == 1 and memory_alerts.alerts[0]["count"] == 3
    # events outside the window do not count
    engine.evaluate(_event(2000))
    engine.evaluate(_event(2100))
    engine.evaluate(_event(2200))
    assert len(memory_alerts.alerts) == 1


def test_threshold_distinct(memory_alerts):
    rule = _rule(threshold={"count": 3, "window": "5m", "group_by": ["source.ip"], "distinct": "destination.port"})
    engine = DetectionEngine([rule], memory_alerts, default_suppress=0)
    for i, port in enumerate([22, 22, 22, 80, 80, 443]):
        engine.evaluate(_event(1000 + i, **{"destination.port": port}))
    assert len(memory_alerts.alerts) == 1 and memory_alerts.alerts[0]["count"] == 3


def test_sequence_rule(memory_alerts):
    rule = build_rule({"id": "S-1", "title": "seq", "severity": "critical", "sequence": {
        "by": ["source.ip"], "within": "10m",
        "stages": [{"name": "fail", "selection": {"event.action": "logon-failed"}, "count": 3},
                   {"name": "ok", "selection": {"event.action": "logon-success"}}]}})
    engine = DetectionEngine([rule], memory_alerts, default_suppress=0)
    engine.evaluate(_event(1000, **{"event.action": "logon-success"}))  # success without failures: nothing
    for i in range(3):
        engine.evaluate(_event(1001 + i))
    assert memory_alerts.alerts == []
    engine.evaluate(_event(1010, **{"event.action": "logon-success", "source.ip": "10.10.99.99"}))  # other key
    assert memory_alerts.alerts == []
    engine.evaluate(_event(1011, **{"event.action": "logon-success"}))
    assert len(memory_alerts.alerts) == 1 and memory_alerts.alerts[0]["rule.id"] == "S-1"
    # track is consumed: a second success needs new failures
    engine.evaluate(_event(1012, **{"event.action": "logon-success"}))
    assert len(memory_alerts.alerts) == 1
    # expiry: failures long ago don't count
    for i in range(3):
        engine.evaluate(_event(5000 + i))
    engine.evaluate(_event(5000 + 700, **{"event.action": "logon-success"}))
    assert len(memory_alerts.alerts) == 1


def test_logsource_prefilter_and_disable(memory_alerts):
    rule = _rule(logsource={"dataset": "windows.security"})
    engine = DetectionEngine([rule], memory_alerts, default_suppress=0)
    engine.evaluate(_event(1000, **{"event.dataset": "linux.auth"}))
    assert memory_alerts.alerts == []
    engine.evaluate(_event(1001, **{"event.dataset": "windows.security"}))
    assert len(memory_alerts.alerts) == 1
    assert engine.set_enabled("T-1", False)
    engine.evaluate(_event(1002, **{"event.dataset": "windows.security"}))
    assert len(memory_alerts.alerts) == 1
    assert engine.snapshot()["disabled_rules"] == 1
