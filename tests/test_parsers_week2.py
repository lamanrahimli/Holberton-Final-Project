"""Week 2 parsers written on top of the base set: auditd, nginx/Apache error logs, Windows DHCP, fail2ban,
plus the time-of-day context fields used by the out-of-hours rules."""
from __future__ import annotations

import os

from kharibulbul.pipeline import normalize as normalize_mod
from tests.conftest import ROOT

SAMPLES = os.path.join(ROOT, "samples")


def _lines(name):
    with open(os.path.join(SAMPLES, name), "r", encoding="utf-8") as fh:
        return [ln.rstrip("\n") for ln in fh if ln.strip()]


def test_auditd_user_auth_failed(pipeline):
    doc = pipeline.process({"raw": _lines("audit.log")[0], "dataset": "linux.auditd"})
    assert doc["kharibulbul.pipeline.parser"] == "auditd"
    assert doc["event.dataset"] == "linux.auditd" and doc["event.module"] == "linux"
    assert doc["auditd.type"] == "USER_AUTH" and doc["auditd.serial"] == 4570
    assert doc["event.category"] == "authentication" and doc["event.action"] == "auth-failed"
    assert doc["event.outcome"] == "failure"
    assert doc["user.name"] == "root" and doc["source.ip"] == "10.10.99.10"
    assert doc["process.name"] == "sshd" and doc["network.protocol"] == "ssh"
    assert doc["@timestamp"].startswith("2026-09-27T")


def test_auditd_login_sudo_execve_iam(pipeline):
    docs = {}
    for line in _lines("audit.log"):
        d = pipeline.process({"raw": line})  # no dataset hint: sniffed from 'type='
        docs.setdefault(d["auditd.type"], []).append(d)
    login = docs["USER_LOGIN"][0]
    assert login["event.action"] == "logon-success" and login["user.id"] == "1001" and login["source.ip"] == "10.10.99.10"
    cmd = docs["USER_CMD"][0]
    assert cmd["event.action"] == "sudo-command"
    assert cmd["process.command_line"] == "cat /etc/shadow"           # hex-decoded
    assert cmd["process.working_directory"] == "/home/aysel" and cmd["user.effective.name"] == "root"
    cmd2 = docs["USER_CMD"][1]
    assert cmd2["process.command_line"].startswith("useradd") and "kbtest" in cmd2["process.command_line"]
    execve = docs["EXECVE"][0]
    assert execve["event.action"] == "process-executed" and execve["process.args"] == ["cat", "/etc/shadow"]
    assert execve["process.name"] == "cat"
    syscall = docs["SYSCALL"][0]
    assert syscall["auditd.key"] == "privileged" and syscall["process.pid"] == 2052 and syscall["process.parent.pid"] == 2050
    proctitle = docs["PROCTITLE"][0]
    assert proctitle["process.command_line"] == "cat /etc/shadow"
    add_user = docs["ADD_USER"][0]
    assert add_user["event.category"] == "iam" and add_user["event.action"] == "user-created" and add_user["user.target.id"] == "1002"
    assert docs["USER_CHAUTHTOK"][0]["event.action"] == "user-password-change" and docs["USER_CHAUTHTOK"][0]["user.target.name"] == "kbtest"
    assert docs["USER_START"][0]["event.category"] == "session"
    assert docs["SERVICE_STOP"][0]["event.action"] == "service-stopped" and docs["SERVICE_STOP"][0]["service.name"] == "auditd"
    assert docs["CONFIG_CHANGE"][0]["event.category"] == "configuration"
    # all lines parsed by the auditd parser, none fell through to generic
    assert all(d["kharibulbul.pipeline.parser"] == "auditd" for ds in docs.values() for d in ds)


def test_nginx_error_log(pipeline):
    lines = _lines("nginx-error.log")
    doc = pipeline.process({"raw": lines[0], "dataset": "nginx.error"})
    assert doc["kharibulbul.pipeline.parser"] == "apache_error"
    assert doc["event.dataset"] == "nginx.error" and doc["event.category"] == "web" and doc["event.action"] == "web-error"
    assert doc["log.level"] == "error" and doc["source.ip"] == "10.10.99.10"
    assert doc["http.request.method"] == "GET" and doc["url.path"] == "/.env"
    assert doc["file.path"] == "/var/www/html/.env" and "sensitive-path" in doc["tags"]
    assert doc["@timestamp"].startswith("2026-09-27T10:16:00")
    crit = pipeline.process({"raw": lines[6]})  # sniffed, no dataset hint
    assert crit["log.level"] == "critical" and crit["event.dataset"] == "nginx.error"
    notice = pipeline.process({"raw": lines[7]})
    assert notice["log.level"] == "info" and "source.ip" not in notice


def test_apache_error_log(pipeline):
    lines = _lines("apache-error.log")
    doc = pipeline.process({"raw": lines[0], "dataset": "apache.error"})
    assert doc["kharibulbul.pipeline.parser"] == "apache_error"
    assert doc["event.dataset"] == "apache.error" and doc["apache.module"] == "core"
    assert doc["error.code"] == "AH00128" and doc["file.path"] == "/var/www/html/.env"
    assert doc["source.ip"] == "10.10.99.10" and doc["source.port"] == 40001
    assert doc["@timestamp"].startswith("2026-09-27T10:16:00.123")
    assert "sensitive-path" in doc["tags"]
    denied = pipeline.process({"raw": lines[2]})
    assert denied["apache.module"] == "authz_core" and denied["error.code"] == "AH01630"
    ok = pipeline.process({"raw": lines[4]})
    assert ok["log.level"] == "info" and ok["error.code"] == "AH00489"


def test_windows_dhcp_log(pipeline):
    lines = _lines("DhcpSrvLog-Sat.log")
    parsed = [pipeline.process({"raw": ln, "dataset": "windows.dhcp"}) for ln in lines]
    docs = [d for d in parsed if d is not None and d["kharibulbul.pipeline.parser"] == "windows_dhcp"]
    assert len(docs) == 7, "header/description lines must not become DHCP events"
    assign = next(d for d in docs if d["event.code"] == "10")
    assert assign["event.action"] == "dhcp-lease-assigned" and assign["client.ip"] == "10.10.20.10"
    assert assign["client.domain"] == "ws01.lab.local" and assign["client.mac"] == "00:15:5d:01:02:03"
    assert assign["@timestamp"].startswith("2026-09-27T10:05:00") and assign["event.outcome"] == "success"
    conflict = next(d for d in docs if d["event.code"] == "13")
    assert conflict["event.action"] == "dhcp-ip-conflict" and conflict["event.type"] == "denied" and conflict["event.outcome"] == "failure"
    nack = next(d for d in docs if d["event.code"] == "15")
    assert nack["event.action"] == "dhcp-lease-denied" and nack["client.domain"] == "unknown-device"


def test_fail2ban_syslog(pipeline):
    lines = _lines("fail2ban.log")
    ban = pipeline.process({"raw": lines[5], "dataset": "linux.auth"})
    assert ban["event.dataset"] == "linux.fail2ban" and ban["event.category"] == "intrusion_detection"
    assert ban["event.action"] == "fail2ban-ban" and ban["event.type"] == "denied"
    assert ban["source.ip"] == "10.10.99.10" and ban["rule.name"] == "sshd"
    assert ban["event.severity"] >= 50
    found = pipeline.process({"raw": lines[0]})
    assert found["event.action"] == "fail2ban-found" and found["event.type"] == "info"
    unban = pipeline.process({"raw": lines[8]})
    assert unban["event.action"] == "fail2ban-unban" and unban["event.type"] == "allowed"
    restore = pipeline.process({"raw": lines[9]})
    assert restore["event.action"] == "fail2ban-restore-ban" and restore["source.ip"] == "10.10.99.11"


def test_time_context_fields(pipeline):
    # server.yml: timezone_offset_hours 4, business_hours [8, 19]
    sat = pipeline.process({"raw": "Sep 26 10:00:00 srv sshd[1]: Accepted publickey for ops from 10.10.20.33 port 1 ssh2"})
    # RFC3164 has no year: the parser assumes the current year; check weekday/hour logic on an explicit ISO stamp instead
    import json
    mon = pipeline.process({"raw": json.dumps({"@timestamp": "2026-09-28T05:30:00Z", "event": {"dataset": "custom.t"}, "message": "x"})})
    assert mon["kharibulbul.time.hour"] == 9 and mon["kharibulbul.time.weekday"] == "mon"
    assert mon["kharibulbul.time.business_hours"] is True
    night = pipeline.process({"raw": json.dumps({"@timestamp": "2026-09-28T22:30:00Z", "event": {"dataset": "custom.t"}, "message": "x"})})
    assert night["kharibulbul.time.hour"] == 2 and night["kharibulbul.time.weekday"] == "tue"
    assert night["kharibulbul.time.business_hours"] is False
    weekend = pipeline.process({"raw": json.dumps({"@timestamp": "2026-09-27T08:00:00Z", "event": {"dataset": "custom.t"}, "message": "x"})})
    assert weekend["kharibulbul.time.weekday"] == "sun" and weekend["kharibulbul.time.business_hours"] is False
    assert "kharibulbul.time.hour" in sat
    # configure() is what the pipeline calls from config
    normalize_mod.configure(0, (8, 19))
    try:
        utc = pipeline.process({"raw": json.dumps({"@timestamp": "2026-09-28T05:30:00Z", "event": {"dataset": "custom.t"}, "message": "x"})})
        assert utc["kharibulbul.time.hour"] == 5 and utc["kharibulbul.time.business_hours"] is False
    finally:
        normalize_mod.configure(4, (8, 19))
