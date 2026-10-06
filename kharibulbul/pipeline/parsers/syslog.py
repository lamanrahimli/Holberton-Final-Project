"""Syslog (RFC3164 / RFC5424) and Linux program parsers.

The syslog parser splits the header, then hands the message to a program
specific sub-parser (sshd, sudo, su, useradd, kernel/UFW, cron, systemd...).
The same sub-parsers are used for plain files (auth.log, ufw.log) and for
journald JSON lines, so every Linux path ends in the same ECS fields.
"""
from __future__ import annotations

import re

from ...common.util import to_int
from . import register
from .base import base_doc, set_ip, set_port, set_ts

FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
              "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]
SEVERITIES = ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"]
LOG_LEVEL = {"emergency": "critical", "alert": "critical", "critical": "critical", "error": "error",
             "warning": "warning", "notice": "info", "informational": "info", "debug": "debug"}

# <34>Oct 11 22:14:15 mymachine su[123]: 'su root' failed for lonvick on /dev/pts/8
_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[^\s:]+)\s+(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:?\s*(?P<msg>.*)$", re.S)
# systemd/journal style "2024-05-01T10:00:00.123456+02:00 host tag[pid]: msg"
_ISO_SYSLOG = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[^\s:]+)\s+(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:?\s*(?P<msg>.*)$", re.S)
# <34>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 1234 ID47 [sd@1 a="b"] BOMAn application event
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<sd>-|(?:\[[^\]]*\])+)\s*(?P<msg>.*)$", re.S)


def split_syslog(line: str) -> dict | None:
    text = line.strip()
    if not text:
        return None
    for rx in (_RFC5424, _RFC3164, _ISO_SYSLOG):
        m = rx.match(text)
        if m:
            d = m.groupdict()
            d["_format"] = "rfc5424" if rx is _RFC5424 else "rfc3164"
            if rx is _RFC5424:
                d["tag"] = d.pop("app")
                if d.get("pid") == "-":
                    d["pid"] = None
            d["msg"] = (d.get("msg") or "").lstrip("\ufeff").strip()
            return d
    return None


def _apply_pri(doc: dict, pri: str | None) -> None:
    if pri is None:
        return
    val = int(pri)
    facility, severity = val // 8, val % 8
    if facility < len(FACILITIES):
        doc["log.syslog.facility.name"] = FACILITIES[facility]
        doc["log.syslog.facility.code"] = facility
    doc["log.syslog.severity.name"] = SEVERITIES[severity]
    doc["log.syslog.severity.code"] = severity
    doc["log.level"] = LOG_LEVEL[SEVERITIES[severity]]
    doc["log.syslog.priority"] = val


# --------------------------------------------------------------------------- #
# Program sub-parsers: (doc, message) -> bool
# --------------------------------------------------------------------------- #

_SSH_FAILED = re.compile(r"Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_ACCEPTED = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_SSH_DISCONNECT = re.compile(r"(?:Disconnected from|Connection closed by|Received disconnect from) (?:(?:authenticating|invalid) user (?P<user>\S+) )?(?P<ip>\d[\d.]+|[0-9a-f:]+) port (?P<port>\d+)")
_SSH_TOOMANY = re.compile(r"(?:maximum authentication attempts exceeded|error: maximum authentication attempts) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_PAM = re.compile(r"pam_unix\(sshd:auth\): authentication failure;.*rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?")
_SSH_SESSION = re.compile(r"pam_unix\(sshd:session\): session (?P<state>opened|closed) for user (?P<user>\S+)")


def parse_sshd(doc: dict, msg: str) -> bool:
    doc["event.dataset"] = "linux.auth"
    doc["event.module"] = "linux"
    doc["network.protocol"] = "ssh"
    m = _SSH_FAILED.search(msg)
    if m:
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "ssh-login-failed", "event.outcome": "failure", "event.severity": "low"})
        doc["user.name"] = m.group("user")
        set_ip(doc, "source.ip", m.group("ip"))
        set_port(doc, "source.port", m.group("port"))
        doc["kharibulbul.auth.method"] = m.group("method")
        if m.group("invalid"):
            doc["tags"].append("invalid-user")
        doc["message"] = f"SSH login FAILED for {doc['user.name']} from {doc.get('source.ip')} ({m.group('method')})"
        return True
    m = _SSH_ACCEPTED.search(msg)
    if m:
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "ssh-login-success", "event.outcome": "success"})
        doc["user.name"] = m.group("user")
        set_ip(doc, "source.ip", m.group("ip"))
        set_port(doc, "source.port", m.group("port"))
        doc["kharibulbul.auth.method"] = m.group("method")
        doc["message"] = f"SSH login success for {doc['user.name']} from {doc.get('source.ip')} ({m.group('method')})"
        return True
    m = _SSH_TOOMANY.search(msg)
    if m:
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "ssh-login-failed", "event.outcome": "failure", "event.severity": "low"})
        doc["user.name"] = m.group("user")
        set_ip(doc, "source.ip", m.group("ip"))
        set_port(doc, "source.port", m.group("port"))
        doc["tags"].append("max-auth-attempts")
        doc["message"] = f"SSH max auth attempts exceeded for {doc['user.name']} from {doc.get('source.ip')}"
        return True
    m = _SSH_INVALID.search(msg)
    if m:
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "ssh-invalid-user", "event.outcome": "failure", "event.severity": "low"})
        doc["user.name"] = m.group("user") or None
        set_ip(doc, "source.ip", m.group("ip"))
        set_port(doc, "source.port", m.group("port"))
        doc["tags"].append("invalid-user")
        doc["message"] = f"SSH invalid user {doc.get('user.name')} from {doc.get('source.ip')}"
        return True
    m = _SSH_PAM.search(msg)
    if m:
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "ssh-pam-auth-failure", "event.outcome": "failure"})
        doc["user.name"] = m.group("user")
        set_ip(doc, "source.ip", m.group("ip"))
        doc["message"] = f"SSH PAM authentication failure for {doc.get('user.name')} from {doc.get('source.ip')}"
        return True
    m = _SSH_SESSION.search(msg)
    if m:
        opened = m.group("state") == "opened"
        doc.update({"event.category": "session", "event.type": "start" if opened else "end",
                    "event.action": "ssh-session-opened" if opened else "ssh-session-closed", "event.outcome": "success"})
        doc["user.name"] = m.group("user")
        doc["message"] = f"SSH session {m.group('state')} for {doc['user.name']}"
        return True
    m = _SSH_DISCONNECT.search(msg)
    if m:
        doc.update({"event.category": "network", "event.type": "end", "event.action": "ssh-disconnected", "event.outcome": "unknown"})
        doc["user.name"] = m.group("user")
        set_ip(doc, "source.ip", m.group("ip"))
        set_port(doc, "source.port", m.group("port"))
        doc["message"] = f"SSH disconnected {doc.get('source.ip')}"
        return True
    doc.update({"event.category": "authentication", "event.type": "info", "event.action": "sshd-message"})
    return True


_SUDO = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<result>.*?TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>[^;]*);\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*))$")
_SUDO_FAIL = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<reason>\d+ incorrect password attempts?|command not allowed|user NOT in sudoers|a password is required)")
_SUDO_PAM = re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*user=(?P<user>\S+)")


def parse_sudo(doc: dict, msg: str) -> bool:
    doc["event.dataset"] = "linux.auth"
    doc["event.module"] = "linux"
    m = _SUDO.search(msg)
    if m:
        failed = "incorrect password" in m.group("result") or "NOT in sudoers" in m.group("result") or "command not allowed" in m.group("result")
        doc.update({"event.category": "process", "event.type": "start", "event.action": "sudo-command",
                    "event.outcome": "failure" if failed else "success", "event.severity": "medium" if failed else "informational"})
        doc["user.name"] = m.group("user")
        doc["user.effective.name"] = m.group("target")
        doc["process.command_line"] = m.group("cmd").strip()
        doc["process.working_directory"] = m.group("pwd").strip()
        doc["process.name"] = doc["process.command_line"].split()[0].rsplit("/", 1)[-1] if doc["process.command_line"] else None
        doc["message"] = f"sudo: {m.group('user')} as {m.group('target')}: {doc['process.command_line']}"
        return True
    m = _SUDO_FAIL.search(msg)
    if m:
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "sudo-failed", "event.outcome": "failure", "event.severity": "medium"})
        doc["user.name"] = m.group("user")
        doc["message"] = f"sudo failure for {m.group('user')}: {m.group('reason')}"
        return True
    m = _SUDO_PAM.search(msg)
    if m:
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "sudo-auth-failure", "event.outcome": "failure", "event.severity": "low"})
        doc["user.name"] = m.group("user")
        doc["message"] = f"sudo authentication failure for {m.group('user')}"
        return True
    if "session opened" in msg:
        m2 = re.search(r"session opened for user (?P<target>\S+)(?:\(uid=\d+\))? by (?:(?P<user>\S+?)\(uid=\d+\))?", msg)
        doc.update({"event.category": "session", "event.type": "start", "event.action": "sudo-session-opened", "event.outcome": "success"})
        if m2:
            doc["user.effective.name"] = m2.group("target")
            doc["user.name"] = m2.group("user")
        return True
    doc.update({"event.category": "process", "event.type": "info", "event.action": "sudo-message"})
    return True


# util-linux: "(to root) aysel on pts/0" / "FAILED SU (to root) aysel on pts/0"; shadow: "Successful su for root by aysel"
_SU_FAILED = re.compile(r"FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on|FAILED su for (?P<target2>\S+) by (?P<user2>\S+)")
_SU_OK = re.compile(r"^\s*\(to (?P<target>\S+)\) (?P<user>\S+) on|Successful su for (?P<target2>\S+) by (?P<user2>\S+)")
_SU_PAM = re.compile(r"pam_\w+\(su(?:-l)?:auth\): authentication failure;.*?ruser=(?P<user>\S*)(?:\s+rhost=\S*)?(?:\s+user=(?P<target>\S+))?")
_SU_SESSION = re.compile(r"pam_unix\(su(?:-l)?:session\): session (?P<state>opened|closed) for user (?P<target>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<user>[^\s(]*)\(uid=\d+\))?")


def parse_su(doc: dict, msg: str) -> bool:
    doc["event.dataset"] = "linux.auth"
    doc["event.module"] = "linux"
    for rx, failed in ((_SU_FAILED, True), (_SU_OK, False)):
        m = rx.search(msg)
        if m:
            doc["user.name"] = m.group("user") or m.group("user2")
            doc["user.effective.name"] = m.group("target") or m.group("target2")
            doc.update({"event.category": "authentication", "event.type": "start", "event.action": "su-failed" if failed else "su-success",
                        "event.outcome": "failure" if failed else "success", "event.severity": "medium" if failed else "informational"})
            doc["message"] = f"su {'FAILED' if failed else 'ok'}: {doc['user.name']} -> {doc['user.effective.name']}"
            return True
    m = _SU_PAM.search(msg)
    if m:
        # PAM's line for the attempt that su itself reports as "FAILED SU": kept searchable, but it is not a
        # second authentication failure (one mistyped password = one failure on the dashboard)
        doc.update({"event.category": "process", "event.type": "info", "event.action": "su-pam-auth-failure", "event.outcome": "failure"})
        if m.group("user"):
            doc["user.name"] = m.group("user")
        if m.group("target"):
            doc["user.effective.name"] = m.group("target")
        doc["message"] = f"su PAM authentication failure: {doc.get('user.name')} -> {doc.get('user.effective.name')}"
        return True
    m = _SU_SESSION.search(msg)
    if m:
        opened = m.group("state") == "opened"
        doc.update({"event.category": "session", "event.type": "start" if opened else "end",
                    "event.action": "su-session-opened" if opened else "su-session-closed", "event.outcome": "success"})
        doc["user.effective.name"] = m.group("target")
        if m.group("user"):
            doc["user.name"] = m.group("user")
        doc["message"] = f"su session {m.group('state')} for {m.group('target')}"
        return True
    doc.update({"event.category": "process", "event.type": "info", "event.action": "su-message"})
    return True


_USERADD = re.compile(r"new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+), home=(?P<home>[^,]+), shell=(?P<shell>\S+)")
_GROUPADD = re.compile(r"new group: name=(?P<name>[^,]+), GID=(?P<gid>\d+)")
_USERDEL = re.compile(r"delete user '(?P<name>[^']+)'")
_USERMOD = re.compile(r"add '(?P<name>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
_PASSWD = re.compile(r"password (?:for|changed for) '?(?P<name>[^'\s]+)'? changed by '?(?P<by>[^'\s]+)'?|pam_unix\(passwd:chauthtok\): password changed for (?P<name2>\S+)")


def parse_account_mgmt(doc: dict, msg: str) -> bool:
    doc["event.dataset"] = "linux.auth"
    doc["event.module"] = "linux"
    doc["event.category"] = "iam"
    m = _USERADD.search(msg)
    if m:
        doc.update({"event.type": "user", "event.action": "user-created", "event.outcome": "success", "event.severity": "medium"})
        doc["user.target.name"] = m.group("name")
        doc["user.target.id"] = m.group("uid")
        doc["user.target.shell"] = m.group("shell")
        doc["message"] = f"User created: {m.group('name')} (uid {m.group('uid')})"
        return True
    m = _GROUPADD.search(msg)
    if m:
        doc.update({"event.type": "group", "event.action": "group-created", "event.outcome": "success"})
        doc["group.name"] = m.group("name")
        doc["message"] = f"Group created: {m.group('name')}"
        return True
    m = _USERDEL.search(msg)
    if m:
        doc.update({"event.type": "user", "event.action": "user-deleted", "event.outcome": "success", "event.severity": "medium"})
        doc["user.target.name"] = m.group("name")
        doc["message"] = f"User deleted: {m.group('name')}"
        return True
    m = _USERMOD.search(msg)
    if m:
        doc.update({"event.type": "group", "event.action": "group-member-added", "event.outcome": "success",
                    "event.severity": "high" if m.group("group") in ("sudo", "wheel", "admin", "root", "docker") else "low"})
        doc["user.target.name"] = m.group("name")
        doc["group.name"] = m.group("group")
        doc["message"] = f"User {m.group('name')} added to group {m.group('group')}"
        return True
    m = _PASSWD.search(msg)
    if m:
        doc.update({"event.type": "user", "event.action": "user-password-change", "event.outcome": "success"})
        doc["user.target.name"] = m.group("name") or m.group("name2")
        doc["user.name"] = m.group("by")
        doc["message"] = f"Password changed for {doc['user.target.name']}"
        return True
    doc.update({"event.type": "info", "event.action": "account-management"})
    return True


_KV = re.compile(r"(\w+)=(\S*)")


def parse_kernel_firewall(doc: dict, msg: str) -> bool:
    """UFW / iptables LOG lines: '[UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4 DST=10.0.0.5 ... PROTO=TCP SPT=4444 DPT=22'."""
    if "SRC=" not in msg or "DST=" not in msg:
        return False
    kv = dict(_KV.findall(msg))
    doc["event.dataset"] = "linux.firewall"
    doc["event.module"] = "linux"
    doc["event.category"] = "network"
    prefix = msg.split("IN=")[0].strip().strip("[]") if "IN=" in msg else ""
    blocked = "BLOCK" in prefix.upper() or "DROP" in prefix.upper() or "REJECT" in prefix.upper() or "DENY" in prefix.upper()
    doc["event.type"] = "denied" if blocked else "allowed"
    doc["event.action"] = "firewall-block" if blocked else "firewall-allow"
    doc["event.outcome"] = "failure" if blocked else "success"
    doc["rule.name"] = prefix or None
    set_ip(doc, "source.ip", kv.get("SRC"))
    set_ip(doc, "destination.ip", kv.get("DST"))
    set_port(doc, "source.port", kv.get("SPT"))
    set_port(doc, "destination.port", kv.get("DPT"))
    doc["network.transport"] = (kv.get("PROTO") or "").lower() or None
    doc["observer.ingress.interface.name"] = kv.get("IN") or None
    doc["observer.egress.interface.name"] = kv.get("OUT") or None
    doc["network.direction"] = "inbound" if kv.get("IN") else "outbound"
    doc["message"] = f"Firewall {doc['event.type']}: {doc.get('source.ip')}:{doc.get('source.port')} -> {doc.get('destination.ip')}:{doc.get('destination.port')}/{doc.get('network.transport')}"
    return True


_CRON = re.compile(r"\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)")


def parse_cron(doc: dict, msg: str) -> bool:
    doc["event.dataset"] = "linux.cron"
    doc["event.module"] = "linux"
    m = _CRON.search(msg)
    if m:
        doc.update({"event.category": "process", "event.type": "start", "event.action": "cron-command", "event.outcome": "success"})
        doc["user.name"] = m.group("user")
        doc["process.command_line"] = m.group("cmd")
        doc["message"] = f"cron ({m.group('user')}): {m.group('cmd')}"
        return True
    doc.update({"event.category": "process", "event.type": "info", "event.action": "cron-message"})
    return True


def parse_systemd(doc: dict, msg: str) -> bool:
    doc["event.dataset"] = "linux.system"
    doc["event.module"] = "linux"
    doc["event.category"] = "host"
    m = re.search(r"(Started|Stopped|Starting|Stopping|Failed to start|Reloaded) (?P<unit>.+?)\.?$", msg)
    if m:
        verb = m.group(1)
        doc["event.type"] = "start" if verb in ("Started", "Starting") else ("end" if verb in ("Stopped", "Stopping") else "info")
        doc["event.action"] = "systemd-unit-" + verb.lower().replace(" ", "-")
        doc["event.outcome"] = "failure" if "Failed" in verb else "success"
        doc["service.name"] = m.group("unit")
        return True
    doc["event.type"] = "info"
    doc["event.action"] = "systemd-message"
    return True


def parse_logind(doc: dict, msg: str) -> bool:
    doc["event.dataset"] = "linux.auth"
    doc["event.module"] = "linux"
    m = re.search(r"New session (?P<id>\S+) of user (?P<user>\S+)", msg)
    if m:
        doc.update({"event.category": "session", "event.type": "start", "event.action": "session-started", "event.outcome": "success"})
        doc["user.name"] = m.group("user")
        return True
    m = re.search(r"Removed session (?P<id>\S+)", msg)
    if m:
        doc.update({"event.category": "session", "event.type": "end", "event.action": "session-ended", "event.outcome": "success"})
        return True
    doc.update({"event.category": "session", "event.type": "info", "event.action": "logind-message"})
    return True


_F2B = re.compile(r"\[(?P<jail>[^\]]+)\]\s+(?P<action>Restore Ban|Ban|Unban|Found|Ignore|Flush)\s+(?P<ip>\d[\d.]+|[0-9a-fA-F:]+)")


def parse_fail2ban(doc: dict, msg: str) -> bool:
    """fail2ban.actions: 'NOTICE [sshd] Ban 10.10.99.10' / fail2ban.filter: 'INFO [sshd] Found 10.10.99.10 - 2026-...'"""
    doc["event.dataset"] = "linux.fail2ban"
    doc["event.module"] = "linux"
    doc["event.category"] = "intrusion_detection"
    m = _F2B.search(msg)
    if not m:
        doc.update({"event.type": "info", "event.action": "fail2ban-message"})
        return True
    action = m.group("action").lower().replace(" ", "-")
    banned = action in ("ban", "restore-ban")
    doc.update({"event.type": "denied" if banned else ("allowed" if action == "unban" else "info"),
                "event.action": f"fail2ban-{action}", "event.outcome": "success",
                "event.severity": "medium" if banned else "informational"})
    set_ip(doc, "source.ip", m.group("ip"))
    doc["rule.name"] = m.group("jail")
    doc["message"] = f"fail2ban {m.group('action')} {m.group('ip')} (jail {m.group('jail')})"
    return True


PROGRAM_PARSERS = {
    "sshd": parse_sshd, "sshd-session": parse_sshd, "sudo": parse_sudo, "su": parse_su, "useradd": parse_account_mgmt,
    "userdel": parse_account_mgmt, "usermod": parse_account_mgmt, "groupadd": parse_account_mgmt, "passwd": parse_account_mgmt,
    "kernel": parse_kernel_firewall, "ufw": parse_kernel_firewall, "cron": parse_cron, "crond": parse_cron,
    "systemd": parse_systemd, "systemd-logind": parse_logind, "login": parse_sshd,
    "fail2ban": parse_fail2ban, "fail2ban.actions": parse_fail2ban, "fail2ban.filter": parse_fail2ban, "fail2ban-server": parse_fail2ban,
}


def apply_program_parser(doc: dict, program: str | None, msg: str) -> None:
    """Populate ECS fields from a program's message text (shared with journald)."""
    prog = (program or "").lower()
    doc["log.syslog.appname"] = program
    doc["process.name"] = doc.get("process.name") or program
    handled = False
    fn = PROGRAM_PARSERS.get(prog)
    if fn:
        handled = fn(doc, msg)
    if not handled:
        if prog.startswith("sshd"):
            handled = parse_sshd(doc, msg)
        elif "SRC=" in msg and "DST=" in msg:
            handled = parse_kernel_firewall(doc, msg)
    if not handled:
        doc.setdefault("event.category", "host")
        doc.setdefault("event.type", "info")
        doc.setdefault("event.action", f"{prog or 'syslog'}-message")
    doc.setdefault("message", msg)


@register("syslog")
def parse(raw: str, meta: dict) -> dict | None:
    parts = split_syslog(raw)
    if not parts:
        return None
    doc = base_doc(raw, meta, "syslog", "syslog", "syslog")
    doc["event.dataset"] = meta.get("dataset") or "syslog"
    set_ts(doc, parts.get("ts"))
    _apply_pri(doc, parts.get("pri"))
    host = parts.get("host")
    if host and host != "-":
        doc["host.name"] = doc.get("host.name") or host.split(".")[0]
        doc["log.syslog.hostname"] = host
    if parts.get("pid"):
        doc["process.pid"] = to_int(parts["pid"])
    doc["host.os.type"] = doc.get("host.os.type") or "linux"
    apply_program_parser(doc, parts.get("tag"), parts.get("msg") or "")
    if parts.get("msgid") and parts["msgid"] != "-":
        doc["log.syslog.msgid"] = parts["msgid"]
    return doc
