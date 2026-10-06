"""Linux auditd parser (/var/log/audit/audit.log).

Lines look like::

    type=USER_AUTH msg=audit(1790000000.500:4570): pid=2000 uid=0 auid=4294967295 ses=4294967295
        msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=10.10.99.10
        addr=10.10.99.10 terminal=ssh res=failed'
    type=EXECVE msg=audit(1790000000.123:4567): argc=2 a0="cat" a1="/etc/shadow"
    type=USER_CMD msg=audit(...): pid=... uid=1001 auid=1001 ses=4 msg='cwd="/home/aysel"
        cmd=636174202F6574632F736861646F77 exe="/usr/bin/sudo" terminal=pts/0 res=success'

Every record type is kept (``auditd.type``, ``auditd.serial`` allow joining the SYSCALL /
EXECVE / PROCTITLE records of one event); the common ones are mapped to the standard
Kharibulbul actions so the Linux rules work on auditd data as well.
"""
from __future__ import annotations

import re

from ...common.util import to_int
from . import register
from .base import base_doc, set_ip, set_process_path, set_ts

_HEAD = re.compile(r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>[A-Z_]+)\s+msg=audit\((?P<ts>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*(?P<body>.*)$")
_KV = re.compile(r"([A-Za-z_][\w-]*)=('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|\S*)")
_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_HEX_FIELDS = {"cmd", "proctitle", "acct", "comm", "cwd", "dir", "path", "name"}

IAM_TYPES = {
    "ADD_USER": ("user", "user-created"), "DEL_USER": ("user", "user-deleted"), "ADD_GROUP": ("group", "group-created"),
    "DEL_GROUP": ("group", "group-deleted"), "USER_CHAUTHTOK": ("user", "user-password-change"),
    "USER_MGMT": ("user", "account-management"), "GRP_MGMT": ("group", "account-management"), "ROLE_ASSIGN": ("user", "role-assigned"),
}
AUTH_TYPES = {"USER_AUTH", "USER_ACCT", "CRED_ACQ", "CRED_DISP", "CRED_REFR", "USER_ERR", "LOGIN"}


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _dehex(value: str) -> str:
    """auditd hex-encodes values containing spaces/quotes/control characters."""
    if value and len(value) >= 4 and len(value) % 2 == 0 and _HEX.match(value):
        try:
            return bytes.fromhex(value).decode("utf-8").replace("\x00", " ").strip()
        except (ValueError, UnicodeDecodeError):
            return value
    return value


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, raw in _KV.findall(text):
        value = _unquote(raw)
        if key in _HEX_FIELDS:
            value = _dehex(value)
        out[key] = value
    return out


def _clean(value: str | None) -> str | None:
    if value in (None, "", "?", "(none)", "unset", "4294967295"):
        return None
    return value


@register("auditd")
def parse(raw: str, meta: dict) -> dict | None:
    m = _HEAD.match(raw.strip())
    if not m:
        return None
    rtype = m.group("type")
    doc = base_doc(raw, meta, "linux.auditd", "linux", "auditd")
    doc["event.dataset"] = "linux.auditd"
    doc["event.provider"] = "auditd"
    doc["host.os.type"] = doc.get("host.os.type") or "linux"
    set_ts(doc, float(m.group("ts")))
    doc["auditd.type"] = rtype
    doc["auditd.serial"] = to_int(m.group("serial"))
    if m.group("node"):
        doc["host.name"] = doc.get("host.name") or m.group("node").split(".")[0]

    kv = parse_kv(m.group("body"))
    inner: dict[str, str] = {}
    if "msg" in kv and "=" in kv["msg"]:
        inner = parse_kv(kv.pop("msg"))
    fields = {**kv, **inner}
    for key, value in fields.items():
        if value not in ("", None) and key not in ("msg",):
            doc[f"auditd.{key}"] = value

    # ---- common fields ----------------------------------------------------
    if _clean(fields.get("pid")):
        doc["process.pid"] = to_int(fields["pid"])
    if _clean(fields.get("ppid")):
        doc["process.parent.pid"] = to_int(fields["ppid"])
    if _clean(fields.get("uid")):
        doc["user.id"] = fields["uid"]
    if _clean(fields.get("auid")):
        doc["auditd.login_uid"] = fields["auid"]
    exe = _clean(fields.get("exe"))
    if exe:
        set_process_path(doc, "process", exe)
    comm = _clean(fields.get("comm"))
    if comm and not doc.get("process.name"):
        doc["process.name"] = comm.lower()
    if _clean(fields.get("key")):
        doc["auditd.key"] = fields["key"]
    term = _clean(fields.get("terminal")) or _clean(fields.get("tty"))
    if term:
        doc["auditd.terminal"] = term
    addr = _clean(fields.get("addr"))
    if addr:
        set_ip(doc, "source.ip", addr)
    elif _clean(fields.get("hostname")):
        doc["source.domain"] = fields["hostname"]
    res = (fields.get("res") or fields.get("success") or "").lower()
    if res in ("success", "yes"):
        doc["event.outcome"] = "success"
    elif res in ("failed", "no"):
        doc["event.outcome"] = "failure"
    acct = _clean(fields.get("acct"))

    # ---- per record type --------------------------------------------------
    if rtype == "SYSCALL":
        doc.update({"event.category": "process", "event.type": "info", "event.action": "auditd-syscall"})
        doc["auditd.syscall"] = fields.get("syscall")
        doc["message"] = f"auditd syscall {fields.get('syscall')} by {doc.get('process.name')} (key={fields.get('key')})"
    elif rtype == "EXECVE":
        args = [fields[k] for k in sorted((k for k in fields if re.fullmatch(r"a\d+", k)), key=lambda k: int(k[1:]))]
        args = [_dehex(a) for a in args]
        doc.update({"event.category": "process", "event.type": "start", "event.action": "process-executed"})
        if args:
            doc["process.args"] = args
            doc["process.command_line"] = " ".join(args)
            doc["process.name"] = args[0].rsplit("/", 1)[-1].lower()
        doc["message"] = "auditd execve: " + (doc.get("process.command_line") or "")
    elif rtype == "PROCTITLE":
        doc.update({"event.category": "process", "event.type": "info", "event.action": "auditd-proctitle"})
        if fields.get("proctitle"):
            doc["process.command_line"] = fields["proctitle"]
        doc["message"] = "auditd proctitle: " + (doc.get("process.command_line") or "")
    elif rtype == "USER_LOGIN":
        ok = doc.get("event.outcome") == "success"
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "logon-success" if ok else "logon-failed"})
        doc["user.name"] = acct or doc.get("user.name")
        if _clean(fields.get("id")):
            doc["user.id"] = fields["id"]
        if term == "ssh" or "sshd" in (exe or ""):
            doc["network.protocol"] = "ssh"
        doc["message"] = f"auditd login {'success' if ok else 'FAILED'}: {doc.get('user.name') or 'uid ' + str(doc.get('user.id'))} from {doc.get('source.ip') or doc.get('source.domain') or 'local'}"
    elif rtype in AUTH_TYPES:
        ok = doc.get("event.outcome") == "success"
        doc.update({"event.category": "authentication", "event.type": "start",
                    "event.action": ("auth-success" if ok else "auth-failed") if rtype == "USER_AUTH" else "auditd-" + rtype.lower().replace("_", "-")})
        doc["user.name"] = acct or doc.get("user.name")
        if "sshd" in (exe or ""):
            doc["network.protocol"] = "ssh"
        if rtype == "USER_AUTH" and not ok:
            doc["event.severity"] = "low"
        doc["message"] = f"auditd {rtype} {res or ''}: {doc.get('user.name')} from {doc.get('source.ip') or doc.get('source.domain') or 'local'} ({fields.get('op') or ''})"
    elif rtype in ("USER_START", "USER_END"):
        doc.update({"event.category": "session", "event.type": "start" if rtype == "USER_START" else "end",
                    "event.action": "session-started" if rtype == "USER_START" else "session-ended"})
        doc["user.name"] = acct or doc.get("user.name")
        doc["message"] = f"auditd session {'started' if rtype == 'USER_START' else 'ended'} for {doc.get('user.name')}"
    elif rtype == "USER_CMD":
        doc.update({"event.category": "process", "event.type": "start", "event.action": "sudo-command"})
        if fields.get("cmd"):
            doc["process.command_line"] = fields["cmd"]
            doc["process.name"] = fields["cmd"].split()[0].rsplit("/", 1)[-1].lower()
        if _clean(fields.get("cwd")):
            doc["process.working_directory"] = fields["cwd"]
        doc["user.effective.name"] = "root"
        doc["message"] = f"auditd sudo ({res or 'unknown'}): {doc.get('process.command_line')}"
    elif rtype in IAM_TYPES:
        etype, action = IAM_TYPES[rtype]
        doc.update({"event.category": "iam", "event.type": etype, "event.action": action, "event.severity": "low"})
        if acct:
            doc["user.target.name"] = acct
        if _clean(fields.get("id")):
            doc["user.target.id"] = fields["id"]
        doc["message"] = f"auditd {action}: {doc.get('user.target.name') or 'id ' + str(doc.get('user.target.id'))} ({fields.get('op') or ''})"
    elif rtype.startswith("ANOM_"):
        doc.update({"event.category": "intrusion_detection", "event.type": "info", "event.action": "auditd-anomaly", "event.severity": "medium"})
        doc["message"] = f"auditd anomaly {rtype}: {fields.get('op') or ''}"
    elif rtype in ("SERVICE_START", "SERVICE_STOP"):
        doc.update({"event.category": "host", "event.type": "start" if rtype == "SERVICE_START" else "end",
                    "event.action": "service-started" if rtype == "SERVICE_START" else "service-stopped"})
        doc["service.name"] = _clean(fields.get("unit"))
        doc["message"] = f"auditd {doc['event.action']}: {doc.get('service.name')}"
    elif rtype in ("CONFIG_CHANGE", "DAEMON_START", "DAEMON_END", "DAEMON_ABORT"):
        doc.update({"event.category": "configuration", "event.type": "change", "event.action": "auditd-" + rtype.lower().replace("_", "-"), "event.severity": "medium"})
        doc["message"] = f"auditd {rtype}: {fields.get('op') or fields.get('key') or ''}"
    elif rtype == "PATH":
        doc.update({"event.category": "file", "event.type": "access", "event.action": "auditd-path"})
        if fields.get("name"):
            doc["file.path"] = fields["name"]
        doc["message"] = f"auditd path: {fields.get('name')} ({fields.get('nametype')})"
    else:
        doc.update({"event.category": "host", "event.type": "info", "event.action": "auditd-" + rtype.lower().replace("_", "-")})
        doc["message"] = f"auditd {rtype}: {m.group('body')[:200]}"
    return doc
