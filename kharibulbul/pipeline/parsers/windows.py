"""Windows Event Log parser.

Input: the rendered XML of one event (what our agent ships from
``wevtutil``/``Get-WinEvent``) or an already-parsed dict with ``winlog.*``
fields.  Output: an ECS-style document.  Sysmon channel events are handed
to :mod:`sysmon` for field mapping.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from ...common.util import to_int
from . import register
from .base import base_doc, clean, set_file_path, set_ip, set_port, set_process_path, set_ts

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

LOGON_TYPES = {
    "2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
    "8": "network-cleartext", "9": "new-credentials", "10": "remote-interactive", "11": "cached-interactive",
}

# 4625 Status / SubStatus codes -> reason
LOGON_FAILURE_REASONS = {
    "0xc000006d": "bad username or password",
    "0xc000006a": "wrong password",
    "0xc0000064": "user does not exist",
    "0xc0000072": "account disabled",
    "0xc0000234": "account locked out",
    "0xc0000070": "workstation restriction",
    "0xc000006f": "outside allowed hours",
    "0xc0000193": "account expired",
    "0xc0000071": "password expired",
    "0xc000015b": "logon type not granted",
    "0xc0000133": "clock skew",
}

CHANNEL_DATASET = {
    "security": "windows.security",
    "system": "windows.system",
    "application": "windows.application",
    "microsoft-windows-sysmon/operational": "windows.sysmon",
    "microsoft-windows-powershell/operational": "windows.powershell",
    "windows powershell": "windows.powershell",
    "microsoft-windows-windows defender/operational": "windows.defender",
    "microsoft-windows-taskscheduler/operational": "windows.taskscheduler",
    "microsoft-windows-terminalservices-localsessionmanager/operational": "windows.rdp",
    "microsoft-windows-windows firewall with advanced security/firewall": "windows.firewall",
    "microsoft-windows-dns-client/operational": "windows.dns",
}


# --------------------------------------------------------------------------- #
# XML -> raw winlog dict
# --------------------------------------------------------------------------- #

def parse_xml(raw: str) -> dict | None:
    text = raw.strip()
    if not text.startswith("<"):
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # some renderers emit events without a namespace or with stray chars
        try:
            root = ET.fromstring(text[text.index("<Event"):])
        except (ValueError, ET.ParseError):
            return None
    tag = root.tag.replace(NS, "")
    if tag != "Event":
        return None
    ns = NS if root.tag.startswith(NS) else ""
    system = root.find(f"{ns}System")
    if system is None:
        return None

    def sys_text(name: str) -> str | None:
        el = system.find(f"{ns}{name}")
        return el.text.strip() if el is not None and el.text else None

    win: dict[str, Any] = {}
    provider = system.find(f"{ns}Provider")
    if provider is not None:
        win["provider_name"] = provider.get("Name")
        win["provider_guid"] = provider.get("Guid")
    win["event_id"] = sys_text("EventID")
    win["version"] = sys_text("Version")
    win["level"] = sys_text("Level")
    win["task"] = sys_text("Task")
    win["opcode"] = sys_text("Opcode")
    win["keywords"] = sys_text("Keywords")
    tc = system.find(f"{ns}TimeCreated")
    if tc is not None:
        win["time_created"] = tc.get("SystemTime")
    win["record_id"] = sys_text("EventRecordID")
    ex = system.find(f"{ns}Execution")
    if ex is not None:
        win["process.pid"] = to_int(ex.get("ProcessID"))
        win["process.thread.id"] = to_int(ex.get("ThreadID"))
    win["channel"] = sys_text("Channel")
    win["computer_name"] = sys_text("Computer")
    sec = system.find(f"{ns}Security")
    if sec is not None and sec.get("UserID"):
        win["user.identifier"] = sec.get("UserID")

    event_data: dict[str, Any] = {}
    ed = root.find(f"{ns}EventData")
    if ed is not None:
        unnamed = 0
        for data in ed:
            name = data.get("Name")
            if not name:
                unnamed += 1
                name = f"param{unnamed}"
            value = (data.text or "").strip()
            if data.tag.replace(ns, "") == "Binary":
                name = "Binary"
            event_data[name] = value
    ud = root.find(f"{ns}UserData")
    if ud is not None:
        for child in ud.iter():
            if child is ud:
                continue
            name = child.tag.split("}")[-1]
            if child.text and child.text.strip() and name not in event_data:
                event_data[name] = child.text.strip()
    win["event_data"] = event_data

    ri = root.find(f"{ns}RenderingInfo")
    if ri is not None:
        msg = ri.find(f"{ns}Message")
        if msg is not None and msg.text:
            win["message"] = msg.text.strip()
        for name in ("Level", "Task", "Opcode", "Channel", "Provider"):
            el = ri.find(f"{ns}{name}")
            if el is not None and el.text:
                win[f"rendered_{name.lower()}"] = el.text.strip()
    return win


# --------------------------------------------------------------------------- #
# Generic winlog -> ECS mapping
# --------------------------------------------------------------------------- #

def _dataset_for(channel: str | None, provider: str | None) -> str:
    ch = (channel or "").lower()
    if ch in CHANNEL_DATASET:
        return CHANNEL_DATASET[ch]
    if "sysmon" in ch or "sysmon" in (provider or "").lower():
        return "windows.sysmon"
    if "powershell" in ch:
        return "windows.powershell"
    if "defender" in ch:
        return "windows.defender"
    return "windows." + re.sub(r"[^a-z0-9]+", "_", ch).strip("_") if ch else "windows.generic"


def _level_name(level: str | None) -> str:
    return {"1": "critical", "2": "error", "3": "warning", "4": "info", "5": "verbose", "0": "info"}.get(level or "4", "info")


def winlog_to_doc(win: dict, raw: str, meta: dict) -> dict:
    channel = win.get("channel")
    provider = win.get("provider_name")
    dataset = _dataset_for(channel, provider)
    doc = base_doc(raw, meta, dataset, "windows", "windows")
    doc["event.dataset"] = dataset  # channel wins over the shipper's hint
    set_ts(doc, win.get("time_created"))
    doc["event.code"] = str(win.get("event_id") or "")
    doc["event.provider"] = provider
    doc["winlog.channel"] = channel
    doc["winlog.provider_name"] = provider
    doc["winlog.record_id"] = to_int(win.get("record_id"))
    doc["winlog.computer_name"] = win.get("computer_name")
    doc["winlog.task"] = win.get("rendered_task") or win.get("task")
    doc["winlog.keywords"] = win.get("keywords")
    doc["log.level"] = _level_name(win.get("level"))
    doc["host.os.type"] = "windows"
    if win.get("computer_name") and not doc.get("host.name"):
        doc["host.name"] = str(win["computer_name"]).split(".")[0]
    if win.get("message"):
        doc["message"] = win["message"]
    ed: dict = win.get("event_data") or {}
    for k, v in ed.items():
        if v not in (None, ""):
            doc[f"winlog.event_data.{k}"] = v

    code = doc["event.code"]
    if dataset == "windows.sysmon":
        from .sysmon import map_sysmon
        map_sysmon(doc, code, ed)
    elif dataset == "windows.security":
        _map_security(doc, code, ed)
    elif dataset == "windows.system":
        _map_system(doc, code, ed)
    elif dataset == "windows.powershell":
        _map_powershell(doc, code, ed)
    elif dataset == "windows.defender":
        _map_defender(doc, code, ed)
    elif dataset == "windows.taskscheduler":
        _map_taskscheduler(doc, code, ed)
    elif dataset == "windows.rdp":
        _map_rdp(doc, code, ed)
    if "message" not in doc:
        doc["message"] = f"{provider} EventID {code}"
    return doc


def _subject(doc: dict, ed: dict) -> None:
    doc["user.name"] = clean(ed.get("SubjectUserName"))
    doc["user.domain"] = clean(ed.get("SubjectDomainName"))
    doc["user.id"] = clean(ed.get("SubjectUserSid"))
    doc["winlog.logon.id"] = clean(ed.get("SubjectLogonId"))


def _target_user(doc: dict, ed: dict) -> None:
    doc["user.target.name"] = clean(ed.get("TargetUserName"))
    doc["user.target.domain"] = clean(ed.get("TargetDomainName"))
    doc["user.target.id"] = clean(ed.get("TargetUserSid") or ed.get("TargetSid"))


def _map_security(doc: dict, code: str, ed: dict) -> None:
    doc["event.provider"] = doc.get("event.provider") or "Microsoft-Windows-Security-Auditing"
    if code == "4624":
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "logon-success", "event.outcome": "success"})
        _subject(doc, ed)
        _target_user(doc, ed)
        doc["user.name"] = clean(ed.get("TargetUserName")) or doc.get("user.name")
        doc["user.domain"] = clean(ed.get("TargetDomainName")) or doc.get("user.domain")
        lt = clean(ed.get("LogonType"))
        doc["winlog.logon.type"] = LOGON_TYPES.get(lt or "", lt)
        doc["winlog.logon.id"] = clean(ed.get("TargetLogonId"))
        set_ip(doc, "source.ip", ed.get("IpAddress"))
        set_port(doc, "source.port", ed.get("IpPort"))
        doc["source.domain"] = clean(ed.get("WorkstationName"))
        set_process_path(doc, "process", ed.get("ProcessName"))
        doc["winlog.logon.auth_package"] = clean(ed.get("AuthenticationPackageName"))
        doc["winlog.logon.elevated"] = clean(ed.get("ElevatedToken"))
        doc["message"] = f"Logon success: {doc.get('user.domain','')}\\{doc.get('user.name','?')} type={doc.get('winlog.logon.type')} from {doc.get('source.ip','local')}"
    elif code == "4625":
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "logon-failed", "event.outcome": "failure"})
        _subject(doc, ed)
        _target_user(doc, ed)
        doc["user.name"] = clean(ed.get("TargetUserName")) or doc.get("user.name")
        doc["user.domain"] = clean(ed.get("TargetDomainName")) or doc.get("user.domain")
        lt = clean(ed.get("LogonType"))
        doc["winlog.logon.type"] = LOGON_TYPES.get(lt or "", lt)
        set_ip(doc, "source.ip", ed.get("IpAddress"))
        set_port(doc, "source.port", ed.get("IpPort"))
        doc["source.domain"] = clean(ed.get("WorkstationName"))
        set_process_path(doc, "process", ed.get("ProcessName"))
        status = (clean(ed.get("SubStatus")) or clean(ed.get("Status")) or "").lower()
        doc["winlog.logon.failure.status"] = status
        doc["winlog.logon.failure.reason"] = LOGON_FAILURE_REASONS.get(status, clean(ed.get("FailureReason")))
        doc["event.severity"] = "low"
        doc["message"] = f"Logon FAILED: {doc.get('user.domain','')}\\{doc.get('user.name','?')} type={doc.get('winlog.logon.type')} from {doc.get('source.ip','local')} ({doc.get('winlog.logon.failure.reason','')})"
    elif code in ("4634", "4647"):
        doc.update({"event.category": "authentication", "event.type": "end", "event.action": "logoff", "event.outcome": "success"})
        _target_user(doc, ed)
        doc["user.name"] = clean(ed.get("TargetUserName"))
        doc["user.domain"] = clean(ed.get("TargetDomainName"))
        doc["message"] = f"Logoff: {doc.get('user.name','?')}"
    elif code == "4648":
        doc.update({"event.category": "authentication", "event.type": "start", "event.action": "logon-explicit-credentials", "event.outcome": "success"})
        _subject(doc, ed)
        _target_user(doc, ed)
        doc["destination.domain"] = clean(ed.get("TargetServerName"))
        set_ip(doc, "source.ip", ed.get("IpAddress"))
        set_process_path(doc, "process", ed.get("ProcessName"))
        doc["message"] = f"Explicit credentials: {doc.get('user.name')} used {doc.get('user.target.name')} on {doc.get('destination.domain')}"
    elif code == "4672":
        doc.update({"event.category": "iam", "event.type": "admin", "event.action": "special-privileges-assigned", "event.outcome": "success"})
        _subject(doc, ed)
        doc["winlog.privileges"] = clean(ed.get("PrivilegeList"))
        doc["message"] = f"Special privileges assigned to {doc.get('user.name')}"
    elif code == "4688":
        doc.update({"event.category": "process", "event.type": "start", "event.action": "process-created", "event.outcome": "success"})
        _subject(doc, ed)
        doc["process.pid"] = to_int(ed.get("NewProcessId"))
        set_process_path(doc, "process", ed.get("NewProcessName"))
        doc["process.command_line"] = clean(ed.get("CommandLine"))
        doc["process.parent.pid"] = to_int(ed.get("ProcessId"))
        set_process_path(doc, "process.parent", ed.get("ParentProcessName"))
        doc["process.integrity_level"] = clean(ed.get("MandatoryLabel"))
        doc["winlog.token_elevation"] = clean(ed.get("TokenElevationType"))
        doc["message"] = f"Process created: {doc.get('process.executable')} {doc.get('process.command_line') or ''}".strip()
    elif code == "4689":
        doc.update({"event.category": "process", "event.type": "end", "event.action": "process-terminated", "event.outcome": "success"})
        _subject(doc, ed)
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        set_process_path(doc, "process", ed.get("ProcessName"))
    elif code == "4697":
        doc.update({"event.category": "configuration", "event.type": "creation", "event.action": "service-installed", "event.outcome": "success", "event.severity": "medium"})
        _subject(doc, ed)
        doc["service.name"] = clean(ed.get("ServiceName"))
        doc["service.path"] = clean(ed.get("ServiceFileName"))
        doc["service.type"] = clean(ed.get("ServiceType"))
        doc["service.start_type"] = clean(ed.get("ServiceStartType"))
        doc["service.account"] = clean(ed.get("ServiceAccount"))
        doc["message"] = f"Service installed: {doc.get('service.name')} -> {doc.get('service.path')}"
    elif code in ("4698", "4699", "4700", "4701", "4702"):
        action = {"4698": "scheduled-task-created", "4699": "scheduled-task-deleted", "4700": "scheduled-task-enabled",
                  "4701": "scheduled-task-disabled", "4702": "scheduled-task-updated"}[code]
        doc.update({"event.category": "configuration", "event.type": "change", "event.action": action, "event.outcome": "success", "event.severity": "low"})
        _subject(doc, ed)
        doc["winlog.task.name"] = clean(ed.get("TaskName"))
        content = clean(ed.get("TaskContent"))
        if content:
            doc["winlog.task.content"] = content[:4000]
            m = re.search(r"<Command>(.*?)</Command>", content, re.S | re.I)
            if m:
                doc["process.command_line"] = m.group(1).strip()
                args = re.search(r"<Arguments>(.*?)</Arguments>", content, re.S | re.I)
                if args:
                    doc["process.command_line"] += " " + args.group(1).strip()
        doc["message"] = f"{action}: {doc.get('winlog.task.name')} by {doc.get('user.name')}"
    elif code in ("4720", "4722", "4723", "4724", "4725", "4726", "4738", "4767", "4781"):
        action = {"4720": "user-created", "4722": "user-enabled", "4723": "user-password-change", "4724": "user-password-reset",
                  "4725": "user-disabled", "4726": "user-deleted", "4738": "user-changed", "4767": "user-unlocked", "4781": "user-renamed"}[code]
        doc.update({"event.category": "iam", "event.type": "user", "event.action": action, "event.outcome": "success", "event.severity": "low"})
        _subject(doc, ed)
        _target_user(doc, ed)
        doc["message"] = f"{action}: {doc.get('user.target.name')} by {doc.get('user.name')}"
    elif code in ("4728", "4732", "4756", "4729", "4733", "4757"):
        added = code in ("4728", "4732", "4756")
        doc.update({"event.category": "iam", "event.type": "group", "event.action": "group-member-added" if added else "group-member-removed",
                    "event.outcome": "success", "event.severity": "medium" if added else "low"})
        _subject(doc, ed)
        doc["group.name"] = clean(ed.get("TargetUserName"))
        doc["group.domain"] = clean(ed.get("TargetDomainName"))
        member = clean(ed.get("MemberName")) or clean(ed.get("MemberSid"))
        doc["user.target.name"] = member.split(",")[0].replace("CN=", "") if member else None
        doc["message"] = f"{doc['event.action']}: {doc.get('user.target.name')} -> {doc.get('group.name')} by {doc.get('user.name')}"
    elif code == "4740":
        doc.update({"event.category": "iam", "event.type": "user", "event.action": "user-locked-out", "event.outcome": "success", "event.severity": "medium"})
        _subject(doc, ed)
        _target_user(doc, ed)
        doc["source.domain"] = clean(ed.get("TargetDomainName"))
        doc["message"] = f"Account locked out: {doc.get('user.target.name')} from {doc.get('source.domain')}"
    elif code in ("4768", "4769", "4771", "4776"):
        failed = code == "4771" or (clean(ed.get("Status")) not in (None, "0x0"))
        doc.update({"event.category": "authentication", "event.type": "start",
                    "event.action": {"4768": "kerberos-tgt-request", "4769": "kerberos-service-ticket", "4771": "kerberos-preauth-failed", "4776": "ntlm-authentication"}[code],
                    "event.outcome": "failure" if failed else "success"})
        doc["user.name"] = clean(ed.get("TargetUserName"))
        doc["user.domain"] = clean(ed.get("TargetDomainName"))
        set_ip(doc, "source.ip", ed.get("IpAddress"))
        doc["source.domain"] = clean(ed.get("Workstation"))
        doc["winlog.logon.failure.status"] = (clean(ed.get("Status")) or "").lower()
        doc["message"] = f"{doc['event.action']} {doc['event.outcome']}: {doc.get('user.name')} from {doc.get('source.ip') or doc.get('source.domain')}"
    elif code == "1102":
        doc.update({"event.category": "configuration", "event.type": "deletion", "event.action": "audit-log-cleared", "event.outcome": "success", "event.severity": "high"})
        _subject(doc, ed)
        doc["message"] = f"Security audit log CLEARED by {doc.get('user.name')}"
    elif code == "4719":
        doc.update({"event.category": "configuration", "event.type": "change", "event.action": "audit-policy-changed", "event.outcome": "success", "event.severity": "medium"})
        _subject(doc, ed)
        doc["message"] = f"Audit policy changed by {doc.get('user.name')}: {clean(ed.get('AuditPolicyChanges'))}"
    elif code in ("5140", "5145"):
        doc.update({"event.category": "file", "event.type": "access", "event.action": "network-share-accessed", "event.outcome": "success"})
        _subject(doc, ed)
        set_ip(doc, "source.ip", ed.get("IpAddress"))
        set_port(doc, "source.port", ed.get("IpPort"))
        doc["file.path"] = clean(ed.get("ShareName"))
        doc["file.name"] = clean(ed.get("RelativeTargetName"))
        doc["message"] = f"Share access: {doc.get('user.name')} -> {doc.get('file.path')} {doc.get('file.name') or ''}"
    elif code in ("5156", "5157", "5158", "5152"):
        allowed = code in ("5156", "5158")
        doc.update({"event.category": "network", "event.type": "allowed" if allowed else "denied",
                    "event.action": "wfp-connection-allowed" if allowed else "wfp-connection-blocked",
                    "event.outcome": "success" if allowed else "failure"})
        set_process_path(doc, "process", ed.get("Application"))
        doc["process.pid"] = to_int(ed.get("ProcessID") or ed.get("ProcessId"))
        direction = clean(ed.get("Direction"))
        doc["network.direction"] = {"%%14592": "inbound", "%%14593": "outbound"}.get(direction or "", direction)
        set_ip(doc, "source.ip", ed.get("SourceAddress"))
        set_port(doc, "source.port", ed.get("SourcePort"))
        set_ip(doc, "destination.ip", ed.get("DestAddress"))
        set_port(doc, "destination.port", ed.get("DestPort"))
        proto = to_int(ed.get("Protocol"))
        doc["network.transport"] = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto, str(proto) if proto is not None else None)
        doc["message"] = f"WFP {doc['event.type']}: {doc.get('source.ip')}:{doc.get('source.port')} -> {doc.get('destination.ip')}:{doc.get('destination.port')} {doc.get('network.transport')}"
    else:
        doc["event.category"] = "host"
        doc["event.type"] = "info"
        doc["event.action"] = f"security-{code}"
        _subject(doc, ed)


def _map_system(doc: dict, code: str, ed: dict) -> None:
    provider = (doc.get("event.provider") or "").lower()
    if code == "7045" and "service control manager" in provider:
        doc.update({"event.category": "configuration", "event.type": "creation", "event.action": "service-installed", "event.outcome": "success", "event.severity": "medium"})
        doc["service.name"] = clean(ed.get("ServiceName"))
        doc["service.path"] = clean(ed.get("ImagePath"))
        doc["service.type"] = clean(ed.get("ServiceType"))
        doc["service.start_type"] = clean(ed.get("StartType"))
        doc["service.account"] = clean(ed.get("AccountName"))
        if doc.get("service.path"):
            doc["process.command_line"] = doc["service.path"]
        doc["message"] = f"Service installed: {doc.get('service.name')} -> {doc.get('service.path')}"
    elif code == "7036" and "service control manager" in provider:
        doc.update({"event.category": "host", "event.type": "change", "event.action": "service-state-changed", "event.outcome": "success"})
        doc["service.name"] = clean(ed.get("param1"))
        doc["service.state"] = clean(ed.get("param2"))
        doc["message"] = f"Service {doc.get('service.name')} entered {doc.get('service.state')}"
    elif code == "7040" and "service control manager" in provider:
        doc.update({"event.category": "configuration", "event.type": "change", "event.action": "service-start-type-changed", "event.outcome": "success"})
        doc["service.name"] = clean(ed.get("param1"))
        doc["message"] = f"Service start type changed: {doc.get('service.name')} {clean(ed.get('param2'))} -> {clean(ed.get('param3'))}"
    elif code == "104":
        doc.update({"event.category": "configuration", "event.type": "deletion", "event.action": "event-log-cleared", "event.outcome": "success", "event.severity": "high"})
        doc["user.name"] = clean(ed.get("SubjectUserName"))
        doc["user.domain"] = clean(ed.get("SubjectDomainName"))
        doc["winlog.cleared_channel"] = clean(ed.get("Channel"))
        doc["message"] = f"Event log '{doc.get('winlog.cleared_channel')}' cleared by {doc.get('user.name')}"
    elif code in ("1074", "6005", "6006", "6008", "41"):
        doc.update({"event.category": "host", "event.type": "info", "event.outcome": "success",
                    "event.action": {"1074": "system-shutdown-initiated", "6005": "eventlog-started", "6006": "eventlog-stopped",
                                     "6008": "unexpected-shutdown", "41": "kernel-power-unexpected-reboot"}[code]})
        if code == "1074":
            doc["user.name"] = clean(ed.get("param7"))
            doc["process.name"] = (clean(ed.get("param1")) or "").split("\\")[-1].lower() or None
    else:
        doc.update({"event.category": "host", "event.type": "info", "event.action": f"system-{code}"})


def _map_powershell(doc: dict, code: str, ed: dict) -> None:
    if code == "4104":
        doc.update({"event.category": "process", "event.type": "info", "event.action": "powershell-scriptblock", "event.outcome": "success"})
        doc["powershell.file.script_block_text"] = (clean(ed.get("ScriptBlockText")) or "")[:8000]
        doc["powershell.file.script_block_id"] = clean(ed.get("ScriptBlockId"))
        doc["file.path"] = clean(ed.get("Path"))
        doc["process.command_line"] = doc["powershell.file.script_block_text"][:4000]
        doc["message"] = "PowerShell script block: " + doc["powershell.file.script_block_text"][:300]
    elif code == "4103":
        doc.update({"event.category": "process", "event.type": "info", "event.action": "powershell-module-logging", "event.outcome": "success"})
        doc["powershell.payload"] = (clean(ed.get("Payload")) or "")[:4000]
        doc["message"] = "PowerShell module log: " + doc["powershell.payload"][:300]
    elif code in ("400", "403", "600"):
        doc.update({"event.category": "process", "event.type": "info", "event.action": "powershell-engine-state", "event.outcome": "success"})
    else:
        doc.update({"event.category": "process", "event.type": "info", "event.action": f"powershell-{code}"})


def _map_defender(doc: dict, code: str, ed: dict) -> None:
    if code in ("1116", "1117", "1118", "1119", "1006", "1007", "1008", "1015", "1116"):
        doc.update({"event.category": "malware", "event.type": "info", "event.action": "defender-threat-detected" if code in ("1116", "1006", "1015") else "defender-threat-action",
                    "event.outcome": "success", "event.severity": "high"})
        doc["threat.name"] = clean(ed.get("Threat Name") or ed.get("ThreatName"))
        doc["threat.severity"] = clean(ed.get("Severity Name") or ed.get("SeverityName"))
        set_file_path(doc, (clean(ed.get("Path")) or "").replace("file:_", ""))
        doc["user.name"] = clean(ed.get("Detection User") or ed.get("User"))
        doc["process.name"] = (clean(ed.get("Process Name")) or "").split("\\")[-1].lower() or None
        doc["message"] = f"Defender: {doc.get('threat.name')} ({doc.get('threat.severity')}) in {doc.get('file.path')}"
    elif code in ("5001", "5010", "5012", "5004"):
        doc.update({"event.category": "configuration", "event.type": "change", "event.action": "defender-protection-changed", "event.outcome": "success", "event.severity": "high"})
        doc["message"] = f"Defender protection state changed (EventID {code})"
    else:
        doc.update({"event.category": "malware", "event.type": "info", "event.action": f"defender-{code}"})


def _map_taskscheduler(doc: dict, code: str, ed: dict) -> None:
    doc.update({"event.category": "configuration", "event.type": "info", "event.action": f"taskscheduler-{code}", "event.outcome": "success"})
    doc["winlog.task.name"] = clean(ed.get("TaskName"))
    doc["user.name"] = clean(ed.get("UserContext") or ed.get("UserName"))
    if code == "106":
        doc["event.action"] = "scheduled-task-registered"
    elif code in ("200", "129"):
        doc["event.action"] = "scheduled-task-started"
        doc["process.executable"] = clean(ed.get("ActionName") or ed.get("Path"))


def _map_rdp(doc: dict, code: str, ed: dict) -> None:
    doc.update({"event.category": "session", "event.type": "info", "event.outcome": "success",
                "event.action": {"21": "rdp-logon-success", "22": "rdp-shell-start", "23": "rdp-logoff", "24": "rdp-disconnected", "25": "rdp-reconnected"}.get(code, f"rdp-{code}")})
    doc["user.name"] = clean(ed.get("User"))
    set_ip(doc, "source.ip", ed.get("Address"))
    doc["winlog.session_id"] = clean(ed.get("SessionID"))


# --------------------------------------------------------------------------- #
# Parser entry points
# --------------------------------------------------------------------------- #

@register("windows")
def parse(raw: str, meta: dict) -> dict | None:
    win = parse_xml(raw)
    if win is None:
        return None
    return winlog_to_doc(win, raw, meta)


def parse_winlog_dict(win: dict, raw: str, meta: dict) -> dict:
    """Used by the JSON parser when a shipper sends pre-parsed winlog fields."""
    return winlog_to_doc(win, raw, meta)
