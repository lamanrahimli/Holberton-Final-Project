"""Sysmon (Microsoft-Windows-Sysmon/Operational) field mapping to ECS."""
from __future__ import annotations

from ...common.util import to_int
from .base import clean, set_file_path, set_ip, set_port, set_process_path, split_hashes

SYSMON_EVENTS = {
    "1": "process-created", "2": "file-time-changed", "3": "network-connection", "4": "sysmon-state-changed",
    "5": "process-terminated", "6": "driver-loaded", "7": "image-loaded", "8": "remote-thread-created",
    "9": "raw-disk-access", "10": "process-accessed", "11": "file-created", "12": "registry-key-changed",
    "13": "registry-value-set", "14": "registry-key-renamed", "15": "file-stream-created", "16": "sysmon-config-changed",
    "17": "pipe-created", "18": "pipe-connected", "19": "wmi-filter", "20": "wmi-consumer", "21": "wmi-binding",
    "22": "dns-query", "23": "file-deleted", "24": "clipboard-changed", "25": "process-tampering",
    "26": "file-delete-detected", "27": "file-block-executable", "28": "file-block-shredding", "29": "file-executable-detected",
    "255": "sysmon-error",
}

CATEGORY = {
    "1": ("process", "start"), "2": ("file", "change"), "3": ("network", "connection"), "5": ("process", "end"),
    "6": ("driver", "start"), "7": ("process", "info"), "8": ("process", "access"), "9": ("file", "access"),
    "10": ("process", "access"), "11": ("file", "creation"), "12": ("registry", "change"), "13": ("registry", "change"),
    "14": ("registry", "change"), "15": ("file", "creation"), "17": ("file", "creation"), "18": ("file", "access"),
    "19": ("configuration", "creation"), "20": ("configuration", "creation"), "21": ("configuration", "creation"),
    "22": ("network", "protocol"), "23": ("file", "deletion"), "25": ("process", "change"), "26": ("file", "deletion"),
    "27": ("file", "denied"), "28": ("file", "denied"), "29": ("file", "creation"),
}


def _user(doc: dict, value) -> None:
    value = clean(value)
    if not value:
        return
    if "\\" in value:
        domain, name = value.split("\\", 1)
        doc["user.domain"] = domain
        doc["user.name"] = name
    else:
        doc["user.name"] = value


def map_sysmon(doc: dict, code: str, ed: dict) -> None:
    doc["event.dataset"] = "windows.sysmon"
    doc["event.module"] = "windows"  # module = dataset prefix, so `logsource: {module: windows}` covers Security + Sysmon
    doc["event.provider"] = "Microsoft-Windows-Sysmon"
    doc["event.action"] = SYSMON_EVENTS.get(code, f"sysmon-{code}")
    cat, typ = CATEGORY.get(code, ("host", "info"))
    doc["event.category"] = cat
    doc["event.type"] = typ
    doc["event.outcome"] = "success"
    if ed.get("RuleName") and ed["RuleName"] != "-":
        doc["rule.ruleset"] = "sysmon"
        doc["sysmon.rule_name"] = ed["RuleName"]
    if ed.get("UtcTime"):
        from .base import set_ts
        set_ts(doc, ed["UtcTime"].replace(" ", "T") + "Z" if "T" not in ed["UtcTime"] else ed["UtcTime"])

    if code == "1":
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        doc["process.entity_id"] = clean(ed.get("ProcessGuid"))
        set_process_path(doc, "process", ed.get("Image"))
        doc["process.command_line"] = clean(ed.get("CommandLine"))
        doc["process.working_directory"] = clean(ed.get("CurrentDirectory"))
        doc["process.integrity_level"] = clean(ed.get("IntegrityLevel"))
        doc["process.pe.original_file_name"] = clean(ed.get("OriginalFileName"))
        doc["process.pe.company"] = clean(ed.get("Company"))
        doc["process.pe.description"] = clean(ed.get("Description"))
        doc["process.pe.product"] = clean(ed.get("Product"))
        _user(doc, ed.get("User"))
        hashes = split_hashes(ed.get("Hashes"))
        for algo in ("md5", "sha1", "sha256", "imphash"):
            if algo in hashes:
                doc[f"process.hash.{algo}"] = hashes[algo]
        doc["process.parent.pid"] = to_int(ed.get("ParentProcessId"))
        doc["process.parent.entity_id"] = clean(ed.get("ParentProcessGuid"))
        set_process_path(doc, "process.parent", ed.get("ParentImage"))
        doc["process.parent.command_line"] = clean(ed.get("ParentCommandLine"))
        parent_user = clean(ed.get("ParentUser"))
        if parent_user:
            doc["process.parent.user.name"] = parent_user.split("\\")[-1]
        doc["winlog.logon.id"] = clean(ed.get("LogonId"))
        doc["message"] = f"Process created: {doc.get('process.command_line') or doc.get('process.executable')} (parent {doc.get('process.parent.name')})"
    elif code == "3":
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        doc["process.entity_id"] = clean(ed.get("ProcessGuid"))
        set_process_path(doc, "process", ed.get("Image"))
        _user(doc, ed.get("User"))
        doc["network.transport"] = (clean(ed.get("Protocol")) or "").lower() or None
        initiated = (clean(ed.get("Initiated")) or "").lower()
        doc["network.direction"] = "outbound" if initiated == "true" else ("inbound" if initiated == "false" else None)
        set_ip(doc, "source.ip", ed.get("SourceIp"))
        set_port(doc, "source.port", ed.get("SourcePort"))
        doc["source.domain"] = clean(ed.get("SourceHostname"))
        set_ip(doc, "destination.ip", ed.get("DestinationIp"))
        set_port(doc, "destination.port", ed.get("DestinationPort"))
        doc["destination.domain"] = clean(ed.get("DestinationHostname"))
        doc["network.protocol"] = (clean(ed.get("DestinationPortName")) or "").lower() or None
        doc["network.type"] = "ipv6" if (clean(ed.get("DestinationIsIpv6")) or "").lower() == "true" else "ipv4"
        doc["message"] = f"Network {doc.get('network.direction')}: {doc.get('process.name')} {doc.get('source.ip')}:{doc.get('source.port')} -> {doc.get('destination.ip')}:{doc.get('destination.port')}/{doc.get('network.transport')}"
    elif code == "5":
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        doc["process.entity_id"] = clean(ed.get("ProcessGuid"))
        set_process_path(doc, "process", ed.get("Image"))
        _user(doc, ed.get("User"))
        doc["message"] = f"Process terminated: {doc.get('process.executable')}"
    elif code in ("6", "7"):
        set_process_path(doc, "process", ed.get("Image"))
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        set_file_path(doc, ed.get("ImageLoaded"))
        doc["dll.path"] = clean(ed.get("ImageLoaded"))
        doc["dll.name"] = doc.get("file.name")
        hashes = split_hashes(ed.get("Hashes"))
        if "sha256" in hashes:
            doc["file.hash.sha256"] = hashes["sha256"]
        doc["file.code_signature.signed"] = (clean(ed.get("Signed")) or "").lower() == "true"
        doc["file.code_signature.subject_name"] = clean(ed.get("Signature"))
        doc["file.code_signature.status"] = clean(ed.get("SignatureStatus"))
        doc["message"] = f"{'Driver' if code == '6' else 'Image'} loaded: {doc.get('file.path')} by {doc.get('process.name')}"
    elif code == "8":
        set_process_path(doc, "process", ed.get("SourceImage"))
        doc["process.pid"] = to_int(ed.get("SourceProcessId"))
        doc["process.entity_id"] = clean(ed.get("SourceProcessGuid"))
        set_process_path(doc, "process.target", ed.get("TargetImage"))
        doc["process.target.pid"] = to_int(ed.get("TargetProcessId"))
        doc["sysmon.start_address"] = clean(ed.get("StartAddress"))
        doc["sysmon.start_function"] = clean(ed.get("StartFunction"))
        _user(doc, ed.get("SourceUser"))
        doc["message"] = f"Remote thread: {doc.get('process.name')} -> {doc.get('process.target.name')}"
    elif code == "10":
        set_process_path(doc, "process", ed.get("SourceImage"))
        doc["process.pid"] = to_int(ed.get("SourceProcessId"))
        set_process_path(doc, "process.target", ed.get("TargetImage"))
        doc["process.target.pid"] = to_int(ed.get("TargetProcessId"))
        doc["sysmon.granted_access"] = (clean(ed.get("GrantedAccess")) or "").lower()
        doc["sysmon.call_trace"] = clean(ed.get("CallTrace"))
        _user(doc, ed.get("SourceUser"))
        doc["message"] = f"Process access: {doc.get('process.name')} -> {doc.get('process.target.name')} ({doc.get('sysmon.granted_access')})"
    elif code in ("11", "23", "26", "29", "27", "28", "2"):
        set_process_path(doc, "process", ed.get("Image"))
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        doc["process.entity_id"] = clean(ed.get("ProcessGuid"))
        set_file_path(doc, ed.get("TargetFilename"))
        _user(doc, ed.get("User"))
        hashes = split_hashes(ed.get("Hashes"))
        if "sha256" in hashes:
            doc["file.hash.sha256"] = hashes["sha256"]
        doc["message"] = f"{doc['event.action']}: {doc.get('file.path')} by {doc.get('process.name')}"
    elif code in ("12", "13", "14"):
        set_process_path(doc, "process", ed.get("Image"))
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        doc["registry.path"] = clean(ed.get("TargetObject"))
        if doc.get("registry.path"):
            doc["registry.value"] = doc["registry.path"].rsplit("\\", 1)[-1]
            hive = doc["registry.path"].split("\\", 1)[0]
            doc["registry.hive"] = hive
        doc["registry.data.strings"] = clean(ed.get("Details"))
        doc["registry.new_name"] = clean(ed.get("NewName"))
        doc["sysmon.event_type"] = clean(ed.get("EventType"))
        _user(doc, ed.get("User"))
        doc["message"] = f"Registry {doc.get('sysmon.event_type')}: {doc.get('registry.path')} = {doc.get('registry.data.strings') or ''} by {doc.get('process.name')}"
    elif code == "15":
        set_process_path(doc, "process", ed.get("Image"))
        set_file_path(doc, ed.get("TargetFilename"))
        doc["file.hash.sha256"] = split_hashes(ed.get("Hash")).get("sha256")
        doc["sysmon.stream_contents"] = (clean(ed.get("Contents")) or "")[:1000]
        doc["message"] = f"Alternate data stream created: {doc.get('file.path')}"
    elif code in ("17", "18"):
        set_process_path(doc, "process", ed.get("Image"))
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        doc["file.name"] = clean(ed.get("PipeName"))
        doc["message"] = f"Named pipe {'created' if code == '17' else 'connected'}: {doc.get('file.name')} by {doc.get('process.name')}"
    elif code in ("19", "20", "21"):
        doc["sysmon.wmi.operation"] = clean(ed.get("Operation"))
        doc["sysmon.wmi.name"] = clean(ed.get("Name"))
        doc["sysmon.wmi.query"] = clean(ed.get("Query"))
        doc["sysmon.wmi.destination"] = clean(ed.get("Destination"))
        _user(doc, ed.get("User"))
        doc["event.severity"] = "medium"
        doc["message"] = f"WMI {doc['event.action']}: {doc.get('sysmon.wmi.name')} {doc.get('sysmon.wmi.query') or doc.get('sysmon.wmi.destination') or ''}"
    elif code == "22":
        set_process_path(doc, "process", ed.get("Image"))
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        doc["dns.question.name"] = (clean(ed.get("QueryName")) or "").lower() or None
        doc["dns.response_code"] = clean(ed.get("QueryStatus"))
        results = clean(ed.get("QueryResults"))
        if results:
            answers = [r.replace("::ffff:", "").replace("type:  5 ", "") for r in results.rstrip(";").split(";") if r]
            doc["dns.answers.data"] = answers
        _user(doc, ed.get("User"))
        doc["network.protocol"] = "dns"
        doc["message"] = f"DNS query: {doc.get('dns.question.name')} by {doc.get('process.name')}"
    elif code == "25":
        set_process_path(doc, "process", ed.get("Image"))
        doc["process.pid"] = to_int(ed.get("ProcessId"))
        doc["sysmon.tamper_type"] = clean(ed.get("Type"))
        doc["event.severity"] = "high"
        doc["message"] = f"Process tampering ({doc.get('sysmon.tamper_type')}): {doc.get('process.executable')}"
    elif code in ("4", "16"):
        doc["event.severity"] = "medium"
        doc["message"] = f"Sysmon {doc['event.action']}: {clean(ed.get('State')) or clean(ed.get('Configuration')) or ''}"
