"""JSON line parser: journald export, pre-parsed winlog dicts and ECS pass-through."""
from __future__ import annotations

import json

from ...common.util import flatten, to_int
from . import register
from .base import base_doc, set_ts
from .syslog import apply_program_parser

_JOURNAL_PRIORITY = {"0": "critical", "1": "critical", "2": "critical", "3": "error", "4": "warning", "5": "info", "6": "info", "7": "debug"}


def _journald(obj: dict, raw: str, meta: dict) -> dict:
    doc = base_doc(raw, meta, "linux.journald", "linux", "journald")
    ts_us = obj.get("__REALTIME_TIMESTAMP") or obj.get("_SOURCE_REALTIME_TIMESTAMP")
    if ts_us:
        set_ts(doc, int(ts_us) / 1_000_000)
    else:
        set_ts(doc, None)
    host = obj.get("_HOSTNAME")
    if host:
        doc["host.name"] = doc.get("host.name") or str(host).split(".")[0]
    doc["host.os.type"] = doc.get("host.os.type") or "linux"
    doc["process.pid"] = to_int(obj.get("_PID"))
    doc["process.executable"] = obj.get("_EXE")
    doc["process.command_line"] = obj.get("_CMDLINE")
    doc["user.id"] = str(obj["_UID"]) if obj.get("_UID") is not None else None
    doc["log.level"] = _JOURNAL_PRIORITY.get(str(obj.get("PRIORITY", "6")), "info")
    doc["log.syslog.priority"] = to_int(obj.get("PRIORITY"))
    unit = obj.get("_SYSTEMD_UNIT")
    if unit:
        doc["service.name"] = unit
    msg = obj.get("MESSAGE")
    if isinstance(msg, list):  # journald may deliver bytes as int arrays
        try:
            msg = bytes(msg).decode("utf-8", "replace")
        except (TypeError, ValueError):
            msg = str(msg)
    program = obj.get("SYSLOG_IDENTIFIER") or (obj.get("_COMM") if obj.get("_COMM") else None)
    apply_program_parser(doc, program, str(msg or ""))
    if doc.get("event.dataset") in (None, "linux.journald") and program:
        doc["event.dataset"] = "linux.journald"
    return doc


@register("json")
def parse(raw: str, meta: dict) -> dict | None:
    text = raw.strip()
    if not text.startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    # journald -o json
    if "MESSAGE" in obj and ("_HOSTNAME" in obj or "__REALTIME_TIMESTAMP" in obj or "SYSLOG_IDENTIFIER" in obj):
        return _journald(obj, raw, meta)

    flat = flatten(obj)

    # pre-parsed windows event (e.g. from a Get-WinEvent based shipper)
    if "winlog.event_id" in flat or "winlog.channel" in flat:
        from .windows import parse_winlog_dict
        win = {k[len("winlog."):]: v for k, v in flat.items() if k.startswith("winlog.") and not k.startswith("winlog.event_data.")}
        win["event_data"] = {k[len("winlog.event_data."):]: v for k, v in flat.items() if k.startswith("winlog.event_data.")}
        if "event_data" not in win or not win["event_data"]:
            ed = obj.get("winlog", {}).get("event_data") if isinstance(obj.get("winlog"), dict) else None
            win["event_data"] = ed or {}
        win.setdefault("time_created", flat.get("@timestamp"))
        return parse_winlog_dict(win, raw, meta)

    # ECS-style pass-through (our own agent, simulate tool, other shippers)
    doc = base_doc(raw, meta, flat.get("event.dataset") or meta.get("dataset") or "json", "json", "json")
    for key, value in flat.items():
        if key in ("event.original",):
            continue
        doc[key] = value
    set_ts(doc, flat.get("@timestamp") or flat.get("timestamp") or flat.get("time"))
    if "message" not in doc:
        doc["message"] = flat.get("msg") or text[:1000]
    doc["event.module"] = flat.get("event.module") or str(doc["event.dataset"]).split(".")[0]
    if "tags" in doc and isinstance(doc["tags"], str):
        doc["tags"] = [doc["tags"]]
    return doc
