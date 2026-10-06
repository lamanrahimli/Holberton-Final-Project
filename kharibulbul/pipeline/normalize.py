"""Post-parse normalisation: consistent casing, derived fields, schema hygiene.

Runs after every parser so rules can rely on e.g. ``process.name`` always
being lower-case and ``network.type`` always being present when there is an IP.
"""
from __future__ import annotations

import re
import shlex
from datetime import timedelta

from ..common import ecs
from ..common.schema import finalize
from ..common.timeutil import parse_timestamp
from ..common.util import parse_ip

_SUSPICIOUS_TLDS = (".xyz", ".top", ".zip", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".onion", ".ru", ".su", ".pw", ".cc", ".ws")
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")
_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

# Local-time context for the "outside business hours" rules (set from pipeline config).
_TZ_OFFSET_HOURS = 0.0
_BUSINESS_HOURS = (8, 19)  # [start, end) in local hours, Monday-Friday


def configure(tz_offset_hours: float = 0.0, business_hours: tuple[int, int] = (8, 19)) -> None:
    global _TZ_OFFSET_HOURS, _BUSINESS_HOURS
    _TZ_OFFSET_HOURS = float(tz_offset_hours)
    _BUSINESS_HOURS = (int(business_hours[0]), int(business_hours[1]))


def time_context(doc: dict) -> None:
    """Add kharibulbul.time.* fields (local hour, weekday, business_hours flag)."""
    ts = parse_timestamp(doc.get("@timestamp"))
    if ts is None:
        return
    local = ts + timedelta(hours=_TZ_OFFSET_HOURS)
    weekday = local.weekday()
    doc["kharibulbul.time.hour"] = local.hour
    doc["kharibulbul.time.weekday"] = _WEEKDAYS[weekday]
    doc["kharibulbul.time.business_hours"] = weekday < 5 and _BUSINESS_HOURS[0] <= local.hour < _BUSINESS_HOURS[1]


def _split_args(cmd: str) -> list[str]:
    try:
        if "\\" in cmd or cmd.lower().endswith(".exe") or re.match(r'^"?[a-z]:\\', cmd, re.I):
            # Windows style: shlex would eat backslashes
            return [a for a in re.findall(r'"[^"]*"|\S+', cmd)]
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def normalize(doc: dict) -> dict:
    # ---- process ----------------------------------------------------------
    for prefix in ("process", "process.parent", "process.target"):
        name = doc.get(f"{prefix}.name")
        if isinstance(name, str):
            doc[f"{prefix}.name"] = name.strip().lower()
        exe = doc.get(f"{prefix}.executable")
        if isinstance(exe, str) and not doc.get(f"{prefix}.name"):
            doc[f"{prefix}.name"] = re.split(r"[\\/]", exe.strip())[-1].lower()
    cmd = doc.get("process.command_line")
    if isinstance(cmd, str) and cmd:
        args = _split_args(cmd)
        if args:
            doc["process.args"] = args[:64]
            doc["process.args_count"] = len(args)

    # ---- users --------------------------------------------------------------
    for field in ("user.name", "user.target.name", "user.effective.name"):
        value = doc.get(field)
        if isinstance(value, str):
            if "\\" in value and field == "user.name" and not doc.get("user.domain"):
                domain, value = value.split("\\", 1)
                doc["user.domain"] = domain
            if "@" in value and not doc.get("user.domain") and field == "user.name":
                value, domain = value.split("@", 1)
                doc["user.domain"] = domain
            doc[field] = value
            if value.endswith("$"):
                doc.setdefault("tags", []).append("machine-account") if "machine-account" not in doc.get("tags", []) else None

    # ---- network ------------------------------------------------------------
    for side in ("source", "destination"):
        ip = doc.get(f"{side}.ip")
        if ip is not None:
            parsed = parse_ip(ip)
            if parsed is None:
                doc.pop(f"{side}.ip", None)
                doc[f"{side}.address"] = str(ip)
            else:
                doc[f"{side}.ip"] = str(parsed)
                doc[f"{side}.address"] = str(parsed)
                doc.setdefault("network.type", "ipv6" if parsed.version == 6 else "ipv4")
    related = []
    for field in ("source.ip", "destination.ip", "host.ip", "client.ip"):
        val = doc.get(field)
        if isinstance(val, list):
            related.extend(str(v) for v in val)
        elif val:
            related.append(str(val))
    existing = doc.get("related.ip")
    if isinstance(existing, list):
        related.extend(existing)
    if related:
        doc["related.ip"] = list(dict.fromkeys(related))
    users = [doc.get(f) for f in ("user.name", "user.target.name", "user.effective.name") if doc.get(f)]
    if users:
        doc["related.user"] = list(dict.fromkeys(users))

    # ---- dns ----------------------------------------------------------------
    qname = doc.get("dns.question.name")
    if isinstance(qname, str):
        qname = qname.lower().rstrip(".")
        doc["dns.question.name"] = qname
        parts = qname.split(".")
        if len(parts) >= 2 and _DOMAIN_RE.match(qname):
            doc["dns.question.registered_domain"] = ".".join(parts[-2:])
            doc["dns.question.top_level_domain"] = parts[-1]
        if qname.endswith(_SUSPICIOUS_TLDS):
            tags = doc.setdefault("tags", [])
            if "suspicious-tld" not in tags:
                tags.append("suspicious-tld")

    # ---- host ---------------------------------------------------------------
    host = doc.get("host.name")
    if isinstance(host, str):
        doc["host.name"] = host.strip().lower()

    # ---- hygiene ------------------------------------------------------------
    for key in ("winlog.record_id", "process.pid", "process.parent.pid", "source.port", "destination.port"):
        val = doc.get(key)
        if isinstance(val, str) and val.isdigit():
            doc[key] = int(val)
    doc = finalize(doc)
    # ---- ECS ----------------------------------------------------------------
    ecs.conform(doc)
    time_context(doc)
    return doc
