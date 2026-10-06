"""ECS-style normalisation: allowed values, conformance fixes, validation and the nested ECS view.

Kharibulbul stores events flat (``doc["source.ip"]``) with Elastic Common Schema field *names*.
This module is what makes that more than a naming habit:

* ``conform()``   - run by the normaliser on every event: stamps ``ecs.version``, lower-cases and maps
                    the categorisation fields onto the ECS allowed values, fills ``related.*``.
* ``validate()``  - lists what is still not ECS-conformant in a document (used by tests, the
                    ``kharibulbul parse --check`` command and the ``ecs-nonconformant`` tag).
* ``to_nested()`` - the document as a real nested ECS object (``{"source": {"ip": ...}}``) with
                    ``event.category`` / ``event.type`` as arrays; served by ``?format=ecs`` and sent to OpenSearch.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

ECS_VERSION = "8.11.0"

# ECS categorisation fields - allowed values (ECS 8.11 "Categorization Fields")
EVENT_KINDS = {"alert", "asset", "enrichment", "event", "metric", "state", "pipeline_error", "signal"}
EVENT_CATEGORIES = {"api", "authentication", "configuration", "database", "driver", "email", "file", "host", "iam",
                    "intrusion_detection", "library", "malware", "network", "package", "process", "registry", "session",
                    "threat", "vulnerability", "web"}
EVENT_TYPES = {"access", "admin", "allowed", "change", "connection", "creation", "deletion", "denied", "end", "error",
               "group", "indicator", "info", "installation", "protocol", "start", "user"}
EVENT_OUTCOMES = {"failure", "success", "unknown"}
NETWORK_DIRECTIONS = {"ingress", "egress", "inbound", "outbound", "internal", "external", "unknown"}

# what sources and sloppy parsers tend to write -> the ECS value
_CATEGORY_ALIASES = {"auth": "authentication", "login": "authentication", "logon": "authentication", "account": "iam",
                     "firewall": "network", "dns": "network", "ids": "intrusion_detection", "service": "configuration",
                     "config": "configuration", "http": "web"}
_TYPE_ALIASES = {"create": "creation", "created": "creation", "delete": "deletion", "deleted": "deletion",
                 "modify": "change", "modified": "change", "changed": "change", "deny": "denied", "blocked": "denied",
                 "block": "denied", "allow": "allowed", "information": "info", "stop": "end", "stopped": "end",
                 "started": "start", "install": "installation"}
_OUTCOME_ALIASES = {"ok": "success", "succeeded": "success", "successful": "success", "allowed": "success",
                    "fail": "failure", "failed": "failure", "error": "failure", "denied": "failure"}

# ECS field sets (top-level namespaces) and the base fields
ECS_FIELD_SETS = {
    "agent", "as", "client", "cloud", "code_signature", "container", "data_stream", "destination", "device", "dll",
    "dns", "ecs", "elf", "email", "error", "event", "faas", "file", "geo", "group", "hash", "host", "http", "interface",
    "log", "macho", "network", "observer", "orchestrator", "organization", "os", "package", "pe", "process", "registry",
    "related", "risk", "rule", "server", "service", "source", "threat", "tls", "tracing", "url", "user", "user_agent",
    "vlan", "volume", "vulnerability", "x509",
}
ECS_BASE_FIELDS = {"@timestamp", "labels", "message", "tags"}
# our documented extensions (ECS allows custom field sets when they do not collide with ECS names)
CUSTOM_FIELD_SETS = {"kharibulbul", "winlog", "sysmon", "powershell", "auditd", "dhcp", "fail2ban", "cron", "systemd",
                     "journald", "syslog", "nginx", "apache", "json"}

ARRAY_FIELDS = ("event.category", "event.type")          # arrays in ECS, scalars in our flat store
IP_FIELDS = ("source.ip", "destination.ip", "client.ip", "server.ip")
INTEGER_FIELDS = ("source.port", "destination.port", "process.pid", "process.parent.pid", "event.severity",
                  "http.response.status_code", "http.response.body.bytes", "winlog.record_id")
LIST_FIELDS = ("tags", "related.ip", "related.user", "related.hosts", "related.hash")

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_ISO_CC = re.compile(r"^[A-Z]{2}$")
_HASH_FIELDS = ("process.hash.md5", "process.hash.sha1", "process.hash.sha256", "file.hash.md5", "file.hash.sha1",
                "file.hash.sha256")


def _canon(value: Any, allowed: set[str], aliases: dict[str, str]) -> Any:
    if isinstance(value, list):
        return [_canon(v, allowed, aliases) for v in value]
    if not isinstance(value, str):
        return value
    text = value.strip().lower().replace("-", "_").replace(" ", "_")
    if text in allowed:
        return text
    return aliases.get(text, value.strip().lower())


def conform(doc: dict) -> dict:
    """Bring a flat document in line with ECS (in place). Never drops information."""
    doc["ecs.version"] = ECS_VERSION
    if "event.kind" in doc:
        doc["event.kind"] = _canon(doc["event.kind"], EVENT_KINDS, {})
    if "event.category" in doc:
        doc["event.category"] = _canon(doc["event.category"], EVENT_CATEGORIES, _CATEGORY_ALIASES)
    if "event.type" in doc:
        doc["event.type"] = _canon(doc["event.type"], EVENT_TYPES, _TYPE_ALIASES)
    if "event.outcome" in doc:
        doc["event.outcome"] = _canon(doc["event.outcome"], EVENT_OUTCOMES, _OUTCOME_ALIASES)

    hosts = [doc.get(f) for f in ("host.name", "source.domain", "destination.domain") if isinstance(doc.get(f), str)]
    if hosts:
        doc["related.hosts"] = list(dict.fromkeys(h.lower() for h in hosts if h))
    hashes = [doc.get(f) for f in _HASH_FIELDS if isinstance(doc.get(f), str) and doc.get(f)]
    if hashes:
        doc["related.hash"] = list(dict.fromkeys(hashes))
    return doc


def _values(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def validate(doc: dict) -> list[str]:
    """Return the ECS problems of a flat document (empty list = conformant)."""
    problems: list[str] = []
    ts = doc.get("@timestamp")
    if not isinstance(ts, str) or not _TS_RE.match(ts):
        problems.append(f"@timestamp is not UTC ISO-8601: {ts!r}")
    if doc.get("ecs.version") != ECS_VERSION:
        problems.append("ecs.version missing")
    for field, allowed in (("event.kind", EVENT_KINDS), ("event.category", EVENT_CATEGORIES),
                           ("event.type", EVENT_TYPES), ("event.outcome", EVENT_OUTCOMES)):
        if field in doc:
            bad = [v for v in _values(doc[field]) if v not in allowed]
            if bad:
                problems.append(f"{field}: {', '.join(map(str, bad))} is not an ECS allowed value")
    for field in ("event.kind", "event.outcome", "event.dataset"):
        if not doc.get(field):
            problems.append(f"{field} missing")
    if "network.direction" in doc and doc["network.direction"] not in NETWORK_DIRECTIONS:
        problems.append(f"network.direction: {doc['network.direction']!r}")
    for field in IP_FIELDS:
        if field in doc:
            try:
                ipaddress.ip_address(str(doc[field]))
            except ValueError:
                problems.append(f"{field}: {doc[field]!r} is not an IP address")
    for field in INTEGER_FIELDS:
        if field in doc and (isinstance(doc[field], bool) or not isinstance(doc[field], int)):
            problems.append(f"{field}: {doc[field]!r} is not an integer")
    for field in LIST_FIELDS:
        if field in doc and not isinstance(doc[field], list):
            problems.append(f"{field} must be a list")
    for side in ("source", "destination"):
        cc = doc.get(f"{side}.geo.country_iso_code")
        if cc is not None and not _ISO_CC.match(str(cc)):
            problems.append(f"{side}.geo.country_iso_code: {cc!r} is not an ISO 3166-1 alpha-2 code")
        loc = doc.get(f"{side}.geo.location")
        if loc is not None and not (isinstance(loc, dict) and {"lat", "lon"} <= set(loc)):
            problems.append(f"{side}.geo.location must be {{lat, lon}}")
    for key in doc:
        top = key.split(".", 1)[0]
        if key in ECS_BASE_FIELDS or top in ECS_FIELD_SETS or top in CUSTOM_FIELD_SETS or top == "labels":
            continue
        problems.append(f"{key}: '{top}' is neither an ECS field set nor a documented extension")
    return problems


def to_nested(doc: dict) -> dict:
    """Flat Kharibulbul document -> nested ECS object (categorisation fields become arrays)."""
    out: dict = {}
    for key in sorted(doc):
        value = doc[key]
        if key in ARRAY_FIELDS and not isinstance(value, list):
            value = [value]
        parts = key.split(".")
        cur = out
        for part in parts[:-1]:
            nxt = cur.get(part)
            if not isinstance(nxt, dict):
                # a scalar already sits where an object is needed ("a": 1 and "a.b": 2): keep it as "value"
                nxt = {} if nxt is None else {"value": nxt}
                cur[part] = nxt
            cur = nxt
        leaf = parts[-1]
        if isinstance(cur.get(leaf), dict) and not isinstance(value, dict):
            cur[leaf]["value"] = value
        else:
            cur[leaf] = value
    return out
