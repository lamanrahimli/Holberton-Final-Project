"""Kharibulbul Event Schema (KES) - an ECS-style flat field vocabulary.

We follow the Elastic Common Schema field *names* so that rules, dashboards
and any future OpenSearch/Elastic tooling understand our data, but the schema
itself is ours: a flat dict with dotted keys, validated by `finalize()`.

Only the fields listed in FIELDS are documented; anything else is still
accepted (stored under its dotted name) so parsers never lose data.
"""
from __future__ import annotations

from typing import Any

from .timeutil import now_iso, parse_timestamp, to_iso
from .util import new_id

SEVERITIES = ("informational", "low", "medium", "high", "critical")
SEVERITY_SCORE = {"informational": 10, "low": 30, "medium": 50, "high": 75, "critical": 95}

# field name -> (type, description)
FIELDS: dict[str, tuple[str, str]] = {
    "@timestamp": ("date", "Event time in UTC ISO-8601"),
    "ecs.version": ("keyword", "ECS version the event conforms to (set by the normaliser)"),
    "related.ip": ("ip[]", "Every IP address seen in the event"),
    "related.user": ("keyword[]", "Every user name seen in the event"),
    "related.hosts": ("keyword[]", "Every host name seen in the event"),
    "related.hash": ("keyword[]", "Every file / process hash seen in the event"),
    "kharibulbul.ecs.problems": ("keyword[]", "ECS conformance problems found after enrichment (tag ecs-nonconformant)"),
    "event.id": ("keyword", "Unique Kharibulbul event id"),
    "event.kind": ("keyword", "event | alert | metric | state"),
    "event.category": ("keyword", "authentication | process | network | file | registry | iam | configuration | intrusion_detection | web | package | session | driver | malware"),
    "event.type": ("keyword", "start | end | creation | deletion | access | change | connection | denied | allowed | info | error | user | group"),
    "event.action": ("keyword", "Normalised action, e.g. logon-failed, process-created"),
    "event.outcome": ("keyword", "success | failure | unknown"),
    "event.code": ("keyword", "Provider-specific event code (Windows EventID, etc.)"),
    "event.provider": ("keyword", "Log provider (Microsoft-Windows-Security-Auditing, sshd, ...)"),
    "event.dataset": ("keyword", "Logical dataset: windows.security, sysmon, linux.auth, nginx.access ..."),
    "event.module": ("keyword", "Parser family: windows, sysmon, syslog, linux, web, json"),
    "event.severity": ("integer", "Numeric severity 0-100 (informational->critical)"),
    "event.original": ("text", "Raw log line / XML as received"),
    "event.ingested": ("date", "When the server received the event"),
    "event.created": ("date", "When the source created the event (if different)"),
    "message": ("text", "Human readable message"),
    "log.level": ("keyword", "info | warning | error | critical"),
    "log.file.path": ("keyword", "Source file path"),
    "log.syslog.facility.name": ("keyword", "Syslog facility"),
    "log.syslog.severity.name": ("keyword", "Syslog severity"),
    "log.syslog.appname": ("keyword", "Syslog program/tag"),
    "host.name": ("keyword", "Hostname of the monitored machine"),
    "host.ip": ("ip", "Host IP address(es)"),
    "host.os.type": ("keyword", "windows | linux | macos"),
    "host.os.name": ("keyword", "OS name"),
    "host.role": ("keyword", "Role from assets.yml (dc, workstation, web, ...)"),
    "agent.id": ("keyword", "Kharibulbul agent id"),
    "agent.name": ("keyword", "Agent display name"),
    "agent.version": ("keyword", "Agent version"),
    "agent.type": ("keyword", "kharibulbul-agent | syslog | http | replay | simulate"),
    "user.name": ("keyword", "Acting user"),
    "user.domain": ("keyword", "Acting user's domain"),
    "user.id": ("keyword", "SID / UID"),
    "user.target.name": ("keyword", "Target user for IAM / logon events"),
    "user.target.domain": ("keyword", "Target user's domain"),
    "user.effective.name": ("keyword", "Effective user (sudo target, runas)"),
    "source.ip": ("ip", "Source IP"),
    "source.port": ("integer", "Source port"),
    "source.domain": ("keyword", "Source hostname / workstation name"),
    "source.geo.country_iso_code": ("keyword", "GeoIP country, ISO 3166-1 alpha-2 (XL = lab private range, XX = documentation range)"),
    "source.geo.country_name": ("keyword", "GeoIP country name"),
    "source.geo.continent_code": ("keyword", "GeoIP continent code (AF, AN, AS, EU, NA, OC, SA)"),
    "source.geo.continent_name": ("keyword", "GeoIP continent name"),
    "source.geo.city_name": ("keyword", "GeoIP city (custom ranges / MaxMind)"),
    "source.geo.location": ("geo_point", "{'lat':..,'lon':..}"),
    "source.geo.name": ("keyword", "Lab zone / logical location for private IPs"),
    "source.as.organization.name": ("keyword", "ASN organisation"),
    "destination.ip": ("ip", "Destination IP"),
    "destination.port": ("integer", "Destination port"),
    "destination.domain": ("keyword", "Destination hostname"),
    "destination.geo.country_iso_code": ("keyword", "GeoIP country, ISO 3166-1 alpha-2"),
    "destination.geo.country_name": ("keyword", "GeoIP country name"),
    "destination.geo.continent_code": ("keyword", "GeoIP continent code"),
    "destination.geo.continent_name": ("keyword", "GeoIP continent name"),
    "destination.geo.city_name": ("keyword", "GeoIP city (custom ranges / MaxMind)"),
    "destination.geo.location": ("geo_point", "{'lat':..,'lon':..}"),
    "destination.geo.name": ("keyword", "Lab zone / logical location for private IPs"),
    "network.transport": ("keyword", "tcp | udp | icmp"),
    "network.protocol": ("keyword", "Application protocol: http, dns, ssh, rdp ..."),
    "network.direction": ("keyword", "inbound | outbound | internal | external"),
    "network.type": ("keyword", "ipv4 | ipv6"),
    "process.pid": ("integer", "Process id"),
    "process.name": ("keyword", "Image file name (lower-case)"),
    "process.executable": ("keyword", "Full image path"),
    "process.command_line": ("text", "Command line"),
    "process.args": ("keyword", "Command line split into arguments"),
    "process.entity_id": ("keyword", "Sysmon ProcessGuid"),
    "process.hash.md5": ("keyword", "MD5"),
    "process.hash.sha1": ("keyword", "SHA1"),
    "process.hash.sha256": ("keyword", "SHA256"),
    "process.pe.original_file_name": ("keyword", "PE OriginalFileName"),
    "process.pe.company": ("keyword", "PE Company"),
    "process.pe.description": ("keyword", "PE Description"),
    "process.parent.pid": ("integer", "Parent pid"),
    "process.parent.name": ("keyword", "Parent image name"),
    "process.parent.executable": ("keyword", "Parent image path"),
    "process.parent.command_line": ("text", "Parent command line"),
    "process.parent.entity_id": ("keyword", "Sysmon ParentProcessGuid"),
    "process.working_directory": ("keyword", "Current directory"),
    "process.integrity_level": ("keyword", "Windows integrity level"),
    "file.path": ("keyword", "Full file path"),
    "file.name": ("keyword", "File name"),
    "file.extension": ("keyword", "Extension without dot"),
    "file.directory": ("keyword", "Directory"),
    "file.hash.sha256": ("keyword", "File SHA256"),
    "registry.path": ("keyword", "Registry key/value path"),
    "registry.value": ("keyword", "Registry value name"),
    "registry.data.strings": ("keyword", "Registry data"),
    "dns.question.name": ("keyword", "Queried name"),
    "dns.answers.data": ("keyword", "Resolved answers"),
    "url.original": ("keyword", "Requested URL"),
    "url.path": ("keyword", "URL path"),
    "http.request.method": ("keyword", "GET/POST/..."),
    "http.response.status_code": ("integer", "HTTP status"),
    "http.response.body.bytes": ("long", "Response size"),
    "user_agent.original": ("text", "User agent"),
    "service.name": ("keyword", "Service / daemon name"),
    "service.path": ("keyword", "Service binary path"),
    "service.type": ("keyword", "Service type"),
    "group.name": ("keyword", "Group name for IAM events"),
    "threat.indicator.matched": ("boolean", "Local threat-intel list matched"),
    "threat.indicator.type": ("keyword", "ipv4-addr | domain-name | file-hash"),
    "threat.indicator.value": ("keyword", "Matched indicator"),
    "threat.indicator.description": ("keyword", "Reason from intel list"),
    "winlog.channel": ("keyword", "Windows channel"),
    "winlog.record_id": ("long", "EventRecordID"),
    "winlog.provider_name": ("keyword", "Provider"),
    "winlog.computer_name": ("keyword", "Computer"),
    "winlog.event_data.*": ("object", "Raw EventData fields"),
    "winlog.logon.type": ("keyword", "Logon type (2 interactive, 3 network, 10 rdp...)"),
    "winlog.logon.id": ("keyword", "Logon ID"),
    "tags": ("keyword[]", "Tags added by parsers, enrichers and rules"),
    "labels.*": ("object", "Free-form labels (asset owner, zone...)"),
    "kharibulbul.asset.criticality": ("keyword", "low | medium | high | critical (from assets.yml)"),
    "kharibulbul.asset.owner": ("keyword", "Asset owner"),
    "kharibulbul.pipeline.parser": ("keyword", "Parser that handled the event"),
    "kharibulbul.pipeline.errors": ("keyword[]", "Parser/enricher problems, if any"),
    "rule.id": ("keyword", "(alerts) rule id"),
    "rule.name": ("keyword", "(alerts) rule title"),
}

# Columns extracted into real SQLite columns for fast filtering/aggregation
INDEXED_FIELDS = [
    "event.dataset", "event.category", "event.action", "event.code", "event.outcome",
    "host.name", "user.name", "source.ip", "destination.ip", "destination.port",
    "process.name", "agent.id", "event.severity",
]

# Fields whose text is indexed for full-text search
FTS_FIELDS = ["message", "process.command_line", "event.original", "file.path", "url.original",
              "dns.question.name", "user.name", "host.name", "process.name", "process.parent.name"]


def new_event(**fields: Any) -> dict:
    """Create a minimal valid event document."""
    doc: dict = {"@timestamp": now_iso(), "event.kind": "event", "event.id": new_id()}
    doc.update({k: v for k, v in fields.items() if v is not None})
    return doc


def finalize(doc: dict) -> dict:
    """Make sure the mandatory fields exist and are well-formed."""
    ts = parse_timestamp(doc.get("@timestamp"))
    doc["@timestamp"] = to_iso(ts) if ts else now_iso()
    doc.setdefault("event.id", new_id())
    doc.setdefault("event.kind", "event")
    doc.setdefault("event.ingested", now_iso())
    doc.setdefault("event.dataset", "generic")
    doc.setdefault("event.module", doc["event.dataset"].split(".")[0])
    doc.setdefault("event.outcome", "unknown")
    sev = doc.get("event.severity")
    if isinstance(sev, str) and sev in SEVERITY_SCORE:
        doc["event.severity"] = SEVERITY_SCORE[sev]
    elif not isinstance(sev, int):
        doc["event.severity"] = SEVERITY_SCORE["informational"]
    tags = doc.get("tags")
    if tags is None:
        doc["tags"] = []
    elif isinstance(tags, str):
        doc["tags"] = [tags]
    if "message" not in doc:
        doc["message"] = str(doc.get("event.original", ""))[:2000]
    # drop empty strings / None to keep documents tidy
    for key in [k for k, v in doc.items() if v is None or v == ""]:
        doc.pop(key)
    return doc


def add_tag(doc: dict, tag: str) -> None:
    tags = doc.setdefault("tags", [])
    if isinstance(tags, str):
        tags = [tags]
        doc["tags"] = tags
    if tag not in tags:
        tags.append(tag)


def severity_name(score: int | None) -> str:
    if score is None:
        return "informational"
    for name in reversed(SEVERITIES):
        if score >= SEVERITY_SCORE[name]:
            return name
    return "informational"
