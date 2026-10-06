"""Helpers shared by all parsers."""
from __future__ import annotations

import ntpath
import posixpath
from typing import Any

from ...common.timeutil import now_iso, parse_timestamp, to_iso
from ...common.util import new_id, to_int


def base_doc(raw: str, meta: dict, dataset: str, module: str, parser: str) -> dict:
    """Start a document with the envelope information the shipper gave us."""
    doc: dict = {
        "event.id": new_id(),
        "event.kind": "event",
        "event.dataset": meta.get("dataset") or dataset,
        "event.module": module,
        "event.original": raw if len(raw) <= 32768 else raw[:32768],
        "kharibulbul.pipeline.parser": parser,
        "tags": [],
    }
    for key in ("host.name", "host.ip", "host.os.type", "host.os.name", "agent.id", "agent.name",
                "agent.version", "agent.type", "log.file.path"):
        if meta.get(key) not in (None, ""):
            doc[key] = meta[key]
    for key, value in (meta.get("fields") or {}).items():
        doc[str(key)] = value
    ts = parse_timestamp(meta.get("@timestamp"))
    if ts:
        doc["@timestamp"] = to_iso(ts)
    return doc


def set_ts(doc: dict, value: Any) -> None:
    ts = parse_timestamp(value)
    if ts:
        doc["@timestamp"] = to_iso(ts)
    elif "@timestamp" not in doc:
        doc["@timestamp"] = now_iso()


def clean(value: Any) -> Any:
    """Windows uses '-' for empty values."""
    if value is None:
        return None
    if isinstance(value, str):
        v = value.strip()
        if v in ("", "-", "NULL SID", "(null)"):
            return None
        return v
    return value


def set_process_path(doc: dict, prefix: str, path: Any) -> None:
    path = clean(path)
    if not path:
        return
    doc[f"{prefix}.executable"] = path
    doc[f"{prefix}.name"] = basename(path).lower()


def set_file_path(doc: dict, path: Any) -> None:
    path = clean(path)
    if not path:
        return
    doc["file.path"] = path
    name = basename(path)
    doc["file.name"] = name
    if "." in name:
        doc["file.extension"] = name.rsplit(".", 1)[-1].lower()
    directory = path[: len(path) - len(name)].rstrip("\\/")
    if directory:
        doc["file.directory"] = directory


def basename(path: str) -> str:
    if "\\" in path:
        return ntpath.basename(path)
    return posixpath.basename(path)


def set_ip(doc: dict, field: str, value: Any) -> None:
    value = clean(value)
    if not value:
        return
    if value.startswith("::ffff:"):
        value = value[7:]
    doc[field] = value


def set_port(doc: dict, field: str, value: Any) -> None:
    port = to_int(clean(value))
    if port is not None and port >= 0:
        doc[field] = port


def split_hashes(text: Any) -> dict[str, str]:
    """Sysmon 'MD5=...,SHA256=...,IMPHASH=...' -> {'md5': ..., 'sha256': ...}"""
    out: dict[str, str] = {}
    if not text:
        return out
    for part in str(text).split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out
