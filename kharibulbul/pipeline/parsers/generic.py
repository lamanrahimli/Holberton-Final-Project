"""Fallback parser: keeps the raw line, extracts what it can (timestamp, IPs, key=value pairs)."""
from __future__ import annotations

import re

from . import register
from .base import base_doc, set_ts

_TS = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_KV = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.]*)=(\"[^\"]*\"|\S+)")
_LEVEL = re.compile(r"\b(CRITICAL|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG|NOTICE)\b", re.I)


@register("generic")
def parse(raw: str, meta: dict) -> dict | None:
    text = raw.rstrip("\r\n")
    if not text.strip():
        return None
    doc = base_doc(raw, meta, meta.get("dataset") or "generic", "generic", "generic")
    m = _TS.search(text)
    set_ts(doc, m.group(1) if m else None)
    doc["event.category"] = "host"
    doc["event.type"] = "info"
    doc["event.action"] = "log-line"
    lvl = _LEVEL.search(text)
    if lvl:
        word = lvl.group(1).lower()
        doc["log.level"] = {"fatal": "critical", "warn": "warning", "notice": "info"}.get(word, word)
    ips = _IPV4.findall(text)
    if ips:
        doc["related.ip"] = list(dict.fromkeys(ips))
    kv = {k: v.strip('"') for k, v in _KV.findall(text)}
    for key, value in list(kv.items())[:40]:
        doc[f"extracted.{key}"] = value
    doc["message"] = text[:4000]
    return doc
