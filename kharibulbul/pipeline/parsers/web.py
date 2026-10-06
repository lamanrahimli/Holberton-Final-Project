"""nginx / Apache access log parser (combined log format, plus common extensions)."""
from __future__ import annotations

import re

from ...common.util import to_int
from . import register
from .base import base_doc, set_ip, set_ts

# 10.0.0.5 - alice [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://ref" "Mozilla/4.08"
_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)?\s?(?P<url>[^"\s]*)\s?(?P<proto>HTTP/[\d.]+)?"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)")?(?:\s+"?(?P<xff>[^"\s]*)"?)?(?P<rest>.*)$')

_SCAN_TOOLS = ("nikto", "sqlmap", "nmap", "masscan", "dirbuster", "gobuster", "wpscan", "nuclei", "zgrab", "acunetix", "python-requests", "curl/", "wget/")


@register("web")
def parse(raw: str, meta: dict) -> dict | None:
    m = _COMBINED.match(raw.strip())
    if not m:
        return None
    dataset = meta.get("dataset") or "nginx.access"
    doc = base_doc(raw, meta, dataset, "web", "web")
    doc["event.dataset"] = dataset
    set_ts(doc, m.group("ts"))
    doc["event.category"] = "web"
    doc["event.type"] = "access"
    doc["event.action"] = "http-request"
    set_ip(doc, "source.ip", m.group("ip"))
    xff = (m.group("xff") or "").split(",")[0].strip()
    if xff and re.match(r"^\d+\.\d+\.\d+\.\d+$", xff):
        doc["client.ip"] = xff
        doc["source.nat.ip"] = doc.get("source.ip")
        doc["source.ip"] = xff
    if m.group("user") not in ("-", ""):
        doc["user.name"] = m.group("user")
    doc["http.request.method"] = m.group("method")
    url = m.group("url") or ""
    doc["url.original"] = url
    doc["url.path"] = url.split("?", 1)[0]
    if "?" in url:
        doc["url.query"] = url.split("?", 1)[1]
    doc["http.version"] = (m.group("proto") or "").replace("HTTP/", "") or None
    status = to_int(m.group("status"))
    doc["http.response.status_code"] = status
    doc["http.response.body.bytes"] = to_int(m.group("bytes"), 0)
    ref = m.group("referrer")
    if ref and ref != "-":
        doc["http.request.referrer"] = ref
    ua = m.group("ua")
    if ua and ua != "-":
        doc["user_agent.original"] = ua
        low = ua.lower()
        if any(t in low for t in _SCAN_TOOLS):
            doc["tags"].append("scanner-user-agent")
    doc["event.outcome"] = "success" if status and status < 400 else "failure"
    if status and status >= 500:
        doc["log.level"] = "error"
    doc["message"] = f"{doc.get('source.ip')} {doc.get('http.request.method')} {url} -> {status}"
    return doc
