"""nginx and Apache *error* log parser.

nginx:   2026/09/27 10:00:00 [error] 1234#1234: *5 open() "/var/www/html/.env" failed (2: No such file or directory),
         client: 10.10.99.10, server: srv-web01, request: "GET /.env HTTP/1.1", host: "srv-web01"
Apache:  [Sat Sep 27 10:00:00.123456 2026] [core:error] [pid 1234:tid 5678] [client 10.10.99.10:40001] AH00128: File does not exist: /var/www/html/.env
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from ...common.util import to_int
from . import register
from .base import base_doc, set_file_path, set_ip, set_port, set_ts

_NGINX = re.compile(r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<cid>\d+) )?(?P<msg>.*)$")
_APACHE = re.compile(r"^\[(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[(?P<module>[\w-]+):(?P<level>\w+)\] "
                     r"\[pid (?P<pid>\d+)(?::tid \d+)?\](?: \[client (?P<client>[^\]]+)\])? (?P<msg>.*)$")
_NGINX_EXTRAS = {
    "client": re.compile(r"client: (?P<v>[\d.]+|[0-9a-f:]+)"),
    "server": re.compile(r"server: (?P<v>[^,]+)"),
    "request": re.compile(r'request: "(?P<v>[^"]*)"'),
    "upstream": re.compile(r'upstream: "(?P<v>[^"]*)"'),
    "host": re.compile(r'host: "(?P<v>[^"]*)"'),
    "referrer": re.compile(r'referrer: "(?P<v>[^"]*)"'),
}
_AH = re.compile(r"^(?P<code>AH\d{5}): (?P<rest>.*)$")
_FILE = re.compile(r"(?:open\(\) \"|File does not exist: |script '|failed to open stream: |\")(?P<path>/[^\"' ,]+)")
_LEVELS = {"emerg": "critical", "alert": "critical", "crit": "critical", "error": "error", "warn": "warning",
           "notice": "info", "info": "info", "debug": "debug"}
_SENSITIVE = (".env", ".git", "wp-config", "passwd", ".htpasswd", ".aws", "id_rsa", "backup", ".bak", "shell.php", "phpmyadmin")


def _apache_ts(text: str) -> datetime | None:
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@register("apache_error")
def parse(raw: str, meta: dict) -> dict | None:
    text = raw.strip()
    m = _NGINX.match(text)
    flavour = "nginx"
    if not m:
        m = _APACHE.match(text)
        flavour = "apache"
    if not m:
        return None
    dataset = meta.get("dataset") or f"{flavour}.error"
    doc = base_doc(raw, meta, dataset, "web", "apache_error")
    doc["event.dataset"] = dataset if dataset.endswith(".error") else f"{flavour}.error"
    doc["event.category"] = "web"
    doc["event.type"] = "error"
    doc["event.action"] = "web-error"
    doc["event.outcome"] = "failure"
    doc["log.level"] = _LEVELS.get(m.group("level").lower(), "error")
    doc["process.pid"] = to_int(m.group("pid"))
    msg = m.group("msg")
    if flavour == "nginx":
        set_ts(doc, m.group("ts").replace("/", "-", 2).replace(" ", "T", 1))
        for key, rx in _NGINX_EXTRAS.items():
            mm = rx.search(msg)
            if mm:
                doc[f"nginx.{key}"] = mm.group("v")
        set_ip(doc, "source.ip", doc.pop("nginx.client", None))
        req = doc.pop("nginx.request", None)
        if req:
            parts = req.split()
            if len(parts) >= 2:
                doc["http.request.method"] = parts[0]
                doc["url.original"] = parts[1]
                doc["url.path"] = parts[1].split("?", 1)[0]
        if doc.get("nginx.host"):
            doc["url.domain"] = doc["nginx.host"]
        core = msg.split(", client:", 1)[0]
    else:
        ts = _apache_ts(m.group("ts"))
        set_ts(doc, ts)
        doc["apache.module"] = m.group("module")
        client = m.group("client")
        if client:
            ip, _, port = client.rpartition(":") if client.count(":") == 1 or "." in client else (client, "", "")
            set_ip(doc, "source.ip", ip or client)
            set_port(doc, "source.port", port)
        ah = _AH.match(msg)
        if ah:
            doc["error.code"] = ah.group("code")
            core = ah.group("rest")
        else:
            core = msg
    fm = _FILE.search(msg)
    if fm:
        set_file_path(doc, fm.group("path"))
    doc["error.message"] = core[:1000]
    low = msg.lower()
    if any(s in low for s in _SENSITIVE):
        doc["tags"].append("sensitive-path")
    doc["message"] = f"{flavour} {m.group('level')}: {core[:300]}" + (f" (client {doc['source.ip']})" if doc.get("source.ip") else "")
    return doc
