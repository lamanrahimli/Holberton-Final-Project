"""Optional OpenSearch output (plain HTTP bulk API, no client library).

Kharibulbul's primary store is SQLite; this adapter mirrors events and alerts
into OpenSearch so the team can *also* build OpenSearch Dashboards on top of
the same ECS-style documents (assignment reference tool).
"""
from __future__ import annotations

import base64
import json
import logging
import ssl
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

from ..common.ecs import to_nested
from ..common.util import unflatten

log = logging.getLogger("kharibulbul.opensearch")

INDEX_TEMPLATE = {
    "index_patterns": ["kharibulbul-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "dynamic_templates": [
                {"strings_as_keyword": {"match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 1024}}}
            ],
            "properties": {
                "@timestamp": {"type": "date"},
                "message": {"type": "text"},
                "event": {"properties": {"original": {"type": "text"}, "severity": {"type": "integer"}}},
                "process": {"properties": {"command_line": {"type": "text"}, "pid": {"type": "long"},
                                           "parent": {"properties": {"command_line": {"type": "text"}, "pid": {"type": "long"}}}}},
                "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"},
                                          "geo": {"properties": {"location": {"type": "geo_point"}}}}},
                "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"},
                                               "geo": {"properties": {"location": {"type": "geo_point"}}}}},
                "powershell": {"properties": {"file": {"properties": {"script_block_text": {"type": "text"}}}}},
            },
        },
    },
}


class OpenSearchOutput:
    def __init__(self, url: str, index_prefix: str = "kharibulbul", username: str = "", password: str = "",
                 verify_tls: bool = False, timeout: float = 10.0):
        self.url = url.rstrip("/")
        self.prefix = index_prefix
        self.timeout = timeout
        self._auth = base64.b64encode(f"{username}:{password}".encode()).decode() if username else None
        self._ctx = None
        if self.url.startswith("https") and not verify_tls:
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        self._lock = threading.Lock()
        self.errors = 0
        self.sent = 0

    def _request(self, method: str, path: str, body: bytes | None = None, content_type: str = "application/json") -> dict | None:
        req = urllib.request.Request(self.url + path, data=body, method=method)
        req.add_header("Content-Type", content_type)
        if self._auth:
            req.add_header("Authorization", f"Basic {self._auth}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                data = resp.read()
                return json.loads(data) if data else {}
        except urllib.error.HTTPError as exc:
            log.warning("OpenSearch %s %s -> HTTP %s: %s", method, path, exc.code, exc.read()[:300])
        except Exception as exc:
            log.warning("OpenSearch %s %s failed: %s", method, path, exc)
        self.errors += 1
        return None

    def ensure_template(self) -> bool:
        body = json.dumps(INDEX_TEMPLATE).encode()
        return self._request("PUT", f"/_index_template/{self.prefix}-events", body) is not None

    def index_name(self, kind: str = "events") -> str:
        day = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        return f"{self.prefix}-{kind}-{day}"

    def bulk(self, docs: list[dict], kind: str = "events") -> None:
        if not docs:
            return
        lines = []
        index = self.index_name(kind)
        for doc in docs:
            _id = doc.get("event.id") or doc.get("id")
            action = {"index": {"_index": index}}
            if _id:
                action["index"]["_id"] = _id
            lines.append(json.dumps(action))
            lines.append(json.dumps(to_nested(doc) if kind == "events" else unflatten(doc), default=str))
        body = ("\n".join(lines) + "\n").encode()
        with self._lock:
            result = self._request("POST", "/_bulk", body, content_type="application/x-ndjson")
        if result is not None:
            self.sent += len(docs)
            if result.get("errors"):
                log.warning("OpenSearch bulk reported item errors")
