"""Small utilities: dotted-field access, flattening, ids, IP helpers, JSON."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import uuid
from typing import Any, Iterable, Iterator


# --------------------------------------------------------------------------- #
# Dotted field access on *flat* documents.
#
# Kharibulbul stores every event as a flat dict with dotted ECS keys, e.g.
#   {"@timestamp": "...", "source.ip": "10.0.0.5", "event.code": "4625"}
# This keeps the rule engine, the store and the API trivially consistent.
# --------------------------------------------------------------------------- #

def get_field(doc: dict, field: str, default: Any = None) -> Any:
    """Return doc[field]; also tolerates nested dicts (source: {ip: ...})."""
    if field in doc:
        return doc[field]
    if "." in field:
        cur: Any = doc
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur
    return default


def set_field(doc: dict, field: str, value: Any) -> None:
    """Set a dotted key on a flat document (None values are dropped)."""
    if value is None:
        doc.pop(field, None)
    else:
        doc[field] = value


def flatten(obj: Any, prefix: str = "", out: dict | None = None) -> dict:
    """Turn nested dicts into a flat dotted-key dict. Lists are kept as lists."""
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict) and v:
                flatten(v, key, out)
            else:
                out[key] = v
    else:
        out[prefix] = obj
    return out


def unflatten(doc: dict) -> dict:
    """Inverse of flatten(): {"a.b": 1} -> {"a": {"b": 1}} (for pretty output)."""
    out: dict = {}
    for key, value in doc.items():
        parts = key.split(".")
        cur = out
        for part in parts[:-1]:
            nxt = cur.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[part] = nxt
            cur = nxt
        cur[parts[-1]] = value
    return out


# --------------------------------------------------------------------------- #
# IDs / JSON
# --------------------------------------------------------------------------- #

def new_id() -> str:
    return uuid.uuid4().hex


def json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":"))


def json_loads(text: str | bytes) -> Any:
    return json.loads(text)


def to_int(value: Any, default: int | None = None) -> int | None:
    try:
        if value is None or value == "":
            return default
        return int(str(value).strip(), 0) if isinstance(value, str) and str(value).lower().startswith("0x") else int(value)
    except (TypeError, ValueError):
        return default


def lower(value: Any) -> str:
    return str(value).lower() if value is not None else ""


# --------------------------------------------------------------------------- #
# IP helpers
# --------------------------------------------------------------------------- #

_PRIVATE_NETS = [
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
              "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128", "100.64.0.0/10")
]


def parse_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.startswith("::ffff:"):
        text = text[7:]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def is_private_ip(value: Any) -> bool:
    ip = parse_ip(value)
    if ip is None:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


def ip_in_networks(value: Any, networks: Iterable[str]) -> bool:
    ip = parse_ip(value)
    if ip is None:
        return False
    for net in networks:
        try:
            if ip in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def hostname() -> str:
    return socket.gethostname().split(".")[0]


def primary_ip(target: str = "10.255.255.255") -> str | None:
    """The local address this host would use to reach ``target`` (a UDP connect sends no packet)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def local_ips(target: str | None = None) -> list[str]:
    """This host's addresses, most useful first: the one facing ``target`` (the SIEM server), the default
    route's, then whatever the hostname resolves to. Loopback is left out, link-local goes last."""
    found: list[str] = []
    for ip in ([primary_ip(target)] if target else []) + [primary_ip()]:
        if ip:
            found.append(ip)
    try:
        found.extend(str(info[4][0]).split("%")[0] for info in socket.getaddrinfo(socket.gethostname(), None))
    except OSError:
        pass
    ips: list[str] = []
    for ip in found:
        if ip not in ips and not ip.startswith("127.") and ip not in ("::1", "0.0.0.0"):
            ips.append(ip)
    link_local = [ip for ip in ips if ip.lower().startswith("fe80:") or ip.startswith("169.254.")]
    return [ip for ip in ips if ip not in link_local] + link_local


# --------------------------------------------------------------------------- #
# Misc
# --------------------------------------------------------------------------- #

_GLOB_CACHE: dict[str, re.Pattern] = {}


def glob_to_regex(pattern: str, case_insensitive: bool = True) -> re.Pattern:
    """Translate a wildcard pattern (* and ?) into an anchored regex."""
    key = ("i:" if case_insensitive else "s:") + pattern
    rx = _GLOB_CACHE.get(key)
    if rx is None:
        parts = []
        for ch in pattern:
            if ch == "*":
                parts.append(".*")
            elif ch == "?":
                parts.append(".")
            else:
                parts.append(re.escape(ch))
        rx = re.compile("^" + "".join(parts) + "$", re.IGNORECASE if case_insensitive else 0)
        _GLOB_CACHE[key] = rx
    return rx


def chunked(items: list, size: int) -> Iterator[list]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def project_root() -> str:
    """Directory that contains the kharibulbul package (the repo root)."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
