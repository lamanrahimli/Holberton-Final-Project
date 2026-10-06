"""Local threat-intelligence lists (no external services).

``intel/ips.txt``, ``intel/domains.txt``, ``intel/hashes.txt`` - one indicator
per line, optional ``# comment`` or ``indicator,description``.  The lists are
re-read when their mtime changes so the SOC team can update them live.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import time

log = logging.getLogger("kharibulbul.intel")

_FILES = {"ips.txt": "ipv4-addr", "domains.txt": "domain-name", "hashes.txt": "file-hash"}


class ThreatIntel:
    def __init__(self, directory: str | None, reload_every: float = 30.0):
        self.directory = directory
        self.reload_every = reload_every
        self.ips: dict[str, str] = {}
        self.cidrs: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self.domains: dict[str, str] = {}
        self.hashes: dict[str, str] = {}
        self._mtimes: dict[str, float] = {}
        self._last_check = 0.0
        self.reload(force=True)

    def reload(self, force: bool = False) -> None:
        if not self.directory or not os.path.isdir(self.directory):
            return
        now = time.time()
        if not force and now - self._last_check < self.reload_every:
            return
        self._last_check = now
        changed = False
        for fname in _FILES:
            path = os.path.join(self.directory, fname)
            mtime = os.path.getmtime(path) if os.path.exists(path) else -1
            if self._mtimes.get(fname) != mtime:
                self._mtimes[fname] = mtime
                changed = True
        if not changed and not force:
            return
        self.ips, self.cidrs, self.domains, self.hashes = {}, [], {}, {}
        for fname, kind in _FILES.items():
            path = os.path.join(self.directory, fname)
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    value, _, desc = line.partition(",")
                    value = value.strip().lower()
                    desc = desc.strip() or f"listed in {fname}"
                    if kind == "ipv4-addr":
                        if "/" in value:
                            try:
                                self.cidrs.append((ipaddress.ip_network(value, strict=False), desc))
                            except ValueError:
                                pass
                        else:
                            self.ips[value] = desc
                    elif kind == "domain-name":
                        self.domains[value.rstrip(".")] = desc
                    else:
                        self.hashes[value] = desc
        log.info("ThreatIntel: %d ips, %d cidrs, %d domains, %d hashes", len(self.ips), len(self.cidrs), len(self.domains), len(self.hashes))

    # ------------------------------------------------------------------ #
    def match_ip(self, ip: str) -> str | None:
        if not ip:
            return None
        ip = str(ip).lower()
        if ip in self.ips:
            return self.ips[ip]
        if self.cidrs:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for net, desc in self.cidrs:
                if addr in net:
                    return desc
        return None

    def match_domain(self, name: str) -> str | None:
        if not name:
            return None
        name = str(name).lower().rstrip(".")
        parts = name.split(".")
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self.domains:
                return self.domains[candidate]
        return None

    def match_hash(self, value: str) -> str | None:
        if not value:
            return None
        return self.hashes.get(str(value).lower())

    def apply(self, doc: dict) -> None:
        self.reload()
        hits: list[tuple[str, str, str]] = []
        for field in ("source.ip", "destination.ip"):
            desc = self.match_ip(doc.get(field, ""))
            if desc:
                hits.append(("ipv4-addr", str(doc[field]), desc))
        for field in ("dns.question.name", "destination.domain", "url.domain"):
            desc = self.match_domain(doc.get(field, ""))
            if desc:
                hits.append(("domain-name", str(doc[field]), desc))
        for field in ("process.hash.sha256", "process.hash.md5", "process.hash.sha1", "file.hash.sha256"):
            desc = self.match_hash(doc.get(field, ""))
            if desc:
                hits.append(("file-hash", str(doc[field]), desc))
        if hits:
            kind, value, desc = hits[0]
            doc["threat.indicator.matched"] = True
            doc["threat.indicator.type"] = kind
            doc["threat.indicator.value"] = value
            doc["threat.indicator.description"] = desc
            tags = doc.setdefault("tags", [])
            if "threat-intel-match" not in tags:
                tags.append("threat-intel-match")
