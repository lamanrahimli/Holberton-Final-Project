"""Asset inventory (config/assets.yml) -> host.role, owner, criticality, zone labels."""
from __future__ import annotations

import ipaddress
import logging
import os

import yaml

log = logging.getLogger("kharibulbul.assets")

CRITICALITY_BOOST = {"low": 0, "medium": 5, "high": 15, "critical": 25}


class AssetInventory:
    def __init__(self, path: str | None):
        self.by_host: dict[str, dict] = {}
        self.by_ip: dict[str, dict] = {}
        self.zones: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        if path and os.path.exists(path):
            self.load(path)

    def load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        for asset in data.get("assets") or []:
            if not isinstance(asset, dict):
                continue
            info = {k: v for k, v in asset.items() if k not in ("hostnames", "ips")}
            for host in asset.get("hostnames") or ([asset["hostname"]] if asset.get("hostname") else []):
                self.by_host[str(host).lower().split(".")[0]] = info
            for ip in asset.get("ips") or ([asset["ip"]] if asset.get("ip") else []):
                self.by_ip[str(ip)] = info
        for zone in data.get("zones") or []:
            for cidr in zone.get("cidrs") or []:
                try:
                    self.zones.append((ipaddress.ip_network(cidr, strict=False), zone.get("name", cidr)))
                except ValueError:
                    log.warning("assets: bad zone cidr %s", cidr)
        log.info("Assets: %d hosts, %d ips, %d zones", len(self.by_host), len(self.by_ip), len(self.zones))

    def zone_for(self, ip: str | None) -> str | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, name in self.zones:
            if addr in net:
                return name
        return None

    def apply(self, doc: dict) -> None:
        host = str(doc.get("host.name") or "").lower().split(".")[0]
        info = self.by_host.get(host)
        if info is None:
            hip = doc.get("host.ip")
            if isinstance(hip, list):
                for candidate in hip:
                    info = self.by_ip.get(str(candidate))
                    if info:
                        break
            elif hip:
                info = self.by_ip.get(str(hip))
        if info:
            if info.get("role"):
                doc["host.role"] = info["role"]
            if info.get("owner"):
                doc["kharibulbul.asset.owner"] = info["owner"]
            crit = str(info.get("criticality", "medium")).lower()
            doc["kharibulbul.asset.criticality"] = crit
            if info.get("os") and not doc.get("host.os.name"):
                doc["host.os.name"] = info["os"]
            for k, v in (info.get("labels") or {}).items():
                doc[f"labels.{k}"] = v
        for side in ("source", "destination"):
            zone = self.zone_for(doc.get(f"{side}.ip"))
            if zone:
                doc[f"{side}.geo.name"] = zone
