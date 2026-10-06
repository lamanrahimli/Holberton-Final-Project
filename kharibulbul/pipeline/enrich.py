"""Enrichment stage: GeoIP, network direction, asset inventory, threat intel, severity boost."""
from __future__ import annotations

import logging

from ..common.schema import SEVERITY_SCORE
from ..common.util import ip_in_networks
from .assets import CRITICALITY_BOOST, AssetInventory
from .geoip import GeoIP
from .intel import ThreatIntel

log = logging.getLogger("kharibulbul.enrich")


class Enricher:
    def __init__(self, lab_networks: list[str], geoip: GeoIP | None = None,
                 assets: AssetInventory | None = None, intel: ThreatIntel | None = None):
        self.lab_networks = lab_networks or []
        self.geoip = geoip
        self.assets = assets
        self.intel = intel

    def direction(self, doc: dict) -> None:
        src, dst = doc.get("source.ip"), doc.get("destination.ip")
        if not src and not dst:
            return
        src_in = ip_in_networks(src, self.lab_networks) if src else None
        dst_in = ip_in_networks(dst, self.lab_networks) if dst else None
        if src and dst:
            if src_in and dst_in:
                direction = "internal"
            elif src_in and not dst_in:
                direction = "outbound"
            elif dst_in and not src_in:
                direction = "inbound"
            else:
                direction = "external"
        elif src:
            direction = "internal" if src_in else "inbound"
        else:
            direction = "internal" if dst_in else "outbound"
        # a parser that knows better (Sysmon Initiated, WFP Direction) keeps its value
        doc.setdefault("network.direction", direction)
        doc["kharibulbul.network.zone_direction"] = direction

    def enrich(self, doc: dict) -> dict:
        try:
            self.direction(doc)
            if self.geoip:
                self.geoip.apply(doc, "source")
                self.geoip.apply(doc, "destination")
            if self.assets:
                self.assets.apply(doc)
            if self.intel:
                self.intel.apply(doc)
            self._severity(doc)
        except Exception as exc:  # never lose an event because of enrichment
            log.exception("enrichment failed: %s", exc)
            doc.setdefault("kharibulbul.pipeline.errors", []).append(f"enrich: {exc}")
        return doc

    @staticmethod
    def _severity(doc: dict) -> None:
        sev = doc.get("event.severity")
        if isinstance(sev, str):
            sev = SEVERITY_SCORE.get(sev, 10)
        if not isinstance(sev, int):
            sev = 10
        if doc.get("threat.indicator.matched"):
            sev = max(sev, SEVERITY_SCORE["high"])
        crit = doc.get("kharibulbul.asset.criticality")
        if crit in CRITICALITY_BOOST and sev > SEVERITY_SCORE["informational"]:
            sev = min(100, sev + CRITICALITY_BOOST[crit])
        doc["event.severity"] = sev
