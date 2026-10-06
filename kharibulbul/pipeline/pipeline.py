"""The Kharibulbul ingest pipeline: envelope -> parse -> normalise -> enrich."""
from __future__ import annotations

import logging
import re
import time
from collections import Counter
from typing import Any

from ..common import ecs
from ..common.config import resolve_path
from ..common.schema import add_tag
from . import parsers
from .assets import AssetInventory
from .enrich import Enricher
from .geoip import GeoIP
from .intel import ThreatIntel
from . import normalize as normalize_mod
from .normalize import normalize

log = logging.getLogger("kharibulbul.pipeline")

_NGINX_ERROR_HEAD = re.compile(r"^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \[")
_APACHE_ERROR_HEAD = re.compile(r"^\[[A-Z][a-z]{2} [A-Z][a-z]{2} \d")

ENVELOPE_META_KEYS = ("dataset", "host.name", "host.ip", "host.os.type", "host.os.name", "agent.id", "agent.name",
                      "agent.version", "agent.type", "log.file.path", "@timestamp", "fields")


class Pipeline:
    def __init__(self, cfg: dict | None = None, enricher: Enricher | None = None):
        cfg = cfg or {}
        pcfg = cfg.get("pipeline", {})
        self.drop_datasets = set(pcfg.get("drop_datasets") or [])
        bh = pcfg.get("business_hours") or [8, 19]
        normalize_mod.configure(tz_offset_hours=float(pcfg.get("timezone_offset_hours", 0) or 0),
                                business_hours=(int(bh[0]), int(bh[1])))
        if enricher is None:
            geo_cfg = pcfg.get("geoip", {})
            geoip = GeoIP(
                mmdb_path=resolve_path(cfg, geo_cfg.get("mmdb", "")) if geo_cfg.get("mmdb") else None,
                custom_csv=resolve_path(cfg, geo_cfg.get("custom_ranges", "")) if geo_cfg.get("custom_ranges") else None,
                lab_networks=pcfg.get("lab_networks") or [],
                country_db=resolve_path(cfg, geo_cfg.get("country_db", "")) if geo_cfg.get("country_db") else None,
            )
            assets = AssetInventory(resolve_path(cfg, pcfg.get("assets", "")) if pcfg.get("assets") else None)
            intel = ThreatIntel(resolve_path(cfg, pcfg.get("intel_dir", "")) if pcfg.get("intel_dir") else None)
            enricher = Enricher(pcfg.get("lab_networks") or [], geoip=geoip, assets=assets, intel=intel)
        self.enricher = enricher
        self.stats: Counter = Counter()
        self.started = time.time()

    # ------------------------------------------------------------------ #
    @staticmethod
    def select_parsers(raw: str, dataset: str | None) -> list[str]:
        ds = (dataset or "").lower()
        head = raw.lstrip()[:48]  # enough for the timestamp-led formats sniffed below
        order: list[str] = []
        if head.startswith("<Event") or head.startswith("<?xml"):
            order.append("windows")
        if head.startswith("{"):
            order.append("json")
        if head.startswith("type=") or head.startswith("node="):
            order.append("auditd")
        if _NGINX_ERROR_HEAD.match(head) or _APACHE_ERROR_HEAD.match(head):
            order.append("apache_error")
        if ds in ("windows.firewall_log", "windows.firewall"):
            order += ["winfirewall"]
        elif ds == "windows.dhcp":
            order += ["windows_dhcp"]
        elif ds.startswith("windows") or ds == "sysmon":
            order += ["windows", "json"]
        elif ds == "linux.auditd" or ds == "auditd":
            order += ["auditd"]
        elif ds in ("nginx.error", "apache.error") or ds.endswith(".error"):
            order += ["apache_error", "syslog"]
        elif ds in ("nginx.access", "apache.access") or ds.startswith("web") or ds.endswith(".access"):
            order += ["web", "syslog"]
        elif ds.startswith("linux") or ds.startswith("syslog") or ds in ("auth", "secure"):
            order += ["syslog", "web"]
        elif ds in ("json", "ecs", "kharibulbul"):
            order += ["json"]
        order += ["syslog", "web", "json", "windows", "generic"]
        seen: set[str] = set()
        return [n for n in order if not (n in seen or seen.add(n))]

    def process(self, envelope: dict[str, Any]) -> dict | None:
        """Turn one envelope into a stored-ready document (or None to drop)."""
        self.stats["received"] += 1
        raw = envelope.get("raw")
        if raw is None:
            # a structured event without raw text: treat the JSON as the raw line
            from ..common.util import json_dumps
            payload = {k: v for k, v in envelope.items() if k not in ENVELOPE_META_KEYS and k != "type"}
            raw = json_dumps(payload)
        raw = str(raw)
        if len(raw.strip()) == 0:
            self.stats["dropped_empty"] += 1
            return None
        meta = {k: envelope[k] for k in ENVELOPE_META_KEYS if k in envelope}
        if isinstance(envelope.get("meta"), dict):
            meta.update(envelope["meta"])
        dataset = meta.get("dataset")
        if dataset in self.drop_datasets:
            self.stats["dropped_dataset"] += 1
            return None

        doc = None
        errors: list[str] = []
        for name in self.select_parsers(raw, dataset):
            fn = parsers.get(name)
            if fn is None:
                continue
            try:
                doc = fn(raw, meta)
            except Exception as exc:  # a broken parser must never kill ingest
                errors.append(f"{name}: {exc}")
                log.debug("parser %s failed: %s", name, exc, exc_info=True)
                doc = None
            if doc is not None:
                self.stats[f"parsed.{name}"] += 1
                break
        if doc is None:
            self.stats["dropped_unparsed"] += 1
            return None
        if errors:
            doc["kharibulbul.pipeline.errors"] = errors
            add_tag(doc, "parser-error")
        try:
            doc = normalize(doc)
        except Exception as exc:
            log.exception("normalize failed: %s", exc)
            self.stats["errors.normalize"] += 1
            add_tag(doc, "normalize-error")
        doc = self.enricher.enrich(doc)
        problems = ecs.validate(doc)           # after enrichment: geo / asset / intel fields are checked too
        if problems:
            doc["kharibulbul.ecs.problems"] = problems[:10]
            add_tag(doc, "ecs-nonconformant")
            self.stats["ecs_nonconformant"] += 1
        self.stats["emitted"] += 1
        return doc

    def process_many(self, envelopes: list[dict]) -> list[dict]:
        out = []
        for env in envelopes:
            doc = self.process(env)
            if doc is not None:
                out.append(doc)
        return out

    def snapshot(self) -> dict:
        data = dict(self.stats)
        data["uptime_seconds"] = round(time.time() - self.started, 1)
        rate_base = max(1.0, time.time() - self.started)
        data["events_per_second"] = round(self.stats["emitted"] / rate_base, 3)
        return data
