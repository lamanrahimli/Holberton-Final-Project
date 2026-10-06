"""GeoIP enrichment.

Three sources, checked in this order:

1. ``geoip/custom_ranges.csv`` - our own CIDR table (lab zones, documentation ranges, hand-picked
   public ranges).  Lets the team label the lab: "Lab-DMZ", "Lab-Workstations", "Campus"...
2. MaxMind GeoLite2-City.mmdb (optional, free with an account) via the ``maxminddb`` package -
   city-level detail when the file exists.
3. ``geoip/dbip-country-lite.csv.gz`` - the free DB-IP "IP to Country Lite" table (CC BY 4.0,
   ``start,end,country`` for the whole IPv4 and IPv6 space), read by our own range index
   (:class:`CountryDB`).  Works fully offline; refresh it with ``kharibulbul geoip update``.

Private addresses that are not in the custom table are labelled as a lab zone.  The result is
cached per IP.
"""
from __future__ import annotations

import csv
import gzip
import ipaddress
import logging
import os
import socket
from array import array
from bisect import bisect_right
from functools import lru_cache
from typing import Any

from ..common.util import parse_ip
from .countries import continent, country_name

log = logging.getLogger("kharibulbul.geoip")

LAB_COUNTRY_CODE = "XL"      # ISO 3166 user-assigned code: the lab's private ranges
LAB_COUNTRY_NAME = "Lab (private range)"

_DB_CACHE: dict[tuple, "CountryDB"] = {}


class CountryDB:
    """IP -> country from a ``start_ip,end_ip,CC`` table (DB-IP Lite format), plain or gzip.

    IPv4 ranges live in two ``array('I')`` (start / end) and are found by bisection; IPv6 ranges are
    kept as (high 64 bits, low 64 bits) pairs in ``array('Q')`` and searched the same way.
    About 360k ranges per family cost ~15 MB of memory and load in well under a second.
    """

    def __init__(self, path: str):
        self.path = path
        self.v4_start, self.v4_end = array("I"), array("I")
        self.v6_start_hi, self.v6_start_lo = array("Q"), array("Q")
        self.v6_end_hi, self.v6_end_lo = array("Q"), array("Q")
        self.v4_cc: list[str] = []
        self.v6_cc: list[str] = []
        self._load(path)

    @classmethod
    def open(cls, path: str) -> "CountryDB":
        """Load once per process (tests and the CLI build several pipelines)."""
        st = os.stat(path)
        key = (os.path.abspath(path), st.st_mtime_ns, st.st_size)
        db = _DB_CACHE.get(key)
        if db is None:
            db = _DB_CACHE[key] = cls(path)
        return db

    @staticmethod
    def _v4(text: str) -> int:
        a, b, c, d = text.split(".")
        return (int(a) << 24) | (int(b) << 16) | (int(c) << 8) | int(d)

    @staticmethod
    def _v6(text: str) -> tuple[int, int]:
        raw = socket.inet_pton(socket.AF_INET6, text)
        return int.from_bytes(raw[:8], "big"), int.from_bytes(raw[8:], "big")

    def _load(self, path: str) -> None:
        with open(path, "rb") as probe:
            opener = gzip.open if probe.read(2) == b"\x1f\x8b" else open
        codes: dict[str, str] = {}
        bad = 0
        with opener(path, "rt", encoding="utf-8", newline="") as fh:
            for line in fh:
                parts = line.strip().split(",")
                if len(parts) < 3 or parts[0].startswith("#"):
                    continue
                start, end, cc = parts[0].strip('"'), parts[1].strip('"'), parts[2].strip('"').upper()
                cc = codes.setdefault(cc, cc)            # share one str object per country
                try:
                    if ":" in start:
                        hi, lo = self._v6(start)
                        self.v6_start_hi.append(hi)
                        self.v6_start_lo.append(lo)
                        hi, lo = self._v6(end)
                        self.v6_end_hi.append(hi)
                        self.v6_end_lo.append(lo)
                        self.v6_cc.append(cc)
                    else:
                        self.v4_start.append(self._v4(start))
                        self.v4_end.append(self._v4(end))
                        self.v4_cc.append(cc)
                except (ValueError, OSError, OverflowError):
                    bad += 1
        if any(self.v4_start[i] > self.v4_start[i + 1] for i in range(len(self.v4_start) - 1)):
            order = sorted(range(len(self.v4_start)), key=self.v4_start.__getitem__)
            self.v4_start = array("I", (self.v4_start[i] for i in order))
            self.v4_end = array("I", (self.v4_end[i] for i in order))
            self.v4_cc = [self.v4_cc[i] for i in order]
        hi6, lo6 = self.v6_start_hi, self.v6_start_lo
        if any((hi6[i], lo6[i]) > (hi6[i + 1], lo6[i + 1]) for i in range(len(hi6) - 1)):
            order = sorted(range(len(hi6)), key=lambda i: (hi6[i], lo6[i]))
            self.v6_start_hi = array("Q", (hi6[i] for i in order))
            self.v6_start_lo = array("Q", (lo6[i] for i in order))
            self.v6_end_hi = array("Q", (self.v6_end_hi[i] for i in order))
            self.v6_end_lo = array("Q", (self.v6_end_lo[i] for i in order))
            self.v6_cc = [self.v6_cc[i] for i in order]
        log.info("GeoIP: country table %s - %d IPv4 + %d IPv6 ranges, %d countries%s", os.path.basename(path),
                 len(self.v4_start), len(self.v6_start_hi), len(codes), f" ({bad} bad lines)" if bad else "")

    def _index6(self, hi: int, lo: int) -> int:
        """Index of the last IPv6 range whose start is <= (hi, lo), or -1."""
        starts_hi, starts_lo = self.v6_start_hi, self.v6_start_lo
        a, b = 0, len(starts_hi)
        while a < b:
            mid = (a + b) // 2
            h = starts_hi[mid]
            if h < hi or (h == hi and starts_lo[mid] <= lo):
                a = mid + 1
            else:
                b = mid
        return a - 1

    def country(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
        """ISO code of the range that contains ``ip`` (None if no range does or it is unallocated: ZZ)."""
        if ip.version == 4:
            value = int(ip)
            i = bisect_right(self.v4_start, value) - 1
            if i < 0 or value > self.v4_end[i]:
                return None
            cc = self.v4_cc[i]
        else:
            value = int(ip)
            key = (value >> 64, value & 0xFFFFFFFFFFFFFFFF)
            i = self._index6(*key)
            if i < 0 or key > (self.v6_end_hi[i], self.v6_end_lo[i]):
                return None
            cc = self.v6_cc[i]
        return None if cc == "ZZ" else cc

    def __len__(self) -> int:
        return len(self.v4_start) + len(self.v6_start_hi)


class GeoIP:
    def __init__(self, mmdb_path: str | None = None, custom_csv: str | None = None, lab_networks: list[str] | None = None,
                 country_db: str | None = None):
        self.mmdb_path = mmdb_path
        self.custom: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, dict]] = []
        self.lab_networks = [ipaddress.ip_network(n, strict=False) for n in (lab_networks or [])]
        self._reader = None
        self.country_db: CountryDB | None = None
        if custom_csv and os.path.exists(custom_csv):
            self._load_custom(custom_csv)
        if mmdb_path and os.path.exists(mmdb_path):
            try:
                import maxminddb  # type: ignore
                self._reader = maxminddb.open_database(mmdb_path)
                log.info("GeoIP: loaded %s", mmdb_path)
            except Exception as exc:  # pragma: no cover - optional dependency
                log.warning("GeoIP: cannot open %s: %s", mmdb_path, exc)
        if country_db and os.path.exists(country_db):
            try:
                self.country_db = CountryDB.open(country_db)
            except (OSError, EOFError, ValueError) as exc:
                log.warning("GeoIP: cannot read %s: %s", country_db, exc)
        elif country_db:
            log.info("GeoIP: %s not found - public addresses stay 'Unknown' (run: kharibulbul geoip update)", country_db)

    # ------------------------------------------------------------------ #
    def _load_custom(self, path: str) -> None:
        with open(path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(row for row in fh if not row.startswith("#"))
            for row in reader:
                cidr = (row.get("cidr") or "").strip()
                if not cidr:
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    log.warning("GeoIP: bad cidr in %s: %s", path, cidr)
                    continue
                info: dict[str, Any] = {}
                for key in ("name", "country_iso_code", "country_name", "city_name", "organization"):
                    if row.get(key):
                        info[key] = row[key].strip()
                try:
                    if row.get("lat") and row.get("lon"):
                        info["location"] = {"lat": float(row["lat"]), "lon": float(row["lon"])}
                except ValueError:
                    pass
                self._add_continent(info)
                self.custom.append((net, info))
        # most specific first
        self.custom.sort(key=lambda item: item[0].prefixlen, reverse=True)
        log.info("GeoIP: loaded %d custom ranges from %s", len(self.custom), path)

    @staticmethod
    def _add_continent(info: dict) -> None:
        cont = continent(info.get("country_iso_code", ""))
        if cont:
            info["continent_code"], info["continent_name"] = cont

    # ------------------------------------------------------------------ #
    def lookup(self, ip_text: Any) -> dict | None:
        ip = parse_ip(ip_text)
        if ip is None:
            return None
        return self._lookup_cached(str(ip))

    @lru_cache(maxsize=50000)
    def _lookup_cached(self, ip_str: str) -> dict | None:
        ip = ipaddress.ip_address(ip_str)
        for net, info in self.custom:
            if ip.version == net.version and ip in net:
                return dict(info)
        if ip.is_unspecified or ip.is_multicast or ip_str == "255.255.255.255":
            return {"name": "Reserved"}
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            zone = "Lab-Private"
            for net in self.lab_networks:
                if ip.version == net.version and ip in net:
                    zone = "Lab-Network"
            return {"name": zone, "country_iso_code": LAB_COUNTRY_CODE, "country_name": LAB_COUNTRY_NAME}
        if self._reader is not None:
            try:
                rec = self._reader.get(ip_str)
            except Exception:
                rec = None
            if rec:
                return self._from_mmdb(rec)
        if self.country_db is not None:
            cc = self.country_db.country(ip)
            if cc:
                name = country_name(cc) or cc
                info = {"name": name, "country_iso_code": cc, "country_name": name}
                self._add_continent(info)
                return info
        return {"name": "Unknown"}

    @classmethod
    def _from_mmdb(cls, rec: dict) -> dict:
        out: dict[str, Any] = {}
        country = rec.get("country") or rec.get("registered_country") or {}
        if country:
            out["country_iso_code"] = country.get("iso_code")
            out["country_name"] = (country.get("names") or {}).get("en")
        city = rec.get("city") or {}
        if city:
            out["city_name"] = (city.get("names") or {}).get("en")
        loc = rec.get("location") or {}
        if loc.get("latitude") is not None:
            out["location"] = {"lat": loc["latitude"], "lon": loc["longitude"]}
        subs = rec.get("subdivisions") or []
        if subs:
            out["region_name"] = (subs[0].get("names") or {}).get("en")
        out["name"] = out.get("country_name") or "Unknown"
        out = {k: v for k, v in out.items() if v is not None}
        cls._add_continent(out)
        return out

    def apply(self, doc: dict, side: str) -> None:
        ip = doc.get(f"{side}.ip")
        if not ip:
            return
        info = self.lookup(ip)
        if not info:
            return
        for key, value in info.items():
            doc[f"{side}.geo.{key}" if key != "organization" else f"{side}.as.organization.name"] = value

    def snapshot(self) -> dict:
        db = self.country_db
        return {
            "custom_ranges": len(self.custom),
            "mmdb": self._reader is not None,
            "country_db": {"file": os.path.basename(db.path), "ipv4_ranges": len(db.v4_start), "ipv6_ranges": len(db.v6_start_hi),
                           "source": "DB-IP IP to Country Lite (CC BY 4.0, https://db-ip.com)"} if db else None,
        }


DBIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{year:04d}-{month:02d}.csv.gz"


def download_country_db(dest: str, url: str | None = None, timeout: float = 120.0) -> tuple[str, int]:
    """Fetch the current DB-IP country table (falls back to last month's file) -> (url used, bytes)."""
    import datetime
    import urllib.error
    import urllib.request
    today = datetime.date.today()
    candidates = [url] if url else []
    if not url:
        year, month = today.year, today.month
        for _ in range(3):
            candidates.append(DBIP_URL.format(year=year, month=month))
            year, month = (year, month - 1) if month > 1 else (year - 1, 12)
    last: Exception | None = None
    for candidate in candidates:
        try:
            req = urllib.request.Request(candidate, headers={"User-Agent": "kharibulbul-geoip-update"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
        except (urllib.error.URLError, OSError) as exc:
            last = exc
            continue
        if data[:2] != b"\x1f\x8b" and candidate.endswith(".gz"):
            last = ValueError(f"{candidate}: not a gzip file")
            continue
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        tmp = dest + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        CountryDB(tmp)                                  # must parse before it replaces the old table
        os.replace(tmp, dest)
        return candidate, len(data)
    raise RuntimeError(f"download failed: {last}")
