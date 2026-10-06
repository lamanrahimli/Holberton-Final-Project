"""Timestamp parsing/formatting. Everything inside Kharibulbul is UTC."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

UTC = timezone.utc

_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}

# "Jan  5 03:04:05" / "Jan 15 03:04:05" (RFC3164 syslog, no year)
_RFC3164_RE = re.compile(r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})$")
# Apache/nginx "10/Oct/2000:13:55:36 -0700"
_CLF_RE = re.compile(r"^(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\s*(?P<tz>[+-]\d{4})?$")
_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?\s*$", re.IGNORECASE)


def now() -> datetime:
    return datetime.now(UTC)


def now_iso() -> str:
    return to_iso(now())


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    dt = dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def to_epoch(dt: datetime) -> float:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


def from_epoch(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, UTC)


def parse_timestamp(value: Any, default_year: int | None = None) -> datetime | None:
    """Parse the timestamp formats we meet in logs. Returns tz-aware UTC datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:  # milliseconds
            ts /= 1000.0
        return from_epoch(ts)
    text = str(value).strip()
    if not text:
        return None

    # epoch as string
    if re.fullmatch(r"\d{10}(\.\d+)?", text):
        return from_epoch(float(text))
    if re.fullmatch(r"\d{13}", text):
        return from_epoch(int(text) / 1000.0)

    # ISO-8601 (also Windows "2024-01-01T10:00:00.1234567Z" with 7 fraction digits)
    iso = text
    if iso.endswith("Z") or iso.endswith("z"):
        iso = iso[:-1] + "+00:00"
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", iso)
    if m:
        # Python's fromisoformat accepts at most 6 fraction digits; Windows
        # event logs emit 7 ("...:00.1234567Z"), so trim to microseconds.
        frac = (m.group(3) or "")[:7]
        candidate = m.group(1) + "T" + m.group(2) + frac + (m.group(4) or "")
        try:
            dt = datetime.fromisoformat(candidate)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    if re.match(r"^\d{4}-\d{2}-\d{2}$", text):
        return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=UTC)

    # RFC3164 syslog
    m = _RFC3164_RE.match(text)
    if m:
        year = default_year or now().year
        mon = _MONTHS.get(m.group("mon").lower())
        if mon:
            dt = datetime(year, mon, int(m.group("day")), int(m.group("h")), int(m.group("m")),
                          int(m.group("s")), tzinfo=UTC)
            # a December log read in January belongs to last year
            if dt - now() > timedelta(days=2):
                dt = dt.replace(year=year - 1)
            return dt

    # Apache CLF
    m = _CLF_RE.match(text)
    if m:
        mon = _MONTHS.get(m.group("mon").lower())
        if mon:
            dt = datetime(int(m.group("year")), mon, int(m.group("day")), int(m.group("h")),
                          int(m.group("m")), int(m.group("s")))
            tz = m.group("tz")
            if tz:
                sign = 1 if tz[0] == "+" else -1
                offset = timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5])) * sign
                dt = dt.replace(tzinfo=timezone(offset))
            else:
                dt = dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)

    # Windows "MM/dd/yyyy HH:mm:ss"
    for fmt in ("%m/%d/%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def parse_duration(value: Any) -> float:
    """'5m' -> 300.0 seconds; also accepts plain numbers (seconds)."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    m = _DURATION_RE.match(str(value))
    if not m:
        raise ValueError(f"invalid duration: {value!r}")
    num = float(m.group(1))
    unit = (m.group(2) or "s").lower()
    return num * {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]


def parse_relative(value: str) -> datetime:
    """'now-15m', 'now', '2024-01-01T00:00:00Z' -> datetime (UTC)."""
    text = str(value).strip()
    if text == "now":
        return now()
    if text.startswith("now-"):
        return now() - timedelta(seconds=parse_duration(text[4:]))
    if text.startswith("now+"):
        return now() + timedelta(seconds=parse_duration(text[4:]))
    dt = parse_timestamp(text)
    if dt is None:
        raise ValueError(f"invalid time: {value!r}")
    return dt
