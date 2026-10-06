"""Windows DHCP Server audit log parser (C:\\Windows\\System32\\dhcp\\DhcpSrvLog-*.log).

CSV rows after a text header::

    ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name,TransactionID,QResult,...
    10,09/27/26,10:00:00,Assign,10.10.20.55,kali-lab.lab.local,0A1B2C3D4E5F,,0,0,,,,,,,,,0

Useful for asset discovery ("which device got which address") and for the DHCP conflict /
denied rules (KB-NET-031).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from . import register
from .base import base_doc, set_ip, set_ts

_DATE = re.compile(r"^\d{2}/\d{2}/\d{2,4}$")
EVENT_IDS = {
    "00": ("host", "info", "dhcp-log-started"), "01": ("host", "info", "dhcp-log-stopped"), "02": ("host", "info", "dhcp-log-paused"),
    "10": ("network", "allowed", "dhcp-lease-assigned"), "11": ("network", "allowed", "dhcp-lease-renewed"),
    "12": ("network", "info", "dhcp-lease-released"), "13": ("network", "denied", "dhcp-ip-conflict"),
    "14": ("network", "denied", "dhcp-lease-denied-scope-full"), "15": ("network", "denied", "dhcp-lease-denied"),
    "16": ("network", "info", "dhcp-lease-deleted"), "17": ("network", "info", "dhcp-lease-expired"), "18": ("network", "info", "dhcp-lease-expired"),
    "20": ("network", "allowed", "dhcp-bootp-assigned"), "21": ("network", "allowed", "dhcp-bootp-dynamic"),
    "22": ("network", "denied", "dhcp-bootp-denied"), "23": ("network", "info", "dhcp-bootp-deleted"),
    "24": ("host", "info", "dhcp-cleanup-started"), "25": ("host", "info", "dhcp-cleanup-stats"),
    "30": ("network", "info", "dhcp-dns-update-request"), "31": ("network", "error", "dhcp-dns-update-failed"),
    "32": ("network", "info", "dhcp-dns-update-success"), "33": ("network", "denied", "dhcp-packet-dropped-policy"),
    "34": ("network", "error", "dhcp-dns-update-request-failed"), "35": ("network", "error", "dhcp-dns-update-request-failed"),
    "36": ("network", "denied", "dhcp-packet-dropped-policy"), "50": ("host", "error", "dhcp-unreachable-domain"),
    "51": ("host", "info", "dhcp-authorized"), "52": ("host", "info", "dhcp-upgraded"), "53": ("host", "info", "dhcp-cached-authorization"),
    "54": ("host", "error", "dhcp-authorization-failed"), "55": ("host", "info", "dhcp-authorization-succeeded"),
    "56": ("host", "error", "dhcp-authorization-failed-stopped"), "57": ("host", "info", "dhcp-another-server-found"),
    "58": ("host", "error", "dhcp-server-unreachable"), "59": ("host", "error", "dhcp-network-failure"),
    "60": ("host", "info", "dhcp-no-dc-reachable"), "61": ("host", "info", "dhcp-another-server-found"),
    "62": ("host", "info", "dhcp-another-server-found"), "63": ("host", "info", "dhcp-restarting-rogue-detection"),
    "64": ("host", "info", "dhcp-no-dhcp-enabled-interfaces"),
}


def _mac(value: str) -> str | None:
    v = value.strip().replace("-", "").replace(":", "").lower()
    if len(v) != 12 or not re.fullmatch(r"[0-9a-f]{12}", v):
        return value.strip() or None
    return ":".join(v[i:i + 2] for i in range(0, 12, 2))


@register("windows_dhcp")
def parse(raw: str, meta: dict) -> dict | None:
    text = raw.strip()
    parts = [p.strip() for p in text.split(",")]
    if len(parts) < 7 or not parts[0].isdigit() or not _DATE.match(parts[1]):
        return None  # header / description lines
    code = parts[0].zfill(2)
    category, etype, action = EVENT_IDS.get(code, ("network", "info", f"dhcp-{code}"))
    doc = base_doc(raw, meta, "windows.dhcp", "windows", "windows_dhcp")
    doc["event.dataset"] = "windows.dhcp"
    doc["host.os.type"] = doc.get("host.os.type") or "windows"
    date, time_ = parts[1], parts[2]
    ts = None
    for fmt in ("%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            ts = datetime.strptime(f"{date} {time_}", fmt).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue
    set_ts(doc, ts)
    doc["event.code"] = code
    doc["event.category"] = category
    doc["event.type"] = etype
    doc["event.action"] = action
    doc["event.outcome"] = "failure" if etype in ("denied", "error") else "success"
    doc["event.provider"] = "Microsoft-DHCP-Server"
    doc["dhcp.description"] = parts[3] or None
    if len(parts) > 4 and parts[4]:
        set_ip(doc, "client.ip", parts[4])
    if len(parts) > 5 and parts[5]:
        doc["client.domain"] = parts[5].lower()
    if len(parts) > 6 and parts[6]:
        doc["client.mac"] = _mac(parts[6])
    if len(parts) > 7 and parts[7]:
        doc["user.name"] = parts[7]
    if len(parts) > 8 and parts[8]:
        doc["dhcp.transaction_id"] = parts[8]
    if len(parts) > 9 and parts[9]:
        doc["dhcp.qresult"] = parts[9]
    if etype == "denied":
        doc["event.severity"] = "medium"
    doc["message"] = f"DHCP {parts[3] or action}: {doc.get('client.ip', '')} {doc.get('client.domain', '')} {doc.get('client.mac', '')}".strip()
    return doc
