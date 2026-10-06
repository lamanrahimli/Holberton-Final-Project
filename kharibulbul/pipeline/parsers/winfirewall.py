"""Windows Firewall log (pfirewall.log, W3C format).

Enable with:  netsh advfirewall set allprofiles logging droppedconnections enable
Lines:  2024-05-01 10:00:00 DROP TCP 10.10.20.55 10.10.20.10 51000 445 52 S 0 0 0 - - - RECEIVE
"""
from __future__ import annotations

import re

from ...common.util import to_int
from . import register
from .base import base_doc, set_ip, set_port, set_ts

_LINE = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<action>ALLOW|DROP|INFO-EVENTS-LOST) (?P<proto>\S+) "
                   r"(?P<src>\S+) (?P<dst>\S+) (?P<spt>\S+) (?P<dpt>\S+) (?P<size>\S+) (?P<flags>\S+) (?P<tcpsyn>\S+) (?P<tcpack>\S+) "
                   r"(?P<tcpwin>\S+) (?P<icmptype>\S+) (?P<icmpcode>\S+) (?P<info>\S+)(?: (?P<path>SEND|RECEIVE))?")


@register("winfirewall")
def parse(raw: str, meta: dict) -> dict | None:
    text = raw.strip()
    if not text or text.startswith("#"):
        return None
    m = _LINE.match(text)
    if not m:
        return None
    doc = base_doc(raw, meta, "windows.firewall_log", "windows", "winfirewall")
    doc["event.dataset"] = "windows.firewall_log"
    set_ts(doc, f"{m.group('date')}T{m.group('time')}")
    blocked = m.group("action") == "DROP"
    doc["event.category"] = "network"
    doc["event.type"] = "denied" if blocked else "allowed"
    doc["event.action"] = "firewall-block" if blocked else "firewall-allow"
    doc["event.outcome"] = "failure" if blocked else "success"
    doc["network.transport"] = m.group("proto").lower()
    set_ip(doc, "source.ip", m.group("src"))
    set_ip(doc, "destination.ip", m.group("dst"))
    set_port(doc, "source.port", m.group("spt"))
    set_port(doc, "destination.port", m.group("dpt"))
    doc["network.bytes"] = to_int(m.group("size"))
    path = m.group("path")
    doc["network.direction"] = "inbound" if path == "RECEIVE" else ("outbound" if path == "SEND" else None)
    doc["host.os.type"] = "windows"
    doc["message"] = f"Windows Firewall {m.group('action')}: {doc.get('source.ip')}:{doc.get('source.port')} -> {doc.get('destination.ip')}:{doc.get('destination.port')}/{doc['network.transport']}"
    return doc
