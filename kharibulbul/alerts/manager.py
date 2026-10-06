"""AlertManager: turns rule matches into de-duplicated, stored, notified alerts."""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from ..common.schema import SEVERITIES, SEVERITY_SCORE, severity_name
from ..common.timeutil import from_epoch, now_iso, to_iso
from ..common.util import new_id
from ..pipeline.assets import CRITICALITY_BOOST

log = logging.getLogger("kharibulbul.alerts")

SAMPLE_FIELDS = (
    "@timestamp", "event.id", "event.dataset", "event.code", "event.action", "event.outcome", "message", "host.name",
    "user.name", "user.target.name", "source.ip", "source.port", "source.geo.country_name", "source.geo.name",
    "destination.ip", "destination.port", "process.name", "process.command_line", "process.parent.name",
    "file.path", "dns.question.name", "url.original", "service.name", "registry.path", "winlog.logon.type", "tags",
)
STATUSES = ("new", "acknowledged", "investigating", "escalated", "closed", "false_positive")
# who an alert goes to at each escalation level when the analyst does not name anybody
ESCALATION_TIERS = {1: "Tier 2 analyst", 2: "SOC lead / incident responder", 3: "Incident manager (CSIRT)"}


def _trim(doc: dict) -> dict:
    return {k: doc[k] for k in SAMPLE_FIELDS if k in doc}


class AlertManager:
    def __init__(self, store, notifier=None):
        self.store = store
        self.notifier = notifier
        self._lock = threading.RLock()
        self.created = 0
        self.updated = 0
        self.escalated = 0

    # ------------------------------------------------------------------ #
    def raise_alert(self, rule, doc: dict, ts: float, count: int, group_fields: list[str], group_key: str,
                    group_values: dict, samples: list[dict], suppress: float, extra: dict | None = None) -> dict | None:
        with self._lock:
            existing = self.store.find_open_alert(rule.id, group_key, not_before=ts - suppress)
            if existing:
                existing["count"] = int(existing.get("count", 1)) + int(count)
                existing["last_seen"] = to_iso(from_epoch(max(ts, _epoch(existing.get("last_seen")))))
                existing["updated"] = now_iso()
                samples_kept = existing.get("sample_events") or []
                for s in samples:
                    trimmed = _trim(s)
                    if trimmed not in samples_kept:
                        samples_kept.append(trimmed)
                existing["sample_events"] = samples_kept[-10:]
                self.store.save_alert(existing)
                self.store.bump_rule(rule.id, hits=0, alerts=0)
                self.updated += 1
                if self.notifier:
                    self.notifier.notify(existing, new=False)
                return existing

            alert = self._build(rule, doc, ts, count, group_fields, group_key, group_values, samples, extra or {})
            self.store.save_alert(alert)
            self.store.bump_rule(rule.id, hits=0, alerts=1)
            self.created += 1
            if self.notifier:
                self.notifier.notify(alert, new=True)
            return alert

    def touch(self, rule, group_key: str, ts: float, extra: int = 1) -> None:
        with self._lock:
            existing = self.store.find_open_alert(rule.id, group_key, not_before=0)
            if existing:
                existing["count"] = int(existing.get("count", 1)) + extra
                existing["last_seen"] = to_iso(from_epoch(max(ts, _epoch(existing.get("last_seen")))))
                existing["updated"] = now_iso()
                self.store.save_alert(existing)

    def update(self, alert_id: str, status: str | None = None, assignee: str | None = None, notes: str | None = None) -> dict | None:
        if status == "escalated":
            return self.escalate(alert_id, by=assignee, assignee=assignee, notes=notes)
        with self._lock:
            alert = self.store.get_alert(alert_id)
            if not alert:
                return None
            if status:
                if status not in STATUSES:
                    raise ValueError(f"status must be one of {', '.join(STATUSES)}")
                alert["status"] = status
                alert.setdefault("history", []).append({"ts": now_iso(), "status": status, "by": assignee or alert.get("assignee")})
            if assignee is not None:
                alert["assignee"] = assignee
            if notes is not None:
                alert["notes"] = notes
            alert["updated"] = now_iso()
            self.store.save_alert(alert)
            return alert

    def escalate(self, alert_id: str, to: str | None = None, reason: str | None = None, by: str | None = None,
                 raise_severity: bool = True, assignee: str | None = None, notes: str | None = None) -> dict | None:
        """Hand an alert to the next tier: status ``escalated``, level + 1 (max 3), severity one step up
        (unless ``raise_severity`` is off), a history entry, and a notification on every enabled sink."""
        with self._lock:
            alert = self.store.get_alert(alert_id)
            if not alert:
                return None
            if alert.get("status") in ("closed", "false_positive"):
                raise ValueError(f"alert is {alert['status']} - reopen it before escalating")
            level = min(max(ESCALATION_TIERS), int((alert.get("escalation") or {}).get("level", 0)) + 1)
            when = now_iso()
            before = alert.get("severity") or "medium"
            if raise_severity and before in SEVERITIES:
                after = SEVERITIES[min(len(SEVERITIES) - 1, SEVERITIES.index(before) + 1)]
                alert["severity"] = after
                alert["severity_score"] = max(int(alert.get("severity_score") or 0), SEVERITY_SCORE[after])
            who = (by or assignee or alert.get("assignee") or "analyst").strip()
            alert["status"] = "escalated"
            alert["escalation"] = {"level": level, "to": (to or "").strip() or ESCALATION_TIERS[level],
                                   "reason": (reason or "").strip(), "by": who, "ts": when,
                                   "severity_before": before, "severity_after": alert.get("severity")}
            alert.setdefault("history", []).append({"ts": when, "status": "escalated", "by": who, "level": level,
                                                    "to": alert["escalation"]["to"], "reason": alert["escalation"]["reason"]})
            if assignee is not None:
                alert["assignee"] = assignee
            if notes is not None:
                alert["notes"] = notes
            alert["updated"] = when
            self.store.save_alert(alert)
            self.escalated += 1
            if self.notifier:
                self.notifier.notify(alert, new=False, event="escalated")
            return alert

    # ------------------------------------------------------------------ #
    def _build(self, rule, doc: dict, ts: float, count: int, group_fields: list[str], group_key: str,
               group_values: dict, samples: list[dict], extra: dict) -> dict:
        score = rule.severity_score
        crit = doc.get("kharibulbul.asset.criticality")
        if crit in CRITICALITY_BOOST:
            score = min(100, score + CRITICALITY_BOOST[crit])
        if doc.get("threat.indicator.matched"):
            score = max(score, SEVERITY_SCORE["high"])
        severity = severity_name(score)
        entity_parts = [f"{k}={v}" for k, v in group_values.items() if v] or [
            f"{k}={doc[k]}" for k in ("host.name", "user.name", "source.ip") if doc.get(k)]
        entity = ", ".join(entity_parts) or doc.get("host.name") or "unknown"
        when = to_iso(from_epoch(ts))
        summary = f"{rule.title} - {entity}"
        if count > 1:
            summary += f" ({count} events)"
        alert = {
            "id": new_id(),
            "kind": rule.kind(),
            "rule.id": rule.id,
            "rule.name": rule.title,
            "rule.description": rule.description,
            "severity": severity,
            "severity_score": score,
            "status": "new",
            "group_key": group_key,
            "group_fields": group_fields,
            "group_values": group_values,
            "entity": entity,
            "summary": summary,
            "first_seen": when,
            "last_seen": when,
            "created": now_iso(),
            "updated": now_iso(),
            "count": int(count),
            "host.name": doc.get("host.name"),
            "user.name": doc.get("user.name") or doc.get("user.target.name"),
            "source.ip": doc.get("source.ip"),
            "source.geo.country_name": doc.get("source.geo.country_name") or doc.get("source.geo.name"),
            "destination.ip": doc.get("destination.ip"),
            "process.name": doc.get("process.name"),
            "mitre": rule.mitre,
            "tags": list(dict.fromkeys(list(rule.tags) + [t for t in doc.get("tags", []) if isinstance(t, str)])),
            "playbook": rule.playbook,
            "falsepositives": rule.falsepositives,
            "asset.criticality": crit,
            "trigger_event_id": doc.get("event.id"),
            "sample_events": [_trim(s) for s in samples[-10:]],
            "history": [{"ts": now_iso(), "status": "new", "by": "kharibulbul"}],
        }
        if extra:
            alert["details"] = {k: v for k, v in extra.items() if v is not None}
        return alert


def _epoch(value: Any) -> float:
    from ..common.timeutil import parse_timestamp, to_epoch
    dt = parse_timestamp(value)
    return to_epoch(dt) if dt else time.time()
