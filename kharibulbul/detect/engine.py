"""Streaming detection engine.

Every stored event is evaluated against every enabled rule:

* **match rules** alert on the first matching event (with suppression),
* **threshold rules** count matching events (or distinct values) per group
  inside a sliding window and alert when the count is reached,
* **sequence rules** track ordered stages per key (e.g. many failures, then a
  success from the same source) and alert when the last stage completes.

Windows use the *event* timestamp, so replayed sample files behave exactly
like live traffic.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Any

from ..common.timeutil import parse_timestamp, to_epoch
from ..common.util import get_field
from .matchers import MatchError, match_selection
from .rules import Rule

log = logging.getLogger("kharibulbul.detect")


def _event_ts(doc: dict) -> float:
    dt = parse_timestamp(doc.get("@timestamp"))
    return to_epoch(dt) if dt else time.time()


def group_key(doc: dict, fields: list[str]) -> tuple[str, dict]:
    values = {}
    for f in fields:
        v = get_field(doc, f)
        if isinstance(v, list):
            v = ",".join(map(str, v))
        values[f] = "" if v is None else str(v)
    key = "|".join(f"{f}={values[f]}" for f in fields) if fields else "*"
    return key, values


class _ThresholdState:
    __slots__ = ("events", "fired_at")

    def __init__(self) -> None:
        self.events: dict[str, deque] = defaultdict(deque)   # group -> deque[(ts, distinct_value, event_id)]
        self.fired_at: dict[str, float] = {}


class _SequenceState:
    __slots__ = ("tracks",)

    def __init__(self) -> None:
        self.tracks: dict[str, dict] = {}  # key -> {"stage": i, "count": n, "since": ts, "events": [...]}


class DetectionEngine:
    def __init__(self, rules: list[Rule], alert_manager, default_suppress: float = 600.0):
        self.alert_manager = alert_manager
        self.default_suppress = default_suppress
        self._lock = threading.RLock()
        self.rules: list[Rule] = []
        self.hits: dict[str, int] = defaultdict(int)
        self.errors: dict[str, int] = defaultdict(int)
        self._thr: dict[str, _ThresholdState] = {}
        self._seq: dict[str, _SequenceState] = {}
        self._evaluated = 0
        self.load(rules)

    # ------------------------------------------------------------------ #
    def load(self, rules: list[Rule]) -> None:
        with self._lock:
            self.rules = [r for r in rules if r.enabled]
            self.disabled = [r for r in rules if not r.enabled]
            for r in self.rules:
                if r.threshold and r.id not in self._thr:
                    self._thr[r.id] = _ThresholdState()
                if r.sequence and r.id not in self._seq:
                    self._seq[r.id] = _SequenceState()
        log.info("detection engine: %d active rules (%d disabled)", len(self.rules), len(self.disabled))

    def all_rules(self) -> list[Rule]:
        return list(self.rules) + list(self.disabled)

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        with self._lock:
            for r in self.all_rules():
                if r.id == rule_id:
                    r.enabled = enabled
                    self.load(self.all_rules())
                    return True
        return False

    # ------------------------------------------------------------------ #
    def evaluate(self, doc: dict) -> list[dict]:
        """Evaluate one event; returns the alerts that were raised/updated."""
        alerts: list[dict] = []
        with self._lock:
            self._evaluated += 1
            ts = _event_ts(doc)
            for rule in self.rules:
                try:
                    if rule.sequence:
                        alert = self._eval_sequence(rule, doc, ts)
                    else:
                        if rule.logsource and not rule.prefilter(doc):
                            continue
                        if not rule.matches(doc):
                            continue
                        self.hits[rule.id] += 1
                        if rule.threshold:
                            alert = self._eval_threshold(rule, doc, ts)
                        else:
                            alert = self._fire(rule, doc, ts, count=1, group_fields=[])
                    if alert:
                        alerts.append(alert)
                except MatchError as exc:
                    self.errors[rule.id] += 1
                    if self.errors[rule.id] == 1:
                        log.error("rule %s: %s", rule.id, exc)
                except Exception as exc:  # a broken rule must not stop detection
                    self.errors[rule.id] += 1
                    if self.errors[rule.id] <= 3:
                        log.exception("rule %s failed: %s", rule.id, exc)
            if self._evaluated % 5000 == 0:
                self._gc(ts)
        return alerts

    # ------------------------------------------------------------------ #
    def _eval_threshold(self, rule: Rule, doc: dict, ts: float) -> dict | None:
        thr = rule.threshold
        state = self._thr[rule.id]
        key, values = group_key(doc, thr["group_by"])
        window = thr["window"]
        dq = state.events[key]
        distinct_field = thr.get("distinct")
        distinct_value = str(get_field(doc, distinct_field)) if distinct_field else None
        dq.append((ts, distinct_value, doc.get("event.id"), doc))
        cutoff = ts - window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if distinct_field:
            count = len({d for _, d, _, _ in dq if d is not None})
        else:
            count = len(dq)
        if count < thr["count"]:
            return None
        fired = state.fired_at.get(key)
        suppress = rule.suppress if rule.suppress is not None else self.default_suppress
        if fired is not None and ts - fired < suppress:
            # already alerted for this group recently: keep the alert's counter moving
            self.alert_manager.touch(rule, key, ts, extra=1)
            dq.clear()
            return None
        state.fired_at[key] = ts
        samples = [d for _, _, _, d in list(dq)[-5:]]
        dq.clear()
        return self._fire(rule, doc, ts, count=count, group_fields=thr["group_by"], key=key, values=values,
                          samples=samples, distinct_field=distinct_field)

    def _eval_sequence(self, rule: Rule, doc: dict, ts: float) -> dict | None:
        seq = rule.sequence
        stages = seq["stages"]
        state = self._seq[rule.id]
        key, values = group_key(doc, seq["by"])
        track = state.tracks.get(key)
        within = seq["within"]
        if track and ts - track["since"] > within:
            del state.tracks[key]
            track = None
        # does this event advance an existing track?
        if track:
            stage = stages[track["stage"]]
            if match_selection(stage.selection, doc):
                track["count"] += 1
                track["events"].append(doc)
                if track["count"] >= stage.count:
                    track["stage"] += 1
                    track["count"] = 0
                    if track["stage"] >= len(stages):
                        del state.tracks[key]
                        self.hits[rule.id] += 1
                        return self._fire(rule, doc, ts, count=len(track["events"]), group_fields=seq["by"], key=key,
                                          values=values, samples=track["events"][-5:], stage_names=[s.name for s in stages])
                return None
        # otherwise, can it start a new track?
        first = stages[0]
        if match_selection(first.selection, doc):
            if not track:
                track = {"stage": 0, "count": 0, "since": ts, "events": []}
                state.tracks[key] = track
            track["count"] += 1
            track["events"].append(doc)
            if track["count"] >= first.count:
                track["stage"] = 1
                track["count"] = 0
        return None

    def _fire(self, rule: Rule, doc: dict, ts: float, count: int, group_fields: list[str], key: str = "*",
              values: dict | None = None, samples: list[dict] | None = None, **extra: Any) -> dict | None:
        suppress = rule.suppress if rule.suppress is not None else self.default_suppress
        return self.alert_manager.raise_alert(rule=rule, doc=doc, ts=ts, count=count, group_fields=group_fields,
                                              group_key=key, group_values=values or {}, samples=samples or [doc],
                                              suppress=suppress, extra=extra)

    # ------------------------------------------------------------------ #
    def _gc(self, now_ts: float) -> None:
        for rule in self.rules:
            if rule.threshold:
                st = self._thr[rule.id]
                window = rule.threshold["window"]
                for key in [k for k, dq in st.events.items() if not dq or now_ts - dq[-1][0] > window * 2]:
                    st.events.pop(key, None)
                for key in [k for k, t in st.fired_at.items() if now_ts - t > (rule.suppress or self.default_suppress) * 2]:
                    st.fired_at.pop(key, None)
            if rule.sequence:
                st2 = self._seq[rule.id]
                within = rule.sequence["within"]
                for key in [k for k, t in st2.tracks.items() if now_ts - t["since"] > within]:
                    st2.tracks.pop(key, None)

    def snapshot(self) -> dict:
        return {
            "evaluated": self._evaluated,
            "active_rules": len(self.rules),
            "disabled_rules": len(self.disabled),
            "hits": dict(self.hits),
            "errors": dict(self.errors),
            "threshold_groups": {rid: len(st.events) for rid, st in self._thr.items()},
            "sequence_tracks": {rid: len(st.tracks) for rid, st in self._seq.items()},
        }
