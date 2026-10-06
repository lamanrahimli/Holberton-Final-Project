"""Rule model, loader and validator.

Rule file format (YAML)
-----------------------
    id: KB-WIN-001                      # unique, stable
    title: Windows brute force
    description: ...
    severity: high                      # informational|low|medium|high|critical
    enabled: true
    tags: [authentication, windows]
    mitre:
      - technique: T1110
        tactic: credential-access
    logsource:                          # optional cheap pre-filter
      dataset: windows.security         # string or list; also: module, category
    detection:
      selection:
        event.code: "4625"
      filter:
        user.name|endswith: "$"
      condition: selection and not filter
    threshold:                          # optional: aggregate before alerting
      count: 10
      window: 5m
      group_by: [host.name, source.ip]
      distinct: user.name               # optional: count distinct values instead of events
    sequence:                           # optional: ordered multi-stage correlation
      by: [source.ip]
      within: 15m
      stages:
        - name: failures
          selection: {event.action: logon-failed}
          count: 5
        - name: success
          selection: {event.action: logon-success}
    suppress: 10m                       # do not re-alert the same group for this long
    playbook: playbooks/PB-001-brute-force.md
    falsepositives: [...]
    references: [...]
"""
from __future__ import annotations

import glob
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable

import yaml

from ..common.schema import SEVERITIES, SEVERITY_SCORE
from ..common.timeutil import parse_duration
from .condition import ConditionError, compile_condition
from .matchers import MatchError, check_selection, match_selection

log = logging.getLogger("kharibulbul.rules")

RESERVED = {"condition", "timeframe"}


@dataclass
class Stage:
    name: str
    selection: Any
    count: int = 1


@dataclass
class Rule:
    id: str
    title: str
    severity: str = "medium"
    description: str = ""
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    mitre: list[dict] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    selections: dict[str, Any] = field(default_factory=dict)
    condition: Callable[[dict], bool] | None = None
    condition_text: str = ""
    threshold: dict | None = None
    sequence: dict | None = None
    suppress: float | None = None
    playbook: str = ""
    falsepositives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    author: str = ""
    path: str = ""
    raw: dict = field(default_factory=dict)
    custom: bool = False          # written from the dashboard (lives in <custom_dir>/rules), editable there

    # ------------------------------------------------------------------ #
    @property
    def severity_score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 50)

    def prefilter(self, doc: dict) -> bool:
        for key, want in self.logsource.items():
            fld = {"dataset": "event.dataset", "module": "event.module", "category": "event.category",
                   "product": "host.os.type", "service": "event.dataset"}.get(key, key)
            actual = doc.get(fld)
            wants = want if isinstance(want, list) else [want]
            if actual is None:
                return False
            if not any(str(actual).lower() == str(w).lower() or str(actual).lower().startswith(str(w).lower() + ".") for w in wants):
                return False
        return True

    def matches(self, doc: dict) -> bool:
        if not self.selections:
            return False
        matched = {name: match_selection(sel, doc) for name, sel in self.selections.items()}
        return bool(self.condition(matched)) if self.condition else all(matched.values())

    def kind(self) -> str:
        if self.sequence:
            return "sequence"
        if self.threshold:
            return "threshold"
        return "match"

    def to_public(self) -> dict:
        return {
            "id": self.id, "title": self.title, "severity": self.severity, "description": self.description,
            "enabled": self.enabled, "tags": self.tags, "mitre": self.mitre, "logsource": self.logsource,
            "kind": self.kind(), "condition": self.condition_text, "threshold": self.threshold,
            "sequence": {"by": self.sequence["by"], "within": self.sequence["within_text"],
                         "stages": [{"name": s.name, "count": s.count} for s in self.sequence["stages"]]} if self.sequence else None,
            "suppress": self.suppress, "playbook": self.playbook, "falsepositives": self.falsepositives,
            "references": self.references, "author": self.author, "path": self.path, "custom": self.custom,
            "detection": self.raw.get("detection"),
        }


# ---------------------------------------------------------------------- #
# validation / building
# ---------------------------------------------------------------------- #

def validate_rule(data: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["rule must be a mapping"]
    for key in ("id", "title"):
        if not data.get(key):
            errors.append(f"missing '{key}'")
    sev = str(data.get("severity", "medium")).lower()
    if sev not in SEVERITIES:
        errors.append(f"severity must be one of {', '.join(SEVERITIES)}")
    det = data.get("detection")
    seq = data.get("sequence")
    if not det and not seq:
        errors.append("rule needs 'detection' or 'sequence'")
    if det is not None:
        if not isinstance(det, dict):
            errors.append("'detection' must be a mapping")
        else:
            names = [k for k in det if k not in RESERVED]
            if not names:
                errors.append("'detection' needs at least one selection")
            for name in names:
                if not isinstance(det[name], (dict, list, str)):
                    errors.append(f"selection '{name}' must be a mapping, list or string")
                else:
                    errors += [f"selection '{name}': {p}" for p in check_selection(det[name])]
            try:
                compile_condition(det.get("condition"), names)
            except ConditionError as exc:
                errors.append(f"condition: {exc}")
    thr = data.get("threshold")
    if thr is not None:
        if not isinstance(thr, dict):
            errors.append("'threshold' must be a mapping")
        else:
            try:
                if int(thr.get("count", 0)) < 1:
                    errors.append("threshold.count must be >= 1")
            except (TypeError, ValueError):
                errors.append("threshold.count must be an integer")
            try:
                if parse_duration(thr.get("window", "5m")) <= 0:
                    errors.append("threshold.window must be > 0")
            except ValueError as exc:
                errors.append(f"threshold.window: {exc}")
            gb = thr.get("group_by", [])
            if not isinstance(gb, (list, str)):
                errors.append("threshold.group_by must be a list of fields")
    if seq is not None:
        if not isinstance(seq, dict) or not isinstance(seq.get("stages"), list) or len(seq["stages"]) < 2:
            errors.append("'sequence' needs a list of >= 2 stages")
        else:
            for i, st in enumerate(seq["stages"]):
                if not isinstance(st, dict) or "selection" not in st:
                    errors.append(f"sequence stage {i} needs a 'selection'")
                else:
                    errors += [f"sequence stage {i}: {p}" for p in check_selection(st["selection"])]
            try:
                parse_duration(seq.get("within", "10m"))
            except ValueError as exc:
                errors.append(f"sequence.within: {exc}")
    if data.get("suppress") is not None:
        try:
            parse_duration(data["suppress"])
        except ValueError as exc:
            errors.append(f"suppress: {exc}")
    mitre = data.get("mitre")
    if mitre is not None and not isinstance(mitre, list):
        errors.append("'mitre' must be a list")
    return errors


def build_rule(data: dict, path: str = "") -> Rule:
    errors = validate_rule(data)
    if errors:
        raise ValueError(f"{path or data.get('id')}: " + "; ".join(errors))
    det = data.get("detection") or {}
    selections = {k: v for k, v in det.items() if k not in RESERVED}
    cond_text = det.get("condition") or ""
    condition = compile_condition(cond_text, list(selections)) if selections else None
    mitre: list[dict] = []
    for item in data.get("mitre") or []:
        if isinstance(item, str):
            mitre.append({"technique": item})
        elif isinstance(item, dict):
            mitre.append({k: str(v) for k, v in item.items()})
    thr = data.get("threshold")
    if not thr and data.get("group_by"):
        # shorthand: a plain match rule that should alert *per entity*
        # (one alert per host / user / ip instead of one global alert)
        thr = {"count": 1, "window": data.get("window", "1m"), "group_by": data["group_by"]}
    threshold = None
    if thr:
        gb = thr.get("group_by", [])
        threshold = {
            "count": int(thr.get("count", 1)),
            "window": parse_duration(thr.get("window", "5m")),
            "window_text": str(thr.get("window", "5m")),
            "group_by": [gb] if isinstance(gb, str) else list(gb),
            "distinct": thr.get("distinct"),
        }
    seq = data.get("sequence")
    sequence = None
    if seq:
        by = seq.get("by", [])
        sequence = {
            "by": [by] if isinstance(by, str) else list(by),
            "within": parse_duration(seq.get("within", "10m")),
            "within_text": str(seq.get("within", "10m")),
            "stages": [Stage(name=str(s.get("name") or f"stage{i + 1}"), selection=s["selection"], count=int(s.get("count", 1)))
                       for i, s in enumerate(seq["stages"])],
        }
    suppress = parse_duration(data["suppress"]) if data.get("suppress") is not None else None
    tags = data.get("tags") or []
    return Rule(
        id=str(data["id"]), title=str(data["title"]), severity=str(data.get("severity", "medium")).lower(),
        description=str(data.get("description") or "").strip(), enabled=bool(data.get("enabled", True)),
        tags=[str(t) for t in ([tags] if isinstance(tags, str) else tags)], mitre=mitre,
        logsource=dict(data.get("logsource") or {}), selections=selections, condition=condition, condition_text=str(cond_text),
        threshold=threshold, sequence=sequence, suppress=suppress, playbook=str(data.get("playbook") or ""),
        falsepositives=[str(x) for x in (data.get("falsepositives") or [])],
        references=[str(x) for x in (data.get("references") or [])], author=str(data.get("author") or ""),
        path=path, raw=data,
    )


def load_rule_file(path: str) -> list[Rule]:
    with open(path, "r", encoding="utf-8") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d]
    rules = []
    for data in docs:
        rules.append(build_rule(data, path))
    return rules


def load_rules(directory: str, strict: bool = False) -> list[Rule]:
    """Load every *.yml / *.yaml under ``directory`` (recursively)."""
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    paths = sorted(glob.glob(os.path.join(directory, "**", "*.yml"), recursive=True) +
                   glob.glob(os.path.join(directory, "**", "*.yaml"), recursive=True))
    for path in paths:
        try:
            for rule in load_rule_file(path):
                if rule.id in seen:
                    msg = f"duplicate rule id {rule.id} in {path} (first in {seen[rule.id]})"
                    if strict:
                        raise ValueError(msg)
                    log.warning(msg)
                    continue
                seen[rule.id] = path
                rules.append(rule)
        except (ValueError, yaml.YAMLError, MatchError) as exc:
            if strict:
                raise
            log.error("rule %s skipped: %s", path, exc)
    log.info("loaded %d rules from %s", len(rules), directory)
    return rules
