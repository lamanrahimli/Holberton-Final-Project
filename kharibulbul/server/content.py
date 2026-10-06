"""Custom content written from the dashboard: detection rules and response playbooks.

The shipped rules (``rules/``) and playbooks (``playbooks/``) are read-only in the UI.  What analysts
write themselves lives under ``<custom_dir>/rules/<id>.yml`` and ``<custom_dir>/playbooks/<name>.md``,
so the curated content and its tests stay untouched and the team's own work is easy to find.
"""
from __future__ import annotations

import logging
import os
import re

import yaml

from ..common.util import ensure_dir
from ..detect.rules import Rule, build_rule, load_rules, validate_rule

log = logging.getLogger("kharibulbul.content")

RULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
PLAYBOOK_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,80}\.md$")
MAX_RULE_BYTES = 64 * 1024
MAX_PLAYBOOK_BYTES = 256 * 1024
CUSTOM_ID_PREFIX = "KB-CUS-"

RULE_TEMPLATE = """id: {rule_id}
title: My custom rule
description: "What the log looks like and why it matters."
severity: medium                # informational | low | medium | high | critical
tags: [custom]
mitre:
  - {{ technique: T1110, tactic: credential-access }}
logsource: {{ dataset: linux.auth }}      # optional cheap pre-filter: dataset / module / category
detection:
  selection:
    event.action: ssh-login-failed
  # filter:
  #   source.ip|cidr: 10.10.10.0/24
  condition: selection            # e.g. "selection and not filter"
threshold:                        # remove this block to alert on every matching event
  count: 5
  window: 5m
  group_by: [host.name, source.ip]
suppress: 10m                     # do not re-alert the same group for this long
playbook: playbooks/PB-001-brute-force.md
falsepositives:
  - "Describe the benign cases"
"""

PLAYBOOK_TEMPLATE = """# PB-C01 - Title of the playbook

**Applies to:** rule ids or situations this playbook is for
**Severity guide:** when it is low / high / critical

## 1. Triage (first 5 minutes)

1. What exactly fired, on which host, for which user?
2. Is it expected (change window, known admin work)?

```kql
event.action:ssh-login-failed AND host.name:<host>
source.ip:<ip>
```

## 2. Containment

- Step one
- Step two

## 3. Eradication and recovery

- ...

## 4. Evidence to keep

- Alert JSON, sample events, affected accounts

## 5. Lessons learned / tuning

- Rule or filter changes to record in docs/TUNING-LOG.md
"""


class ContentError(ValueError):
    """A request that cannot be fulfilled; ``status`` is the HTTP status the API answers with."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _write(path: str, text: str) -> None:
    ensure_dir(os.path.dirname(path))
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")
    os.replace(tmp, path)


class CustomContent:
    def __init__(self, rules_dir: str, playbooks_dir: str, custom_dir: str):
        self.rules_dir = rules_dir
        self.playbooks_dir = playbooks_dir
        self.custom_rules_dir = os.path.join(custom_dir, "rules")
        self.custom_playbooks_dir = os.path.join(custom_dir, "playbooks")

    # ------------------------------------------------------------------ #
    # rules
    # ------------------------------------------------------------------ #
    def load_rules(self) -> list[Rule]:
        """Shipped rules plus the custom ones (a custom rule can never replace a shipped id)."""
        rules = load_rules(self.rules_dir) if os.path.isdir(self.rules_dir) else []
        ids = {r.id for r in rules}
        if os.path.isdir(self.custom_rules_dir):
            for rule in load_rules(self.custom_rules_dir):
                if rule.id in ids:
                    log.warning("custom rule %s ignored: the id already exists", rule.id)
                    continue
                rule.custom = True
                ids.add(rule.id)
                rules.append(rule)
        return rules

    def next_rule_id(self, existing: list[Rule]) -> str:
        used = [int(m.group(1)) for r in existing if (m := re.fullmatch(re.escape(CUSTOM_ID_PREFIX) + r"(\d+)", r.id))]
        return f"{CUSTOM_ID_PREFIX}{(max(used) + 1 if used else 1):03d}"

    def rule_template(self, existing: list[Rule]) -> str:
        return RULE_TEMPLATE.format(rule_id=self.next_rule_id(existing))

    @staticmethod
    def parse_rule(text: str) -> dict:
        if not isinstance(text, str) or not text.strip():
            raise ContentError("rule YAML is empty")
        if len(text.encode("utf-8")) > MAX_RULE_BYTES:
            raise ContentError(f"rule is larger than {MAX_RULE_BYTES // 1024} kB")
        try:
            docs = [d for d in yaml.safe_load_all(text) if d]
        except yaml.YAMLError as exc:
            raise ContentError(f"yaml error: {exc}") from None
        if len(docs) != 1:
            raise ContentError("exactly one rule per file (no '---' separators)")
        errors = validate_rule(docs[0])
        if errors:
            raise ContentError("; ".join(errors))
        return docs[0]

    def save_rule(self, text: str, existing: list[Rule], rule_id: str | None = None) -> Rule:
        """Create (``rule_id`` None) or replace a custom rule. Returns the built rule; the caller reloads the engine."""
        data = self.parse_rule(text)
        rid = str(data["id"]).strip()
        if not RULE_ID_RE.match(rid):
            raise ContentError("id: 3-64 characters, letters / digits / - / _ (for example KB-CUS-001)")
        current = {r.id: r for r in existing}
        if rule_id is None:
            if rid in current:
                raise ContentError(f"a rule with id {rid} already exists", 409)
        else:
            old = current.get(rule_id)
            if old is None:
                raise ContentError("rule not found", 404)
            if not old.custom:
                raise ContentError(f"{rule_id} is a shipped rule and read-only - clone it under a new id", 403)
            if rid != rule_id:
                raise ContentError(f"the id in the YAML ({rid}) must stay {rule_id}; create a new rule to rename")
        playbook = str(data.get("playbook") or "").strip()
        if playbook and self.read_playbook(os.path.basename(playbook)) is None:
            raise ContentError(f"playbook {playbook} does not exist (see the Playbooks page)")
        path = os.path.join(self.custom_rules_dir, f"{rid}.yml")
        try:
            rule = build_rule(data, path)
        except ValueError as exc:
            raise ContentError(str(exc)) from None
        rule.custom = True
        _write(path, text.replace("\r\n", "\n"))
        return rule

    def delete_rule(self, rule_id: str, existing: list[Rule]) -> None:
        rule = next((r for r in existing if r.id == rule_id), None)
        if rule is None:
            raise ContentError("rule not found", 404)
        if not rule.custom:
            raise ContentError(f"{rule_id} is a shipped rule - disable it instead of deleting", 403)
        path = os.path.join(self.custom_rules_dir, f"{rule_id}.yml")
        if os.path.isfile(path):
            os.remove(path)

    # ------------------------------------------------------------------ #
    # playbooks
    # ------------------------------------------------------------------ #
    @staticmethod
    def _names(directory: str) -> list[str]:
        if not directory or not os.path.isdir(directory):
            return []
        return sorted(f for f in os.listdir(directory) if f.lower().endswith(".md"))

    def list_playbooks(self) -> list[dict]:
        items = [{"name": n, "custom": False} for n in self._names(self.playbooks_dir)]
        shipped = {i["name"].lower() for i in items}
        items += [{"name": n, "custom": True} for n in self._names(self.custom_playbooks_dir) if n.lower() not in shipped]
        return items

    def read_playbook(self, name: str) -> tuple[str, bool] | None:
        """(markdown, is_custom) for a playbook file name, or None."""
        safe = os.path.basename(str(name or ""))
        if not safe or not safe.lower().endswith(".md"):
            return None
        for directory, custom in ((self.playbooks_dir, False), (self.custom_playbooks_dir, True)):
            path = os.path.join(directory, safe) if directory else ""
            if path and os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as fh:
                    return fh.read(), custom
        return None

    def save_playbook(self, name: str, content: str, create: bool) -> dict:
        name = str(name or "").strip()
        if name and not name.lower().endswith(".md"):
            name += ".md"
        if not PLAYBOOK_NAME_RE.match(name):
            raise ContentError("name: letters, digits, space . _ - only, up to 80 characters (for example PB-C01-phishing.md)")
        if not isinstance(content, str) or not content.strip():
            raise ContentError("the playbook is empty")
        if len(content.encode("utf-8")) > MAX_PLAYBOOK_BYTES:
            raise ContentError(f"playbook is larger than {MAX_PLAYBOOK_BYTES // 1024} kB")
        shipped = {n.lower() for n in self._names(self.playbooks_dir)}
        if name.lower() in shipped:
            raise ContentError(f"{name} is a shipped playbook and read-only - save yours under another name", 409 if create else 403)
        path = os.path.join(self.custom_playbooks_dir, name)
        exists = os.path.isfile(path)
        if create and exists:
            raise ContentError(f"a playbook named {name} already exists", 409)
        if not create and not exists:
            raise ContentError("playbook not found", 404)
        _write(path, content.replace("\r\n", "\n"))
        return {"name": name, "custom": True}

    def delete_playbook(self, name: str) -> None:
        safe = os.path.basename(str(name or ""))
        if safe.lower() in {n.lower() for n in self._names(self.playbooks_dir)}:
            raise ContentError(f"{safe} is a shipped playbook and cannot be deleted", 403)
        path = os.path.join(self.custom_playbooks_dir, safe)
        if not safe or not os.path.isfile(path):
            raise ContentError("playbook not found", 404)
        os.remove(path)
