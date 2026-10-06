"""Playbooks stay executable: every query in a ```kql block compiles, every rule id they cite exists."""
from __future__ import annotations

import glob
import os
import re

from kharibulbul.detect.rules import load_rules
from kharibulbul.store.query import compile_query
from tests.conftest import ROOT

PLAYBOOKS = sorted(glob.glob(os.path.join(ROOT, "playbooks", "PB-*.md")))


def _kql_blocks(text: str) -> list[str]:
    return re.findall(r"```kql\n(.*?)```", text, re.S)


def test_playbook_queries_compile():
    assert len(PLAYBOOKS) >= 9
    checked = 0
    for path in PLAYBOOKS:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        blocks = _kql_blocks(text)
        assert blocks, f"{os.path.basename(path)} has no ```kql triage block"
        for block in blocks:
            for line in block.splitlines():
                line = line.split("->")[0].strip()          # trailing "-> what to look at" hints
                if not line or line.startswith("#"):
                    continue
                query = re.sub(r"<[^>]+>", "x", line)       # <ip>, <host> placeholders
                compile_query(query)                         # raises QueryError on bad syntax
                checked += 1
    assert checked >= 40


def test_playbooks_reference_existing_rules(rules_dir):
    ids = {r.id for r in load_rules(rules_dir)}
    for path in PLAYBOOKS + [os.path.join(ROOT, "playbooks", "README.md")]:
        with open(path, "r", encoding="utf-8") as fh:
            cited = set(re.findall(r"KB-[A-Z]+-\d{3}", fh.read()))
        missing = cited - ids
        assert not missing, f"{os.path.basename(path)} cites unknown rules: {sorted(missing)}"


def test_every_rule_playbook_exists_and_is_tagged(rules_dir):
    for rule in load_rules(rules_dir):
        assert rule.playbook, f"{rule.id} has no playbook"
        path = os.path.join(ROOT, rule.playbook)
        assert os.path.exists(path), f"{rule.id}: {rule.playbook} missing"
