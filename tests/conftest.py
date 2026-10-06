"""Shared fixtures: a pipeline wired to the repository's config/intel/geoip data."""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from kharibulbul.common.config import load_server_config  # noqa: E402
from kharibulbul.pipeline.pipeline import Pipeline  # noqa: E402


@pytest.fixture(scope="session")
def server_cfg() -> dict:
    return load_server_config(os.path.join(ROOT, "config", "server.yml"))


@pytest.fixture(scope="session")
def pipeline(server_cfg) -> Pipeline:
    return Pipeline(server_cfg)


@pytest.fixture(scope="session")
def rules_dir() -> str:
    return os.path.join(ROOT, "rules")


class MemoryAlerts:
    """Collects alerts in memory (no store) for engine tests."""

    def __init__(self) -> None:
        self.alerts: list[dict] = []
        self.touched: list[tuple] = []

    def raise_alert(self, rule, doc, ts, count, group_fields, group_key, group_values, samples, suppress, extra=None):
        alert = {"rule.id": rule.id, "count": count, "group_key": group_key, "group_values": group_values,
                 "event.id": doc.get("event.id"), "ts": ts}
        self.alerts.append(alert)
        return alert

    def touch(self, rule, group_key, ts, extra=1):
        self.touched.append((rule.id, group_key, ts))

    def ids(self) -> set[str]:
        return {a["rule.id"] for a in self.alerts}


@pytest.fixture
def memory_alerts() -> MemoryAlerts:
    return MemoryAlerts()
