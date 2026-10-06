"""YAML configuration loading with defaults and ${ENV} substitution."""
from __future__ import annotations

import copy
import os
import re
from typing import Any

import yaml

from .util import project_root

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

SERVER_DEFAULTS: dict[str, Any] = {
    "name": "Kharibulbul SIEM",
    "data_dir": "data",
    "log_level": "INFO",
    "ingest": {
        "tcp": {"enabled": True, "host": "0.0.0.0", "port": 5044, "tls": {"enabled": False, "cert": "", "key": "", "ca": ""}},
        "syslog_udp": {"enabled": True, "host": "0.0.0.0", "port": 5514},
        "syslog_tcp": {"enabled": False, "host": "0.0.0.0", "port": 5514},
        "http": {"enabled": True},
        "shared_secret": "",          # if set, agents must present it in "hello"
        "max_line_bytes": 1048576,
    },
    "api": {"host": "0.0.0.0", "port": 8080, "token": "", "cors": False},
    "store": {
        "backend": "sqlite",
        "sqlite": {"path": "data/kharibulbul.db", "batch_size": 200, "flush_interval": 1.0},
        "retention_days": 0,           # 0 = keep events forever (no date limit); N = purge events older than N days
        "opensearch": {"enabled": False, "url": "http://127.0.0.1:9200", "index_prefix": "kharibulbul",
                        "username": "", "password": "", "verify_tls": False},
    },
    "pipeline": {
        "lab_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "geoip": {"mmdb": "geoip/GeoLite2-City.mmdb", "custom_ranges": "geoip/custom_ranges.csv",
                  "country_db": "geoip/dbip-country-lite.csv.gz"},
        "assets": "config/assets.yml",
        "intel_dir": "intel",
        "drop_datasets": [],
        "timezone_offset_hours": 0,   # lab local time = UTC + offset (Baku: 4)
        "business_hours": [8, 19],    # local hours [start, end) Monday-Friday for kharibulbul.time.business_hours
    },
    "detect": {
        "rules_dir": "rules",
        "enabled": True,
        "default_suppress": "10m",
    },
    "custom_dir": "custom",           # rules and playbooks written from the dashboard: <custom_dir>/rules, <custom_dir>/playbooks
    "alerts": {
        "notify": {
            "console": {"enabled": True},
            "file": {"enabled": True, "path": "data/alerts.jsonl"},
            "webhook": {"enabled": False, "url": "", "headers": {}, "min_severity": "medium"},
            "smtp": {"enabled": False, "host": "", "port": 587, "username": "", "password": "",
                     "from": "", "to": [], "starttls": True, "min_severity": "high"},
        }
    },
    "agents": {"heartbeat_timeout": "5m"},
}

AGENT_DEFAULTS: dict[str, Any] = {
    "agent": {"name": "", "id": "", "id_file": "data/agent.id", "labels": {}},   # id: set by the "Add agent" wizard
    "server": {"host": "127.0.0.1", "port": 5044, "tls": {"enabled": False, "ca": "", "verify": True},
               "shared_secret": "", "reconnect_min": 1, "reconnect_max": 30},
    "spool": {"dir": "data/spool", "max_mb": 200},
    "batch": {"size": 100, "flush_interval": 1.0, "max_bytes": 524288},   # keep below the server's ingest.max_line_bytes
    "heartbeat_interval": 30,
    "inputs": [],
    "log_level": "INFO",
}


def _substitute_env(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match) -> str:
            return os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else "")
        return _ENV_RE.sub(repl, value)
    if isinstance(value, list):
        return [_substitute_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _substitute_env(v) for k, v in value.items()}
    return value


def deep_merge(base: dict, override: dict | None) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return _substitute_env(data)


def load_server_config(path: str | None) -> dict:
    cfg = deep_merge(SERVER_DEFAULTS, load_yaml(path) if path else {})
    cfg["_base_dir"] = os.path.dirname(os.path.abspath(path)) if path else os.getcwd()
    return cfg


def load_agent_config(path: str | None) -> dict:
    cfg = deep_merge(AGENT_DEFAULTS, load_yaml(path) if path else {})
    cfg["_base_dir"] = os.path.dirname(os.path.abspath(path)) if path else os.getcwd()
    return cfg


def resolve_path(cfg: dict, path: str) -> str:
    """Resolve a relative path against the repo root (config/ lives there)."""
    if not path:
        return path
    if os.path.isabs(path):
        return path
    candidates = [
        os.path.join(os.getcwd(), path),
        os.path.join(cfg.get("_base_dir", os.getcwd()), path),
        os.path.join(cfg.get("_base_dir", os.getcwd()), "..", path),
        os.path.join(project_root(), path),
    ]
    for cand in candidates:
        if os.path.exists(cand):
            return os.path.abspath(cand)
    return os.path.abspath(candidates[0])
