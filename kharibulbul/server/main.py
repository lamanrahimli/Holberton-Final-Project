"""Server bootstrap: wires store, pipeline, detection, alerts, ingest and API together."""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time

from .. import __version__
from ..alerts.manager import AlertManager
from ..alerts.notify import Notifier
from ..common.config import load_server_config, resolve_path
from ..common.schema import new_event
from ..common.timeutil import now_iso, parse_duration
from ..common.util import ensure_dir, project_root
from ..detect.engine import DetectionEngine
from ..pipeline.pipeline import Pipeline
from ..store.opensearch_store import OpenSearchOutput
from ..store.sqlite_store import SQLiteStore
from .api import create_app
from .content import CustomContent
from .ingest import IngestServer

log = logging.getLogger("kharibulbul.server")

BANNER = r"""
  _  __ _                _  _             _  _             _
 | |/ /| |__   __ _  _ _(_)| |__   _  _  | || |__   _  _  | |
 | ' < | ' \ / _` || '_| || '_ \ | || | | || '_ \ | || | | |
 |_|\_\|_||_|\__,_||_| |_||_.__/  \_,_| |_||_.__/  \_,_| |_|
        Xarıbülbül SIEM  v{version}  -  listening like a nightingale
"""


class KharibulbulServer:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.started = time.time()
        self.root = project_root()
        data_dir = ensure_dir(resolve_path(cfg, cfg.get("data_dir", "data")))
        scfg = cfg["store"]["sqlite"]
        db_path = scfg.get("path") or os.path.join(data_dir, "kharibulbul.db")
        if not os.path.isabs(db_path):
            db_path = os.path.join(data_dir, os.path.basename(db_path)) if db_path.startswith("data") else resolve_path(cfg, db_path)
        self.store = SQLiteStore(db_path, int(scfg.get("batch_size", 200)), float(scfg.get("flush_interval", 1.0)))
        self.pipeline = Pipeline(cfg)
        self.notifier = Notifier(cfg.get("alerts", {}).get("notify"), base_dir=self.root)
        self.alert_manager = AlertManager(self.store, self.notifier)
        self.rules_dir = resolve_path(cfg, cfg["detect"].get("rules_dir", "rules"))
        self.playbooks_dir = resolve_path(cfg, "playbooks")
        # rules / playbooks written from the dashboard live next to the shipped ones, in their own folder
        custom = str(cfg.get("custom_dir") or "custom")
        if not os.path.isabs(custom):
            found = resolve_path(cfg, custom)
            custom = found if os.path.isdir(found) else os.path.join(self.root, custom)
        self.content = CustomContent(self.rules_dir, self.playbooks_dir, custom)
        rules = self.content.load_rules()
        self.engine = DetectionEngine(rules, self.alert_manager, default_suppress=parse_duration(cfg["detect"].get("default_suppress", "10m")))
        self.detect_enabled = bool(cfg["detect"].get("enabled", True))
        os_cfg = cfg["store"].get("opensearch") or {}
        self.opensearch = None
        if os_cfg.get("enabled"):
            self.opensearch = OpenSearchOutput(os_cfg["url"], os_cfg.get("index_prefix", "kharibulbul"), os_cfg.get("username", ""),
                                               os_cfg.get("password", ""), bool(os_cfg.get("verify_tls", False)))
            self.opensearch.ensure_template()
        tls = cfg["ingest"].get("tcp", {}).get("tls") or {}
        for key in ("cert", "key", "ca"):
            if tls.get(key):
                tls[key] = resolve_path(cfg, tls[key])
        self.ingest = IngestServer(cfg, self.handle_batch, self.handle_agent_hello, self.handle_agent_disconnect)
        self.app = create_app(self)
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------ #
    # data path
    # ------------------------------------------------------------------ #
    def handle_batch(self, envelopes: list[dict], ctx: dict | None = None) -> int:
        """Process a batch of envelopes end-to-end. Runs in a worker thread."""
        agent = (ctx or {}).get("agent") or {}
        remote = (ctx or {}).get("remote")
        for env in envelopes:
            if not isinstance(env, dict):
                continue
            if agent.get("id"):
                env.setdefault("agent.id", agent["id"])
                env.setdefault("agent.name", agent.get("name"))
                env.setdefault("agent.version", agent.get("version"))
                env.setdefault("agent.type", "kharibulbul-agent")
                env.setdefault("host.name", agent.get("host"))
                if agent.get("os"):
                    env.setdefault("host.os.type", agent["os"])
                if agent.get("ip"):
                    env.setdefault("host.ip", agent["ip"])
            elif agent.get("type"):
                env.setdefault("agent.type", agent["type"])
            if remote and "host.ip" not in env:
                env["host.ip"] = remote.split(":")[0] if isinstance(remote, str) else remote
        docs = self.pipeline.process_many([e for e in envelopes if isinstance(e, dict)])
        if not docs:
            return 0
        self.store.put_many(docs)
        if self.detect_enabled:
            for doc in docs:
                self.engine.evaluate(doc)
        if self.opensearch:
            self.opensearch.bulk(docs)
        if agent.get("id"):
            self.store.touch_agent(agent["id"], len(docs))
        return len(docs)

    def handle_agent_hello(self, agent: dict, remote_ip: str) -> None:
        if not agent.get("id"):
            return
        self.store.upsert_agent({"id": agent["id"], "name": agent.get("name"), "host": agent.get("host"), "ip": agent.get("ip"),
                                 "os": agent.get("os"), "version": agent.get("version"), "labels": agent.get("labels"),
                                 "status": "online", "remote": remote_ip})

    def handle_agent_disconnect(self, agent: dict) -> None:
        if agent.get("id"):
            self.store.set_agent_status(agent["id"], "disconnected")

    def reload_rules(self) -> int:
        rules = self.content.load_rules()
        self.engine.load(rules)
        return len(rules)

    def emit_internal(self, action: str, message: str, severity: str = "medium", **fields) -> None:
        """Create an internal SIEM event (agent silent, retention run...) that rules can see."""
        doc = new_event(**{"event.dataset": "kharibulbul.internal", "event.module": "kharibulbul", "event.category": "host",
                           "event.type": "info", "event.action": action, "event.outcome": "unknown", "event.severity": severity,
                           "message": message, "host.name": fields.pop("host", None) or "kharibulbul-server", **fields})
        self.handle_batch([{"raw": __import__("json").dumps(doc), "dataset": "kharibulbul.internal"}], {"agent": {"type": "internal"}})

    # ------------------------------------------------------------------ #
    # background loops
    # ------------------------------------------------------------------ #
    async def _retention_loop(self) -> None:
        days = float(self.cfg["store"].get("retention_days") or 0)   # 0 = keep everything
        if days <= 0:
            log.info("retention: disabled (store.retention_days = 0), events are kept until deleted by hand")
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=3600)
            except asyncio.TimeoutError:
                pass
            if self._stop.is_set():
                break
            if days > 0:
                try:
                    n = await asyncio.get_running_loop().run_in_executor(None, self.store.purge, days)
                    if n:
                        log.info("retention: purged %d events older than %s days", n, days)
                except Exception as exc:  # pragma: no cover
                    log.warning("retention failed: %s", exc)

    async def _agent_monitor(self) -> None:
        timeout = parse_duration(self.cfg.get("agents", {}).get("heartbeat_timeout", "5m"))
        reported: set[str] = set()
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass
            if self._stop.is_set():
                break
            try:
                for a in self.store.list_agents(timeout):
                    if a["status"] in ("silent", "disconnected") and a["seconds_since_seen"] > timeout:
                        if a["id"] not in reported:
                            reported.add(a["id"])
                            self.emit_internal("agent-silent", f"Agent {a.get('name')} on {a.get('host')} has not reported for {int(a['seconds_since_seen'])}s",
                                               severity="medium", host=a.get("host"), **{"agent.id": a["id"], "agent.name": a.get("name")})
                    elif a["status"] == "online" and a["id"] in reported:
                        reported.discard(a["id"])
            except Exception as exc:  # pragma: no cover
                log.warning("agent monitor failed: %s", exc)

    async def _flush_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=2)
            except asyncio.TimeoutError:
                pass

    # ------------------------------------------------------------------ #
    async def run(self) -> None:
        import uvicorn

        _print_banner(__version__)
        self.store.start()
        await self.ingest.start()
        api_cfg = self.cfg.get("api", {})
        config = uvicorn.Config(self.app, host=api_cfg.get("host", "0.0.0.0"), port=int(api_cfg.get("port", 8080)),
                                log_level="warning", access_log=False, loop="asyncio")
        server = uvicorn.Server(config)
        log.info("web UI / API on http://%s:%s/  (docs: /api/docs)", api_cfg.get("host", "0.0.0.0"), api_cfg.get("port", 8080))
        self.emit_internal("server-started", f"Kharibulbul server {__version__} started", severity="informational")
        tasks = [asyncio.create_task(self._retention_loop()), asyncio.create_task(self._agent_monitor())]
        try:
            await server.serve()
        finally:
            self._stop.set()
            for t in tasks:
                t.cancel()
            await self.ingest.stop()
            self.store.stop()
            self.notifier.close()
            log.info("server stopped")


def _ensure_utf8_stdio() -> None:
    """Windows consoles default to cp1252; the banner uses Azerbaijani letters."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _print_banner(version: str) -> None:
    text = BANNER.format(version=version)
    try:
        print(text)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        sys.stdout.buffer.write((text + "\n").encode(enc, errors="replace"))


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=getattr(logging, str(level).upper(), logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("uvicorn").setLevel(logging.WARNING)


def run_server(config_path: str | None) -> None:
    _ensure_utf8_stdio()
    cfg = load_server_config(config_path)
    setup_logging(cfg.get("log_level", "INFO"))
    server = KharibulbulServer(cfg)
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:  # pragma: no cover
        pass
