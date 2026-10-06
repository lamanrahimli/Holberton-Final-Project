"""Bülbül agent entry point."""
from __future__ import annotations

import logging
import os
import platform
import signal
import threading
import time

from .. import __version__
from ..common.config import load_agent_config, resolve_path
from ..common.util import ensure_dir, hostname, local_ips, new_id
from .inputs import build_inputs
from .shipper import Shipper

log = logging.getLogger("kharibulbul.agent")


def _agent_id(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
            if value:
                return value
    except OSError:
        pass
    ensure_dir(os.path.dirname(path) or ".")
    value = new_id()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(value)
    return value


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        data_dir = ensure_dir(resolve_path(cfg, os.path.dirname(cfg["agent"].get("id_file", "data/agent.id")) or "data"))
        # an id issued by the server's "Add agent" wizard (agent.id) wins over the locally generated one
        self.id = str(cfg["agent"].get("id") or "").strip() or _agent_id(
            os.path.join(data_dir, os.path.basename(cfg["agent"].get("id_file", "agent.id"))))
        self.name = cfg["agent"].get("name") or hostname()
        os_type = {"windows": "windows", "linux": "linux", "darwin": "macos"}.get(platform.system().lower(), platform.system().lower())
        self.info = {
            "id": self.id, "name": self.name, "host": hostname(), "ip": local_ips(str(cfg["server"].get("host") or "")), "os": os_type,
            "os_name": f"{platform.system()} {platform.release()}", "version": __version__,
            "labels": cfg["agent"].get("labels") or {}, "python": platform.python_version(),
        }
        host_fields = {"host.name": hostname(), "host.os.type": os_type, "host.os.name": self.info["os_name"],
                       "agent.id": self.id, "agent.name": self.name, "agent.version": __version__, "agent.type": "kharibulbul-agent"}
        if self.info["ip"]:
            host_fields["host.ip"] = self.info["ip"]
        spool_dir = resolve_path(cfg, cfg["spool"].get("dir", "data/spool"))
        self.shipper = Shipper(cfg, self.info, spool_dir)
        state_dir = ensure_dir(os.path.join(data_dir, "agent-state"))
        self.inputs = build_inputs(cfg.get("inputs") or [], self.shipper.enqueue, state_dir, host_fields)
        self._stop = threading.Event()

    def run(self) -> None:
        log.info("Bülbül agent %s (%s) starting: %d inputs -> %s:%s", self.name, self.id[:8], len(self.inputs),
                 self.cfg["server"]["host"], self.cfg["server"].get("port", 5044))
        self.shipper.start()
        for inp in self.inputs:
            inp.start()
        try:
            signal.signal(signal.SIGTERM, lambda *_: self._stop.set())
        except (ValueError, OSError):  # not main thread / unsupported
            pass
        last_report = time.time()
        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
                if time.time() - last_report > 60:
                    last_report = time.time()
                    log.info("status: connected=%s sent=%d batches=%d queued=%d spooled=%d failures=%d inputs=%s",
                             self.shipper.connected, self.shipper.sent_events, self.shipper.sent_batches,
                             self.shipper.queue.qsize(), self.shipper.spool.pending(), self.shipper.failures,
                             {i.name.replace("kb-input-", ""): i.emitted for i in self.inputs})
        except KeyboardInterrupt:
            pass
        finally:
            log.info("agent stopping")
            for inp in self.inputs:
                inp.stop()
            self.shipper.stop()
            self.shipper.join(timeout=15)


def run_agent(config_path: str | None) -> None:
    cfg = load_agent_config(config_path)
    logging.basicConfig(level=getattr(logging, str(cfg.get("log_level", "INFO")).upper(), logging.INFO),
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    Agent(cfg).run()
