"""Agent inputs. Each input runs in its own thread and emits envelopes through ``emit(envelope)``."""
from __future__ import annotations

import logging
import threading
from typing import Callable

log = logging.getLogger("kharibulbul.agent.inputs")

Emit = Callable[[dict], None]


class Input(threading.Thread):
    """Base class: subclasses implement ``run_once()`` (polling) or override ``run``."""

    type_name = "base"

    def __init__(self, cfg: dict, emit: Emit, state_dir: str, host_fields: dict):
        super().__init__(name=f"kb-input-{cfg.get('type', 'input')}-{cfg.get('id', '')}", daemon=True)
        self.cfg = cfg
        self.emit_fn = emit
        self.state_dir = state_dir
        self.host_fields = host_fields
        self.interval = float(cfg.get("interval", 1.0))
        self._stop = threading.Event()
        self.emitted = 0
        self.errors = 0

    def emit(self, raw: str, dataset: str | None = None, ts: str | None = None, path: str | None = None,
             fields: dict | None = None) -> None:
        env: dict = {"raw": raw, "dataset": dataset or self.cfg.get("dataset") or "generic"}
        if ts:
            env["@timestamp"] = ts
        if path:
            env["log.file.path"] = path
        merged = dict(self.cfg.get("fields") or {})
        if fields:
            merged.update(fields)
        if merged:
            env["fields"] = merged
        env.update(self.host_fields)
        self.emit_fn(env)
        self.emitted += 1

    def stop(self) -> None:
        self._stop.set()

    def run_once(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def run(self) -> None:
        log.info("input %s started", self.name)
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:
                self.errors += 1
                log.warning("input %s error: %s", self.name, exc, exc_info=self.errors <= 3)
                self._stop.wait(min(30, self.interval * 5))
            self._stop.wait(self.interval)


_TYPES: dict[str, type[Input]] = {}


def register(name: str):
    def deco(cls: type[Input]) -> type[Input]:
        _TYPES[name] = cls
        cls.type_name = name
        return cls
    return deco


def build_inputs(configs: list[dict], emit: Emit, state_dir: str, host_fields: dict) -> list[Input]:
    from . import command, file, journald, winlog  # noqa: F401  (registration)
    inputs: list[Input] = []
    for i, cfg in enumerate(configs or []):
        if not cfg.get("enabled", True):
            continue
        typ = cfg.get("type")
        cls = _TYPES.get(typ)
        if cls is None:
            log.error("unknown input type %r (have: %s)", typ, ", ".join(sorted(_TYPES)))
            continue
        cfg = dict(cfg)
        cfg.setdefault("id", str(i))
        inputs.append(cls(cfg, emit, state_dir, host_fields))
    return inputs
