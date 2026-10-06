"""Shipper: batches envelopes and delivers them to the server over TCP/TLS with acks and a disk spool."""
from __future__ import annotations

import json
import logging
import queue
import random
import socket
import ssl
import threading
import time

from ..common.util import json_dumps
from .spool import Spool

log = logging.getLogger("kharibulbul.agent.shipper")

LINE_OVERHEAD = 64        # room for the {"type":"batch","id":n,"events":[...]} wrapper
MIN_LINE_BYTES = 4096     # floor when the limit is lowered after a "line too long" reply
TRUNCATED = " ...[truncated by agent]"


class Shipper(threading.Thread):
    def __init__(self, cfg: dict, agent_info: dict, spool_dir: str):
        super().__init__(name="kb-shipper", daemon=True)
        self.cfg = cfg
        self.server = cfg["server"]
        self.agent_info = agent_info
        self.batch_size = int(cfg["batch"].get("size", 100))
        self.flush_interval = float(cfg["batch"].get("flush_interval", 1.0))
        # one protocol line must stay below the server's ingest.max_line_bytes (1 MiB by default)
        self.max_bytes = int(cfg["batch"].get("max_bytes", 524288))
        self.heartbeat_interval = float(cfg.get("heartbeat_interval", 30))
        self.queue: "queue.Queue[dict]" = queue.Queue(maxsize=50_000)
        self.spool = Spool(spool_dir, float(cfg["spool"].get("max_mb", 200)))
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._rfile = None
        self._seq = 0
        self.sent_events = 0
        self.sent_batches = 0
        self.failures = 0
        self.connected = False
        self._last_send = time.time()
        self._backoff = float(self.server.get("reconnect_min", 1))
        self._send_failed = False

    # ------------------------------------------------------------------ #
    def enqueue(self, envelope: dict) -> None:
        try:
            self.queue.put(envelope, timeout=5)
        except queue.Full:
            # backpressure: persist straight to disk instead of dropping
            self.spool.append([envelope])

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------ #
    def _connect(self) -> bool:
        host, port = self.server["host"], int(self.server.get("port", 5044))
        tls = self.server.get("tls") or {}
        try:
            raw = socket.create_connection((host, port), timeout=10)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock: socket.socket = raw
            if tls.get("enabled"):
                ctx = ssl.create_default_context()
                if tls.get("ca"):
                    ctx.load_verify_locations(tls["ca"])
                if not tls.get("verify", True):
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                if tls.get("cert"):
                    ctx.load_cert_chain(tls["cert"], tls.get("key") or None)
                sock = ctx.wrap_socket(raw, server_hostname=host)
            sock.settimeout(30)
            self._sock = sock
            self._rfile = sock.makefile("rb")
            hello = {"type": "hello", "agent": self.agent_info, "secret": self.server.get("shared_secret") or ""}
            self._send_obj(hello)
            reply = self._read_obj()
            if not reply or reply.get("type") != "welcome":
                log.error("server rejected hello: %s", reply)
                self._close()
                return False
            self.connected = True
            log.info("connected to %s:%s (tls=%s)", host, port, bool(tls.get("enabled")))
            return True
        except (OSError, ssl.SSLError) as exc:
            log.warning("connect to %s:%s failed: %s", host, port, exc)
            self._close()
            return False

    def _close(self) -> None:
        self.connected = False
        try:
            if self._rfile:
                self._rfile.close()
        except Exception:
            pass
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock, self._rfile = None, None

    def _send_obj(self, obj: dict) -> int:
        assert self._sock is not None
        data = json_dumps(obj).encode("utf-8") + b"\n"
        self._sock.sendall(data)
        return len(data)

    def _read_obj(self) -> dict | None:
        assert self._rfile is not None
        line = self._rfile.readline()
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _send_batch(self, batch: list[dict]) -> bool:
        if not self.connected and not self._connect():
            return False
        self._seq += 1
        try:
            sent = self._send_obj({"type": "batch", "id": self._seq, "events": batch})
            reply = self._read_obj()
            if not reply or reply.get("type") != "ack":
                if reply and reply.get("error") == "line too long":
                    # the server's ingest.max_line_bytes is below our batch.max_bytes: split finer on the retry
                    self.max_bytes = max(MIN_LINE_BYTES, min(self.max_bytes, sent) // 2)
                    log.warning("server line limit hit with %d bytes, batch.max_bytes lowered to %d", sent, self.max_bytes)
                raise OSError(f"no ack (got {reply})")
            self.sent_events += len(batch)
            self.sent_batches += 1
            self._last_send = time.time()
            self._backoff = float(self.server.get("reconnect_min", 1))
            return True
        except (OSError, ssl.SSLError) as exc:
            self.failures += 1
            self._send_failed = True
            log.warning("send failed: %s", exc)
            self._close()
            return False

    def _fit(self, env: dict, budget: int) -> dict:
        """An envelope that alone exceeds the line limit is shipped with its raw text cut short."""
        raw = str(env.get("raw") or "")
        env = dict(env)
        while raw and len(json_dumps(env).encode("utf-8")) + 1 > budget:
            raw = raw[: len(raw) // 2]
            env["raw"] = raw + TRUNCATED
        log.warning("oversized event (%s) truncated to fit batch.max_bytes", env.get("dataset"))
        return env

    def _chunks(self, batch: list[dict]):
        """Split a batch so that every protocol line stays below ``batch.max_bytes``."""
        budget = max(MIN_LINE_BYTES, self.max_bytes) - LINE_OVERHEAD
        chunk: list[dict] = []
        size = 0
        for env in batch:
            n = len(json_dumps(env).encode("utf-8")) + 1
            if n > budget:
                env = self._fit(env, budget)
                n = len(json_dumps(env).encode("utf-8")) + 1
            if chunk and size + n > budget:
                yield chunk
                chunk, size = [], 0
            chunk.append(env)
            size += n
        if chunk:
            yield chunk

    def _deliver(self, batch: list[dict]) -> int:
        """Send a batch as one or more protocol lines; returns how many events were acknowledged."""
        done = 0
        for chunk in self._chunks(batch):
            if not self._send_batch(chunk):
                break
            done += len(chunk)
        return done

    def _heartbeat(self) -> None:
        if not self.connected:
            return
        try:
            self._send_obj({"type": "heartbeat"})
            reply = self._read_obj()
            if not reply or reply.get("type") != "pong":
                raise OSError("no pong")
            self._last_send = time.time()
            self._backoff = float(self.server.get("reconnect_min", 1))
        except (OSError, ssl.SSLError) as exc:
            log.warning("heartbeat failed: %s", exc)
            self._close()

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        while not self._stop.is_set():
            if not self.connected:
                # a rejected send backs off like a failed connect (no tight reconnect loop)
                if self._send_failed or not self._connect():
                    self._send_failed = False
                    # exponential backoff with jitter, then keep collecting into the spool
                    delay = self._backoff + random.uniform(0, 0.5)
                    self._backoff = min(self._backoff * 2, float(self.server.get("reconnect_max", 30)))
                    self._spool_pending(max_wait=delay)
                    continue
            if self.spool.pending():
                n = self.spool.drain(self._deliver)
                if n:
                    log.info("replayed %d spooled events", n)
                if not self.connected:
                    continue
            batch = self._collect()
            if batch:
                self.spool.append(batch[self._deliver(batch):])
            elif time.time() - self._last_send >= self.heartbeat_interval:
                self._heartbeat()
        # shutdown: try to deliver what is left, else spool it
        rest = self._collect(drain_all=True)
        if rest:
            self.spool.append(rest[self._deliver(rest):])
        self._close()

    def _collect(self, drain_all: bool = False) -> list[dict]:
        batch: list[dict] = []
        deadline = time.time() + self.flush_interval
        while len(batch) < (self.batch_size if not drain_all else 10_000):
            timeout = deadline - time.time()
            if timeout <= 0 and not drain_all:
                break
            try:
                batch.append(self.queue.get(timeout=max(0.01, timeout) if not drain_all else 0.05))
            except queue.Empty:
                break
        return batch

    def _spool_pending(self, max_wait: float) -> None:
        """While disconnected, move queued events to disk so inputs never block."""
        end = time.time() + max_wait
        while time.time() < end and not self._stop.is_set():
            batch = self._collect()
            if batch:
                self.spool.append(batch)
            else:
                time.sleep(0.2)
