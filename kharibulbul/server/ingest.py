"""Ingest listeners.

* TCP (optionally TLS) newline-delimited JSON - the Kharibulbul agent protocol:

      -> {"type": "hello", "agent": {...}, "secret": "..."}
      <- {"type": "welcome", "server": "...", "time": "..."}
      -> {"type": "batch", "id": 7, "events": [envelope, ...]}
      <- {"type": "ack", "id": 7, "n": 12}
      -> {"type": "heartbeat"}
      <- {"type": "pong"}

  An *envelope* is ``{"raw": "...", "dataset": "...", "@timestamp": "...",
  "host.name": "...", "log.file.path": "...", "fields": {...}}``.

* UDP / TCP syslog - any device or rsyslog/journald forwarder can send here;
  each line becomes an envelope with ``dataset: syslog``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from typing import Awaitable, Callable

from ..common.timeutil import now_iso
from ..common.util import json_dumps

log = logging.getLogger("kharibulbul.ingest")

BatchHandler = Callable[[list[dict], dict], int]


class _SyslogUDP(asyncio.DatagramProtocol):
    def __init__(self, server: "IngestServer"):
        self.server = server

    def datagram_received(self, data: bytes, addr) -> None:
        self.server.on_syslog(data, addr[0], "udp")


class IngestServer:
    def __init__(self, cfg: dict, on_batch: BatchHandler, on_agent_hello: Callable[[dict, str], None],
                 on_agent_disconnect: Callable[[dict], None]):
        self.cfg = cfg.get("ingest", {})
        self.on_batch = on_batch
        self.on_agent_hello = on_agent_hello
        self.on_agent_disconnect = on_agent_disconnect
        self.servers: list[asyncio.AbstractServer] = []
        self.transports: list[asyncio.BaseTransport] = []
        self.connections = 0
        self.received_events = 0
        self.received_batches = 0
        self.rejected = 0
        self.syslog_messages = 0
        self._loop: asyncio.AbstractEventLoop | None = None

    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        limit = int(self.cfg.get("max_line_bytes", 1048576))
        tcp = self.cfg.get("tcp", {})
        if tcp.get("enabled", True):
            ctx = self._tls_context(tcp.get("tls") or {})
            srv = await asyncio.start_server(self._handle_agent, tcp.get("host", "0.0.0.0"), int(tcp.get("port", 5044)),
                                             ssl=ctx, limit=limit)
            self.servers.append(srv)
            log.info("agent ingest listening on %s:%s (tls=%s)", tcp.get("host"), tcp.get("port"), bool(ctx))
        udp = self.cfg.get("syslog_udp", {})
        if udp.get("enabled", True):
            transport, _ = await self._loop.create_datagram_endpoint(
                lambda: _SyslogUDP(self), local_addr=(udp.get("host", "0.0.0.0"), int(udp.get("port", 5514))))
            self.transports.append(transport)
            log.info("syslog UDP listening on %s:%s", udp.get("host"), udp.get("port"))
        stcp = self.cfg.get("syslog_tcp", {})
        if stcp.get("enabled"):
            srv = await asyncio.start_server(self._handle_syslog_tcp, stcp.get("host", "0.0.0.0"), int(stcp.get("port", 5514)), limit=limit)
            self.servers.append(srv)
            log.info("syslog TCP listening on %s:%s", stcp.get("host"), stcp.get("port"))

    async def stop(self) -> None:
        for srv in self.servers:
            srv.close()
            await srv.wait_closed()
        for t in self.transports:
            t.close()

    @staticmethod
    def _tls_context(tls: dict) -> ssl.SSLContext | None:
        if not tls.get("enabled"):
            return None
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(tls["cert"], tls.get("key") or None)
        if tls.get("ca"):
            ctx.load_verify_locations(tls["ca"])
            ctx.verify_mode = ssl.CERT_REQUIRED  # mutual TLS when a CA is configured
        return ctx

    # ------------------------------------------------------------------ #
    async def _handle_agent(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        remote = f"{peer[0]}:{peer[1]}" if peer else "?"
        self.connections += 1
        secret = self.cfg.get("shared_secret") or ""
        agent: dict = {}
        authenticated = not secret
        log.info("agent connection from %s", remote)
        try:
            while True:
                try:
                    line = await reader.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    await self._send(writer, {"type": "error", "error": "line too long"})
                    self.rejected += 1
                    continue
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    self.rejected += 1
                    await self._send(writer, {"type": "error", "error": "invalid json"})
                    continue
                mtype = msg.get("type")
                if mtype == "hello":
                    if secret and msg.get("secret") != secret:
                        self.rejected += 1
                        await self._send(writer, {"type": "error", "error": "bad shared secret"})
                        log.warning("agent from %s rejected: bad shared secret", remote)
                        break
                    authenticated = True
                    agent = msg.get("agent") or {}
                    agent["remote"] = remote
                    self.on_agent_hello(agent, peer[0] if peer else "")
                    await self._send(writer, {"type": "welcome", "server": "kharibulbul", "time": now_iso()})
                    log.info("agent %s (%s) registered from %s", agent.get("name"), agent.get("id"), remote)
                    continue
                if not authenticated:
                    self.rejected += 1
                    await self._send(writer, {"type": "error", "error": "hello required"})
                    break
                if mtype in ("batch", "events"):
                    events = msg.get("events") or []
                    self.received_batches += 1
                    self.received_events += len(events)
                    n = await self._loop.run_in_executor(None, self.on_batch, events, {"agent": agent, "remote": remote})
                    await self._send(writer, {"type": "ack", "id": msg.get("id"), "n": n})
                elif mtype == "event":
                    self.received_events += 1
                    await self._loop.run_in_executor(None, self.on_batch, [msg], {"agent": agent, "remote": remote})
                elif mtype == "heartbeat":
                    if agent.get("id"):
                        self.on_agent_hello(agent, peer[0] if peer else "")
                    await self._send(writer, {"type": "pong", "time": now_iso()})
                else:
                    await self._send(writer, {"type": "error", "error": f"unknown message type {mtype!r}"})
        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
            pass
        except Exception as exc:  # pragma: no cover
            log.exception("agent connection %s failed: %s", remote, exc)
        finally:
            if agent:
                self.on_agent_disconnect(agent)
                log.info("agent %s disconnected (%s)", agent.get("name"), remote)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _send(writer: asyncio.StreamWriter, obj: dict) -> None:
        writer.write(json_dumps(obj).encode("utf-8") + b"\n")
        await writer.drain()

    # ------------------------------------------------------------------ #
    def on_syslog(self, data: bytes, ip: str, transport: str) -> None:
        text = data.decode("utf-8", errors="replace")
        envelopes = []
        for line in text.splitlines():
            if line.strip():
                envelopes.append({"raw": line, "dataset": "syslog", "agent.type": f"syslog-{transport}",
                                  "host.ip": ip, "@timestamp": None})
        if not envelopes:
            return
        self.syslog_messages += len(envelopes)
        ctx = {"agent": {}, "remote": ip}
        if self._loop is not None and self._loop.is_running():
            self._loop.run_in_executor(None, self.on_batch, envelopes, ctx)
        else:  # pragma: no cover - tests
            self.on_batch(envelopes, ctx)

    async def _handle_syslog_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                self.on_syslog(line, ip, "tcp")
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    def snapshot(self) -> dict:
        return {"connections": self.connections, "batches": self.received_batches, "events": self.received_events,
                "rejected": self.rejected, "syslog_messages": self.syslog_messages, "time": time.time()}
