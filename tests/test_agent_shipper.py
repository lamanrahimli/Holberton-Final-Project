"""Agent shipper / spool: batches are split to fit the protocol line limit and delivered exactly once."""
from __future__ import annotations

import json
import socket
import socketserver
import threading

import pytest

from kharibulbul.agent.shipper import TRUNCATED, Shipper
from kharibulbul.agent.spool import Spool
from kharibulbul.common.config import AGENT_DEFAULTS, deep_merge
from kharibulbul.common.util import json_dumps

LINE_LIMIT = 1048576   # the server default (ingest.max_line_bytes)


class _Handler(socketserver.StreamRequestHandler):
    """Speaks the agent protocol and rejects lines above the limit like the real ingest server."""

    def handle(self):
        srv = self.server
        for line in self.rfile:
            if len(line) > srv.line_limit:
                srv.rejected += 1
                self._reply({"type": "error", "error": "line too long"})
                continue
            msg = json.loads(line)
            if msg["type"] == "hello":
                self._reply({"type": "welcome"})
            elif msg["type"] == "batch":
                srv.lines.append(len(line))
                srv.events.extend(msg["events"])
                self._reply({"type": "ack", "id": msg["id"], "n": len(msg["events"])})

    def _reply(self, obj):
        self.wfile.write(json.dumps(obj).encode() + b"\n")


@pytest.fixture
def fake_server():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    srv.line_limit, srv.lines, srv.events, srv.rejected = LINE_LIMIT, [], [], 0
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _shipper(tmp_path, port=1, **batch):
    cfg = deep_merge(AGENT_DEFAULTS, {"server": {"host": "127.0.0.1", "port": port}, "batch": batch})
    return Shipper(cfg, {"id": "t", "name": "t"}, str(tmp_path / "spool"))


def _events(n, size):
    return [{"raw": f"{i:04d} " + "x" * size, "dataset": "windows.powershell", "host.name": "h"} for i in range(n)]


def test_chunks_keep_every_line_below_the_limit(tmp_path):
    shipper = _shipper(tmp_path, max_bytes=20000)
    batch = _events(100, 1500)
    chunks = list(shipper._chunks(batch))
    assert len(chunks) > 1
    assert [e for c in chunks for e in c] == batch          # nothing lost, order kept
    for i, chunk in enumerate(chunks):
        line = json_dumps({"type": "batch", "id": i, "events": chunk}).encode("utf-8") + b"\n"
        assert len(line) <= 20000


def test_single_oversized_event_is_truncated(tmp_path):
    shipper = _shipper(tmp_path, max_bytes=8192)
    big = {"raw": "y" * 50000, "dataset": "windows.powershell"}
    (chunk,) = list(shipper._chunks([big]))
    assert chunk[0]["raw"].endswith(TRUNCATED) and chunk[0]["dataset"] == "windows.powershell"
    assert len(json_dumps({"type": "batch", "id": 1, "events": chunk}).encode("utf-8")) + 1 <= 8192
    assert big["raw"] == "y" * 50000                        # the caller's envelope is untouched


def test_batch_above_server_line_limit_is_delivered(tmp_path, fake_server):
    """Regression: 100 PowerShell events of ~11 kB are 1.1 MB in one line - the server refused it forever."""
    shipper = _shipper(tmp_path, port=fake_server.server_address[1])
    batch = _events(100, 11000)
    assert len(json_dumps({"type": "batch", "id": 1, "events": batch})) > LINE_LIMIT
    assert shipper._deliver(batch) == 100
    shipper._close()
    assert fake_server.events == batch and fake_server.rejected == 0
    assert max(fake_server.lines) <= shipper.max_bytes


def test_line_too_long_reply_lowers_the_limit(tmp_path, fake_server):
    fake_server.line_limit = 100000                         # server stricter than the agent's batch.max_bytes
    shipper = _shipper(tmp_path, port=fake_server.server_address[1])
    batch = _events(100, 11000)
    assert shipper._deliver(batch) == 0 and shipper._send_failed
    assert shipper.max_bytes < 524288
    done = 0
    for _ in range(5):                                      # the retries converge below the server's limit
        done += shipper._deliver(batch[done:])
        if done == 100:
            break
    shipper._close()
    assert fake_server.events == batch                      # delivered once each, in order


def test_spool_drain_keeps_only_the_undelivered_rest(tmp_path):
    spool = Spool(str(tmp_path / "spool"))
    batch = _events(10, 10)
    spool.append(batch)
    assert spool.drain(lambda b: 4) == 4 and spool.pending() == 1
    seen = []
    assert spool.drain(lambda b: seen.extend(b) or len(b)) == 6
    assert seen == batch[4:] and spool.pending() == 0


def test_spool_drain_stops_when_nothing_is_delivered(tmp_path):
    spool = Spool(str(tmp_path / "spool"))
    spool.append(_events(3, 10))
    spool.append(_events(2, 10))
    assert spool.drain(lambda b: 0) == 0 and spool.pending() == 2


def test_unreachable_server_delivers_nothing(tmp_path):
    with socket.socket() as s:                              # a port nobody listens on
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    assert _shipper(tmp_path, port=port)._deliver(_events(2, 10)) == 0
