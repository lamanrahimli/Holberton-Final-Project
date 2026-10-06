"""SQLite + FTS5 event store ("Qarabağ store").

Design
------
* ``events``     - one row per event: hot fields as real columns (fast filters
                   and aggregations) + the full flat document as JSON.
* ``events_fts`` - FTS5 index over message / command line / raw text.
* ``alerts``, ``agents``, ``rule_stats`` - SIEM state.

A single writer thread batches inserts (WAL mode); readers use their own
thread-local connections, so the API never blocks ingest.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import sqlite3
import threading
import time
from datetime import datetime
from typing import Any, Iterable

from ..common.schema import FTS_FIELDS
from ..common.timeutil import from_epoch, parse_timestamp, to_epoch, to_iso
from ..common.util import ensure_dir, json_dumps
from .query import COLUMNS, LIST_FIELDS, compile_query, field_expr

log = logging.getLogger("kharibulbul.store")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
    event_id  TEXT NOT NULL UNIQUE,
    ts        REAL NOT NULL,
    dataset   TEXT, category TEXT, action TEXT, code TEXT, outcome TEXT,
    host TEXT, user TEXT, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, process TEXT,
    agent_id TEXT, severity INTEGER,
    doc       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_host_ts ON events(host, ts);
CREATE INDEX IF NOT EXISTS ix_events_dataset_ts ON events(dataset, ts);
CREATE INDEX IF NOT EXISTS ix_events_action_ts ON events(action, ts);
CREATE INDEX IF NOT EXISTS ix_events_srcip_ts ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS ix_events_user_ts ON events(user, ts);
CREATE INDEX IF NOT EXISTS ix_events_severity_ts ON events(severity, ts);
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(text, tokenize='unicode61');

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT, rule_name TEXT, severity TEXT, severity_score INTEGER,
    status TEXT DEFAULT 'new', group_key TEXT, entity TEXT,
    first_seen REAL, last_seen REAL, created REAL, updated REAL, count INTEGER DEFAULT 1,
    host TEXT, user TEXT, src_ip TEXT, assignee TEXT, doc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_alerts_rule_group ON alerts(rule_id, group_key, status);
CREATE INDEX IF NOT EXISTS ix_alerts_last_seen ON alerts(last_seen);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT, host TEXT, ip TEXT, os TEXT, version TEXT, labels TEXT,
    first_seen REAL, last_seen REAL, events INTEGER DEFAULT 0, status TEXT DEFAULT 'online', remote TEXT
);

CREATE TABLE IF NOT EXISTS rule_stats (
    rule_id TEXT PRIMARY KEY, hits INTEGER DEFAULT 0, alerts INTEGER DEFAULT 0, last_hit REAL
);
"""

OPEN_STATUSES = ("new", "acknowledged", "investigating", "escalated")   # an alert in one of these is still being worked
_OPEN_SQL = ",".join(f"'{s}'" for s in OPEN_STATUSES)

_COLUMN_FIELDS = [
    ("dataset", "event.dataset"), ("category", "event.category"), ("action", "event.action"),
    ("code", "event.code"), ("outcome", "event.outcome"), ("host", "host.name"), ("user", "user.name"),
    ("src_ip", "source.ip"), ("dst_ip", "destination.ip"), ("dst_port", "destination.port"),
    ("process", "process.name"), ("agent_id", "agent.id"), ("severity", "event.severity"),
]


def _epoch(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    dt = parse_timestamp(value)
    return to_epoch(dt) if dt else time.time()


def _fts_text(doc: dict) -> str:
    parts = []
    for field in FTS_FIELDS:
        val = doc.get(field)
        if val is None:
            continue
        if isinstance(val, list):
            parts.extend(str(v) for v in val)
        else:
            parts.append(str(val))
    return "\n".join(parts)[:20000]


class SQLiteStore:
    def __init__(self, path: str = "data/kharibulbul.db", batch_size: int = 200, flush_interval: float = 1.0):
        self.path = path
        if path != ":memory:":
            ensure_dir(os.path.dirname(os.path.abspath(path)))
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._lock = threading.RLock()
        self._local = threading.local()
        self._queue: "queue.Queue[dict | None]" = queue.Queue(maxsize=100_000)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.written = 0
        self._conn = self._connect()
        with self._lock:
            self._conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ #
    # connections
    # ------------------------------------------------------------------ #
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None, timeout=30)
        conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-32000")
        return conn

    def _read(self) -> sqlite3.Connection:
        if self.path == ":memory:":
            return self._conn
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    # ------------------------------------------------------------------ #
    # writer thread
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._thread is None:
            self._stop.clear()
            self._thread = threading.Thread(target=self._writer_loop, name="kb-store-writer", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None
        self.flush()

    def put(self, doc: dict) -> None:
        self._queue.put(doc)

    def put_many(self, docs: Iterable[dict]) -> None:
        for doc in docs:
            self._queue.put(doc)

    def flush(self) -> int:
        """Write everything queued right now (synchronously)."""
        batch: list[dict] = []
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is not None:
                batch.append(item)
        if batch:
            self._write_batch(batch)
        return len(batch)

    def _writer_loop(self) -> None:
        while not self._stop.is_set():
            batch: list[dict] = []
            deadline = time.time() + self.flush_interval
            while len(batch) < self.batch_size:
                timeout = deadline - time.time()
                if timeout <= 0:
                    break
                try:
                    item = self._queue.get(timeout=timeout)
                except queue.Empty:
                    break
                if item is not None:
                    batch.append(item)
            if batch:
                try:
                    self._write_batch(batch)
                except Exception as exc:  # keep the writer alive
                    log.exception("store write failed: %s", exc)

    def _write_batch(self, docs: list[dict]) -> None:
        with self._lock:
            conn = self._conn
            conn.execute("BEGIN")
            try:
                for doc in docs:
                    values = [doc.get(field) for _, field in _COLUMN_FIELDS]
                    values = [json_dumps(v) if isinstance(v, (list, dict)) else v for v in values]
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO events (event_id, ts, dataset, category, action, code, outcome, host, user, "
                        "src_ip, dst_ip, dst_port, process, agent_id, severity, doc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        [doc.get("event.id"), _epoch(doc.get("@timestamp"))] + values + [json_dumps(doc)],
                    )
                    if cur.rowcount:
                        conn.execute("INSERT INTO events_fts(rowid, text) VALUES (?, ?)", (cur.lastrowid, _fts_text(doc)))
                        self.written += 1
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------ #
    # event reads
    # ------------------------------------------------------------------ #
    @staticmethod
    def _time_clause(since: datetime | float | None, until: datetime | float | None) -> tuple[str, list]:
        sql, params = [], []
        if since is not None:
            sql.append("ts >= ?")
            params.append(_epoch(since))
        if until is not None:
            sql.append("ts <= ?")
            params.append(_epoch(until))
        return (" AND ".join(sql) if sql else "1=1"), params

    def search(self, query: str = "", since=None, until=None, limit: int = 100, offset: int = 0,
               sort: str = "desc") -> list[dict]:
        where = compile_query(query)
        tclause, tparams = self._time_clause(since, until)
        order = "DESC" if str(sort).lower() != "asc" else "ASC"
        rows = self._read().execute(
            f"SELECT doc FROM events WHERE {tclause} AND ({where.sql}) ORDER BY ts {order}, id {order} LIMIT ? OFFSET ?",
            tparams + where.params + [int(limit), int(offset)]).fetchall()
        return [json.loads(r["doc"]) for r in rows]

    def count(self, query: str = "", since=None, until=None) -> int:
        where = compile_query(query)
        tclause, tparams = self._time_clause(since, until)
        row = self._read().execute(f"SELECT COUNT(*) AS n FROM events WHERE {tclause} AND ({where.sql})",
                                   tparams + where.params).fetchone()
        return int(row["n"])

    def histogram(self, query: str = "", since=None, until=None, interval: float = 60.0) -> list[dict]:
        where = compile_query(query)
        since_e = _epoch(since) if since is not None else time.time() - 3600
        until_e = _epoch(until) if until is not None else time.time()
        interval = max(1.0, float(interval))
        rows = self._read().execute(
            f"SELECT CAST((ts - ?) / ? AS INTEGER) AS b, COUNT(*) AS n FROM events "
            f"WHERE ts >= ? AND ts <= ? AND ({where.sql}) GROUP BY b ORDER BY b",
            [since_e, interval, since_e, until_e] + where.params).fetchall()
        counts = {int(r["b"]): int(r["n"]) for r in rows}
        buckets = int((until_e - since_e) // interval) + 1
        return [{"ts": to_iso(from_epoch(since_e + i * interval)), "count": counts.get(i, 0)} for i in range(buckets)]

    def terms(self, field: str, query: str = "", since=None, until=None, size: int = 10) -> list[dict]:
        where = compile_query(query)
        tclause, tparams = self._time_clause(since, until)
        if field in LIST_FIELDS:
            sql = (f"SELECT je.value AS k, COUNT(*) AS n FROM events, json_each(events.doc, '$.\"{field}\"') AS je "
                   f"WHERE {tclause} AND ({where.sql}) GROUP BY k ORDER BY n DESC LIMIT ?")
        else:
            expr = field_expr(field)
            sql = (f"SELECT {expr} AS k, COUNT(*) AS n FROM events WHERE {tclause} AND ({where.sql}) "
                   f"AND {expr} IS NOT NULL GROUP BY k ORDER BY n DESC LIMIT ?")
        rows = self._read().execute(sql, tparams + where.params + [int(size)]).fetchall()
        return [{"key": r["k"], "count": int(r["n"])} for r in rows]

    def get_event(self, event_id: str) -> dict | None:
        row = self._read().execute("SELECT doc FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return json.loads(row["doc"]) if row else None

    def purge(self, older_than_days: float) -> int:
        cutoff = time.time() - older_than_days * 86400
        with self._lock:
            conn = self._conn
            conn.execute("BEGIN")
            try:
                conn.execute("DELETE FROM events_fts WHERE rowid IN (SELECT id FROM events WHERE ts < ?)", (cutoff,))
                cur = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                conn.execute("DELETE FROM alerts WHERE last_seen < ? AND status = 'closed'", (cutoff,))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return cur.rowcount

    def oldest_ts(self) -> float | None:
        """Event time of the oldest stored event (epoch seconds) - the start of the "all time" range."""
        row = self._read().execute("SELECT MIN(ts) AS oldest FROM events").fetchone()
        return float(row["oldest"]) if row and row["oldest"] is not None else None

    def db_stats(self) -> dict:
        conn = self._read()
        row = conn.execute("SELECT COUNT(*) AS n, MIN(ts) AS oldest, MAX(ts) AS newest FROM events").fetchone()
        size = os.path.getsize(self.path) if self.path != ":memory:" and os.path.exists(self.path) else 0
        return {
            "events": int(row["n"]),
            "oldest": to_iso(from_epoch(row["oldest"])) if row["oldest"] else None,
            "newest": to_iso(from_epoch(row["newest"])) if row["newest"] else None,
            "size_bytes": size,
            "queued": self._queue.qsize(),
            "written_this_session": self.written,
        }

    # ------------------------------------------------------------------ #
    # alerts
    # ------------------------------------------------------------------ #
    def find_open_alert(self, rule_id: str, group_key: str, not_before: float) -> dict | None:
        row = self._read().execute(
            f"SELECT doc FROM alerts WHERE rule_id = ? AND group_key = ? AND status IN ({_OPEN_SQL}) "
            "AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1", (rule_id, group_key, not_before)).fetchone()
        return json.loads(row["doc"]) if row else None

    def save_alert(self, alert: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO alerts (id, rule_id, rule_name, severity, severity_score, status, group_key, entity, "
                "first_seen, last_seen, created, updated, count, host, user, src_ip, assignee, doc) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (alert["id"], alert.get("rule.id"), alert.get("rule.name"), alert.get("severity"), alert.get("severity_score"),
                 alert.get("status", "new"), alert.get("group_key"), alert.get("entity"), _epoch(alert.get("first_seen")),
                 _epoch(alert.get("last_seen")), _epoch(alert.get("created")), _epoch(alert.get("updated")), alert.get("count", 1),
                 alert.get("host.name"), alert.get("user.name"), alert.get("source.ip"), alert.get("assignee"), json_dumps(alert)))

    def get_alert(self, alert_id: str) -> dict | None:
        row = self._read().execute("SELECT doc FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return json.loads(row["doc"]) if row else None

    def list_alerts(self, status: str | None = None, severity: str | None = None, rule_id: str | None = None,
                    since=None, until=None, text: str | None = None, limit: int = 100, offset: int = 0) -> list[dict]:
        clauses, params = ["1=1"], []
        if status:
            statuses = [s.strip() for s in status.split(",") if s.strip()]
            clauses.append("status IN (%s)" % ",".join("?" * len(statuses)))
            params += statuses
        if severity:
            sevs = [s.strip() for s in severity.split(",") if s.strip()]
            clauses.append("severity IN (%s)" % ",".join("?" * len(sevs)))
            params += sevs
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if since is not None:
            clauses.append("last_seen >= ?")
            params.append(_epoch(since))
        if until is not None:
            clauses.append("last_seen <= ?")
            params.append(_epoch(until))
        if text:
            clauses.append("(LOWER(doc) LIKE ?)")
            params.append(f"%{text.lower()}%")
        rows = self._read().execute(
            f"SELECT doc FROM alerts WHERE {' AND '.join(clauses)} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            params + [int(limit), int(offset)]).fetchall()
        return [json.loads(r["doc"]) for r in rows]

    def alert_counts(self, since=None) -> dict:
        conn = self._read()
        params: list = []
        clause = "1=1"
        if since is not None:
            clause = "last_seen >= ?"
            params.append(_epoch(since))
        by_sev = {r["severity"]: int(r["n"]) for r in conn.execute(
            f"SELECT severity, COUNT(*) AS n FROM alerts WHERE {clause} GROUP BY severity", params)}
        by_status = {r["status"]: int(r["n"]) for r in conn.execute(
            f"SELECT status, COUNT(*) AS n FROM alerts WHERE {clause} GROUP BY status", params)}
        by_rule = [{"rule_id": r["rule_id"], "rule_name": r["rule_name"], "count": int(r["n"])} for r in conn.execute(
            f"SELECT rule_id, rule_name, COUNT(*) AS n FROM alerts WHERE {clause} GROUP BY rule_id ORDER BY n DESC LIMIT 10", params)]
        total = sum(by_status.values())
        return {"total": total, "by_severity": by_sev, "by_status": by_status, "by_rule": by_rule,
                "open": sum(v for k, v in by_status.items() if k != "closed")}

    def alerts_histogram(self, since, until, interval: float) -> list[dict]:
        since_e, until_e = _epoch(since), _epoch(until)
        interval = max(1.0, float(interval))
        rows = self._read().execute(
            "SELECT CAST((last_seen - ?) / ? AS INTEGER) AS b, COUNT(*) AS n FROM alerts WHERE last_seen >= ? AND last_seen <= ? GROUP BY b",
            (since_e, interval, since_e, until_e)).fetchall()
        counts = {int(r["b"]): int(r["n"]) for r in rows}
        buckets = int((until_e - since_e) // interval) + 1
        return [{"ts": to_iso(from_epoch(since_e + i * interval)), "count": counts.get(i, 0)} for i in range(buckets)]

    def alert_tactics(self, since=None, open_only: bool = True) -> list[dict]:
        """Open alerts grouped by MITRE ATT&CK tactic (one alert may carry several tactics)."""
        clauses, params = ["json_extract(m.value, '$.tactic') IS NOT NULL"], []
        if open_only:
            clauses.append(f"alerts.status IN ({_OPEN_SQL})")
        if since is not None:
            clauses.append("alerts.last_seen >= ?")
            params.append(_epoch(since))
        rows = self._read().execute(
            f"SELECT json_extract(m.value, '$.tactic') AS k, COUNT(DISTINCT alerts.id) AS n FROM alerts, json_each(alerts.doc, '$.mitre') AS m "
            f"WHERE {' AND '.join(clauses)} GROUP BY k ORDER BY n DESC", params).fetchall()
        return [{"key": r["k"], "count": int(r["n"])} for r in rows]

    # ------------------------------------------------------------------ #
    # agents
    # ------------------------------------------------------------------ #
    def upsert_agent(self, agent: dict) -> None:
        now = time.time()
        with self._lock:
            row = self._conn.execute("SELECT first_seen, events FROM agents WHERE id = ?", (agent["id"],)).fetchone()
            first_seen = row["first_seen"] if row else now
            events = (row["events"] if row else 0) + int(agent.get("events_delta", 0))
            self._conn.execute(
                "INSERT OR REPLACE INTO agents (id, name, host, ip, os, version, labels, first_seen, last_seen, events, status, remote) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (agent["id"], agent.get("name"), agent.get("host"), json_dumps(agent.get("ip") or []), agent.get("os"),
                 agent.get("version"), json_dumps(agent.get("labels") or {}), first_seen, now, events,
                 agent.get("status", "online"), agent.get("remote")))

    def touch_agent(self, agent_id: str, events_delta: int = 0) -> None:
        with self._lock:
            self._conn.execute("UPDATE agents SET last_seen = ?, events = events + ?, status = 'online' WHERE id = ?",
                               (time.time(), int(events_delta), agent_id))

    def list_agents(self, heartbeat_timeout: float = 300.0) -> list[dict]:
        rows = self._read().execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        out = []
        now = time.time()
        for r in rows:
            d = dict(r)
            d["ip"] = json.loads(d["ip"]) if d.get("ip") else []
            d["labels"] = json.loads(d["labels"]) if d.get("labels") else {}
            d["first_seen"] = to_iso(from_epoch(d["first_seen"])) if d.get("first_seen") else None
            d["last_seen_iso"] = to_iso(from_epoch(d["last_seen"])) if d.get("last_seen") else None
            d["seconds_since_seen"] = round(now - (d.get("last_seen") or now), 1)
            # "pending" = enrolled from the dashboard, has not connected yet
            if d["status"] not in ("disconnected", "pending") and d["seconds_since_seen"] > heartbeat_timeout:
                d["status"] = "silent"
            out.append(d)
        return out

    def get_agent(self, agent_id: str) -> dict | None:
        return next((a for a in self.list_agents(float("inf")) if a["id"] == agent_id), None)

    def delete_agent(self, agent_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
        return cur.rowcount > 0

    def set_agent_status(self, agent_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE agents SET status = ? WHERE id = ?", (status, agent_id))

    # ------------------------------------------------------------------ #
    # rule stats
    # ------------------------------------------------------------------ #
    def bump_rule(self, rule_id: str, hits: int = 0, alerts: int = 0) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO rule_stats (rule_id, hits, alerts, last_hit) VALUES (?,?,?,?) "
                "ON CONFLICT(rule_id) DO UPDATE SET hits = hits + excluded.hits, alerts = alerts + excluded.alerts, last_hit = excluded.last_hit",
                (rule_id, hits, alerts, time.time()))

    def rule_stats(self) -> dict[str, dict]:
        rows = self._read().execute("SELECT * FROM rule_stats").fetchall()
        return {r["rule_id"]: {"hits": r["hits"], "alerts": r["alerts"],
                               "last_hit": to_iso(from_epoch(r["last_hit"])) if r["last_hit"] else None} for r in rows}

    def close(self) -> None:
        self.stop()
        with self._lock:
            self._conn.close()
