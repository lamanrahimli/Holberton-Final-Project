"""Query language compiler + SQLite store tests."""
from __future__ import annotations

import time

import pytest

from kharibulbul.common.schema import finalize, new_event
from kharibulbul.store.query import QueryError, compile_query
from kharibulbul.store.sqlite_store import SQLiteStore


def test_compile_basic_terms():
    c = compile_query("event.action:logon-failed")
    assert "LOWER(action) = ?" in c.sql and c.params == ["logon-failed"]
    c = compile_query("source.ip:10.10.20.*")
    assert "LIKE" in c.sql and c.params == ["10.10.20.%"]
    c = compile_query("destination.port:>1024")
    assert ">" in c.sql and c.params == [1024.0]
    c = compile_query("tags:threat-intel-match")
    assert "json_each" in c.sql
    c = compile_query('"certutil urlcache"')
    assert "events_fts" in c.sql and c.params == ['"certutil" "urlcache"']
    c = compile_query("_exists_:process.command_line")
    assert "IS NOT NULL" in c.sql
    c = compile_query("")
    assert c.sql == "1=1"


def test_compile_boolean_logic():
    c = compile_query("(event.code:4625 OR event.action:ssh-login-failed) AND NOT user.name:svc")
    assert c.sql.count("OR") == 1 and "NOT" in c.sql and c.params == ["4625", "ssh-login-failed", "svc"]
    c = compile_query("host.name:ws01 event.code:4625")  # implicit AND
    assert "AND" in c.sql


def test_compile_errors():
    with pytest.raises(QueryError):
        compile_query("(event.code:4625")
    with pytest.raises(QueryError):
        compile_query("destination.port:>abc")


def _doc(**kw):
    return finalize(new_event(**kw))


def test_store_roundtrip_and_aggregations(tmp_path):
    store = SQLiteStore(str(tmp_path / "t.db"))
    now = time.time()
    docs = []
    for i in range(30):
        docs.append(_doc(**{"@timestamp": now - i, "event.dataset": "windows.security", "event.action": "logon-failed" if i % 3 else "logon-success",
                            "event.code": "4625" if i % 3 else "4624", "host.name": "ws01" if i % 2 else "ws02", "source.ip": f"10.10.99.{i % 4}",
                            "user.name": f"user{i % 5}", "message": f"Logon FAILED for user{i % 5} certutil test {i}", "tags": ["a", "b"] if i % 2 else ["c"],
                            "destination.port": 1000 + i}))
    store.put_many(docs)
    assert store.flush() == 30
    assert store.count() == 30
    assert store.count("event.action:logon-failed") == 20
    assert store.count("event.code:4625 AND host.name:ws01") == 10
    assert store.count("tags:c") == 15
    assert store.count("destination.port:>1020") == 9
    assert store.count("source.ip:10.10.99.1 OR source.ip:10.10.99.2") == 15
    assert store.count('"certutil"') == 30
    assert store.count("user0*") == 6  # fts prefix on message
    hits = store.search("event.action:logon-success", limit=5)
    assert len(hits) == 5 and all(h["event.action"] == "logon-success" for h in hits)
    terms = store.terms("host.name")
    assert {t["key"] for t in terms} == {"ws01", "ws02"}
    terms = store.terms("tags", size=5)
    assert {t["key"] for t in terms} == {"a", "b", "c"}
    hist = store.histogram("", now - 60, now, 10)
    assert sum(b["count"] for b in hist) == 30
    doc = store.get_event(docs[0]["event.id"])
    assert doc["message"] == docs[0]["message"]
    # duplicate ids are ignored
    store.put(docs[0])
    store.flush()
    assert store.count() == 30
    stats = store.db_stats()
    assert stats["events"] == 30
    store.close()


def test_alerts_and_agents(tmp_path):
    store = SQLiteStore(str(tmp_path / "a.db"))
    alert = {"id": "abc", "rule.id": "KB-1", "rule.name": "r", "severity": "high", "severity_score": 75, "status": "new",
             "group_key": "host.name=ws01", "entity": "ws01", "first_seen": "2026-09-27T10:00:00Z", "last_seen": "2026-09-27T10:00:00Z",
             "created": "2026-09-27T10:00:00Z", "updated": "2026-09-27T10:00:00Z", "count": 3, "host.name": "ws01"}
    store.save_alert(alert)
    assert store.get_alert("abc")["count"] == 3
    assert store.find_open_alert("KB-1", "host.name=ws01", not_before=0)["id"] == "abc"
    assert store.find_open_alert("KB-1", "other", not_before=0) is None
    assert store.list_alerts(status="new")[0]["id"] == "abc"
    assert store.list_alerts(severity="low") == []
    counts = store.alert_counts()
    assert counts["total"] == 1 and counts["by_severity"]["high"] == 1 and counts["open"] == 1
    alert["status"] = "closed"
    store.save_alert(alert)
    assert store.find_open_alert("KB-1", "host.name=ws01", not_before=0) is None
    store.upsert_agent({"id": "ag1", "name": "ws01", "host": "ws01", "ip": ["10.10.20.10"], "os": "windows", "version": "0.1.0"})
    store.touch_agent("ag1", 5)
    agents = store.list_agents()
    assert agents[0]["events"] == 5 and agents[0]["status"] == "online"
    store.bump_rule("KB-1", hits=2, alerts=1)
    store.bump_rule("KB-1", hits=1)
    assert store.rule_stats()["KB-1"]["hits"] == 3
    store.close()
