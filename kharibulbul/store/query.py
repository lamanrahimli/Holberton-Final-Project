"""Kharibulbul Query Language (KQL-ish) -> SQLite SQL.

Examples
--------
    event.action:logon-failed AND source.ip:10.0.0.*
    host.name:ws01 NOT user.name:svc_backup
    (event.code:4625 OR event.action:ssh-login-failed) AND destination.port:>1024
    tags:threat-intel-match
    process.name:(certutil.exe OR mshta.exe OR regsvr32.exe)   <- one field, several values
    "certutil -urlcache"            <- free text, full-text search
    _exists_:process.command_line

Grammar
-------
    query   := or_expr
    or_expr := and_expr ('OR' and_expr)*
    and_expr:= not_expr (('AND')? not_expr)*        (implicit AND)
    not_expr:= 'NOT' not_expr | '!' not_expr | primary
    primary := '(' query ')' | field ':' [op] value | value
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# fields extracted into real columns by SQLiteStore
COLUMNS = {
    "@timestamp": "ts", "event.dataset": "dataset", "event.category": "category", "event.action": "action",
    "event.code": "code", "event.outcome": "outcome", "host.name": "host", "user.name": "user",
    "source.ip": "src_ip", "destination.ip": "dst_ip", "destination.port": "dst_port",
    "process.name": "process", "agent.id": "agent_id", "event.severity": "severity",
}
LIST_FIELDS = {"tags", "related.ip", "related.user", "related.hosts", "related.hash", "process.args", "dns.answers.data",
               "host.ip", "kharibulbul.ecs.problems"}
NUMERIC_FIELDS = {"destination.port", "source.port", "event.severity", "process.pid", "process.parent.pid",
                  "http.response.status_code", "http.response.body.bytes", "winlog.record_id", "process.args_count"}

_TOKEN = re.compile(r"""
    \s*(?:
        (?P<lpar>\() | (?P<rpar>\)) |
        (?P<and>AND\b) | (?P<or>OR\b) | (?P<not>NOT\b|!) |
        (?P<term>(?P<field>[@A-Za-z_][\w.@-]*)\s*:\s*(?P<op>>=|<=|>|<)?\s*(?P<value>"(?:[^"\\]|\\.)*"|\([^()]*\)|[^\s()]+)) |
        (?P<text>"(?:[^"\\]|\\.)*"|[^\s()]+)
    )""", re.X)


class QueryError(ValueError):
    pass


@dataclass
class Compiled:
    sql: str
    params: list[Any]


class _Parser:
    def __init__(self, text: str):
        self.tokens = list(self._lex(text))
        self.pos = 0

    @staticmethod
    def _lex(text: str):
        pos = 0
        text = text.strip()
        while pos < len(text):
            m = _TOKEN.match(text, pos)
            if not m or m.end() == pos:
                raise QueryError(f"cannot parse query near: {text[pos:pos + 20]!r}")
            pos = m.end()
            kind = m.lastgroup
            if kind == "term":
                yield ("term", (m.group("field"), m.group("op") or "", _unquote(m.group("value"))))
            elif kind == "text":
                yield ("text", _unquote(m.group("text")))
            elif kind in ("and", "or", "not", "lpar", "rpar"):
                yield (kind, None)

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)

    def take(self):
        tok = self.peek()
        self.pos += 1
        return tok

    # ---- grammar ---------------------------------------------------------
    def parse(self) -> Compiled:
        if not self.tokens:
            return Compiled("1=1", [])
        node = self.or_expr()
        if self.peek()[0] is not None:
            raise QueryError("unexpected token at end of query")
        return node

    def or_expr(self) -> Compiled:
        left = self.and_expr()
        while self.peek()[0] == "or":
            self.take()
            right = self.and_expr()
            left = Compiled(f"({left.sql} OR {right.sql})", left.params + right.params)
        return left

    def and_expr(self) -> Compiled:
        left = self.not_expr()
        while True:
            kind = self.peek()[0]
            if kind == "and":
                self.take()
                right = self.not_expr()
            elif kind in ("not", "lpar", "term", "text"):
                right = self.not_expr()
            else:
                break
            left = Compiled(f"({left.sql} AND {right.sql})", left.params + right.params)
        return left

    def not_expr(self) -> Compiled:
        if self.peek()[0] == "not":
            self.take()
            inner = self.not_expr()
            return Compiled(f"(NOT {inner.sql})", inner.params)
        return self.primary()

    def primary(self) -> Compiled:
        kind, value = self.take()
        if kind == "lpar":
            inner = self.or_expr()
            if self.take()[0] != "rpar":
                raise QueryError("missing ')'")
            return inner
        if kind == "term":
            field, op, val = value
            return compile_term(field, op, val)
        if kind == "text":
            return compile_fulltext(value)
        raise QueryError("unexpected token")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return re.sub(r"\\(.)", r"\1", value[1:-1])
    return value


def field_expr(field: str) -> str:
    """SQL expression that yields the value of ``field`` for a row of ``events``."""
    if field in COLUMNS:
        return COLUMNS[field]
    return f"json_extract(doc, '$.\"{field}\"')"


def _like_pattern(value: str) -> str:
    out = []
    for ch in value:
        if ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        elif ch in ("%", "_", "\\"):
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def compile_term(field: str, op: str, value: str) -> Compiled:
    field = field.strip()
    if len(value) >= 2 and value[0] == "(" and value[-1] == ")":
        # field:(a OR b OR c)  /  field:(a AND b)  - one field, several values
        inner = value[1:-1].strip()
        if re.search(r"\s+AND\s+", inner) and not re.search(r"\s+OR\s+", inner):
            parts, joiner = re.split(r"\s+AND\s+", inner), " AND "
        else:
            parts, joiner = re.split(r"\s+OR\s+", inner), " OR "
        compiled = [compile_term(field, op, _unquote(p.strip())) for p in parts if p.strip()]
        if not compiled:
            raise QueryError(f"{field}: empty value group")
        return Compiled("(" + joiner.join(c.sql for c in compiled) + ")", [x for c in compiled for x in c.params])
    if field == "_exists_":
        return Compiled(f"{field_expr(value)} IS NOT NULL", [])
    if field in ("@timestamp", "timestamp"):
        raise QueryError("use the time range parameters instead of @timestamp in the query")
    if value == "*":
        return Compiled(f"{field_expr(field)} IS NOT NULL", [])
    expr = field_expr(field)
    if op:
        try:
            num = float(value)
        except ValueError:
            raise QueryError(f"{field}: comparison needs a number, got {value!r}") from None
        return Compiled(f"CAST({expr} AS REAL) {op} ?", [num])
    if field in LIST_FIELDS:
        if "*" in value or "?" in value:
            return Compiled(f"EXISTS (SELECT 1 FROM json_each(doc, '$.\"{field}\"') WHERE LOWER(value) LIKE ? ESCAPE '\\')",
                            [_like_pattern(value.lower())])
        return Compiled(f"EXISTS (SELECT 1 FROM json_each(doc, '$.\"{field}\"') WHERE LOWER(value) = ?)", [value.lower()])
    if field in NUMERIC_FIELDS and re.fullmatch(r"-?\d+(\.\d+)?", value):
        return Compiled(f"CAST({expr} AS REAL) = ?", [float(value)])
    if "*" in value or "?" in value:
        return Compiled(f"LOWER({expr}) LIKE ? ESCAPE '\\'", [_like_pattern(value.lower())])
    return Compiled(f"LOWER({expr}) = ?", [value.lower()])


def compile_fulltext(text: str) -> Compiled:
    words = [w for w in re.split(r"\s+", text.strip()) if w]
    if not words:
        return Compiled("1=1", [])
    parts = []
    for w in words:
        prefix = w.endswith("*")
        w = w.rstrip("*").replace('"', '""')
        if not w:
            continue
        parts.append(f'"{w}"' + ("*" if prefix else ""))
    if not parts:
        return Compiled("1=1", [])
    match = " ".join(parts)  # implicit AND in FTS5
    return Compiled("id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)", [match])


def compile_query(text: str | None) -> Compiled:
    """Compile a query string into a SQL WHERE fragment (without 'WHERE')."""
    if not text or not text.strip() or text.strip() == "*":
        return Compiled("1=1", [])
    return _Parser(text).parse()
