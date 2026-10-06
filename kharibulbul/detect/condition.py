"""Rule condition expressions: ``selection and not filter``, ``1 of sel*``, ``all of them``."""
from __future__ import annotations

import fnmatch
import re
from typing import Callable

_TOKEN = re.compile(r"\s*(?:(?P<lpar>\()|(?P<rpar>\))|(?P<and>and\b)|(?P<or>or\b)|(?P<not>not\b)|"
                    r"(?P<of>(?P<n>\d+|all)\s+of\s+(?P<pat>them|[\w*?.-]+))|(?P<name>[\w.-]+))", re.I)


class ConditionError(ValueError):
    pass


Evaluator = Callable[[dict], bool]  # matched-selections -> bool


class _Parser:
    def __init__(self, text: str, names: list[str]):
        self.names = names
        self.tokens = list(self._lex(text))
        self.pos = 0

    @staticmethod
    def _lex(text: str):
        pos = 0
        text = text.strip()
        while pos < len(text):
            m = _TOKEN.match(text, pos)
            if not m or m.end() == pos:
                raise ConditionError(f"cannot parse condition near {text[pos:pos + 15]!r}")
            pos = m.end()
            kind = m.lastgroup
            if kind == "of":
                yield ("of", (m.group("n").lower(), m.group("pat")))
            elif kind == "name":
                yield ("name", m.group("name"))
            else:
                yield (kind, None)

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else (None, None)

    def take(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def parse(self) -> Evaluator:
        if not self.tokens:
            raise ConditionError("empty condition")
        fn = self.or_expr()
        if self.peek()[0] is not None:
            raise ConditionError("unexpected token at end of condition")
        return fn

    def or_expr(self) -> Evaluator:
        left = self.and_expr()
        while self.peek()[0] == "or":
            self.take()
            right = self.and_expr()
            left = (lambda l, r: (lambda m: l(m) or r(m)))(left, right)
        return left

    def and_expr(self) -> Evaluator:
        left = self.not_expr()
        while self.peek()[0] == "and":
            self.take()
            right = self.not_expr()
            left = (lambda l, r: (lambda m: l(m) and r(m)))(left, right)
        return left

    def not_expr(self) -> Evaluator:
        if self.peek()[0] == "not":
            self.take()
            inner = self.not_expr()
            return lambda m: not inner(m)
        return self.primary()

    def primary(self) -> Evaluator:
        kind, value = self.take()
        if kind == "lpar":
            inner = self.or_expr()
            if self.take()[0] != "rpar":
                raise ConditionError("missing ')'")
            return inner
        if kind == "name":
            if value not in self.names:
                raise ConditionError(f"unknown selection {value!r} (have: {', '.join(self.names)})")
            return (lambda n: (lambda m: bool(m.get(n))))(value)
        if kind == "of":
            n, pattern = value
            matched = self.names if pattern == "them" else [x for x in self.names if fnmatch.fnmatchcase(x, pattern)]
            if not matched:
                raise ConditionError(f"'{pattern}' matches no selection")
            if n == "all":
                return (lambda names: (lambda m: all(m.get(x) for x in names)))(matched)
            k = int(n)
            return (lambda names, k: (lambda m: sum(1 for x in names if m.get(x)) >= k))(matched, k)
        raise ConditionError("unexpected token in condition")


def compile_condition(text: str | None, names: list[str]) -> Evaluator:
    """Compile a condition; without one, all selections are AND-ed together."""
    if text is None or not str(text).strip():
        return lambda m: all(m.get(n) for n in names)
    return _Parser(str(text), names).parse()
