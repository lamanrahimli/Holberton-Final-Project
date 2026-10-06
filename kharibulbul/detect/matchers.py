r"""Selection matching (Sigma-inspired).

A *selection* is a mapping ``field|modifier|modifier: value`` (all fields must
match = AND) or a list of such mappings (any may match = OR).  A list of values
for one field means OR unless the ``all`` modifier is present.

Supported modifiers
-------------------
contains, startswith, endswith, re, all, cs (case-sensitive), cidr,
gt, gte, lt, lte, exists, not, wildcard (default for strings: * and ? are wildcards)

Examples
--------
    process.name: certutil.exe
    process.command_line|contains|all: ["-urlcache", "http"]
    source.ip|cidr: 10.0.0.0/8
    destination.port|gte: 1024
    user.name|endswith|not: "$"
    process.command_line|re: '(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{40,}'
"""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Any

from ..common.util import get_field, glob_to_regex

_NUMERIC_MODS = {"gt", "gte", "lt", "lte"}


class MatchError(ValueError):
    pass


@lru_cache(maxsize=4096)
def _compile_re(pattern: str, flags: int) -> re.Pattern:
    return re.compile(pattern, flags)


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _match_scalar(actual: Any, expected: Any, mods: set[str]) -> bool:
    """Compare one actual scalar with one expected scalar under the modifiers."""
    if expected is None:
        return actual is None
    if "exists" in mods:
        return (actual is not None) == bool(expected)
    if actual is None:
        return False
    if mods & _NUMERIC_MODS:
        a, e = _as_number(actual), _as_number(expected)
        if a is None or e is None:
            return False
        if "gt" in mods:
            return a > e
        if "gte" in mods:
            return a >= e
        if "lt" in mods:
            return a < e
        return a <= e
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    if "re" in mods:
        flags = 0 if "cs" in mods else re.IGNORECASE
        try:
            return _compile_re(str(expected), flags).search(str(actual)) is not None
        except re.error as exc:
            raise MatchError(f"bad regex {expected!r}: {exc}") from None
    if isinstance(expected, bool):
        return str(actual).lower() in ("true", "1") if expected else str(actual).lower() in ("false", "0")
    if isinstance(expected, (int, float)) and not isinstance(actual, str):
        a = _as_number(actual)
        return a is not None and a == float(expected)
    a, e = str(actual), str(expected)
    if "cs" not in mods:
        a, e = a.lower(), e.lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    if "*" in e or "?" in e:
        return glob_to_regex(e, case_insensitive="cs" not in mods).match(a) is not None
    return a == e


def _match_value(actual: Any, expected: Any, mods: set[str]) -> bool:
    """actual may be a list (tags, args): any element may satisfy the check."""
    if isinstance(actual, list):
        if expected is None:
            return len(actual) == 0
        return any(_match_scalar(item, expected, mods) for item in actual)
    return _match_scalar(actual, expected, mods)


def match_field(doc: dict, spec: str, expected: Any) -> bool:
    parts = spec.split("|")
    field, mods = parts[0].strip(), {m.strip().lower() for m in parts[1:]}
    negate = "not" in mods
    mods.discard("not")
    actual = get_field(doc, field)
    if isinstance(expected, list):
        if "all" in mods:
            result = all(_match_value(actual, e, mods) for e in expected)
        else:
            result = any(_match_value(actual, e, mods) for e in expected)
    else:
        result = _match_value(actual, expected, mods)
    return (not result) if negate else result


MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cs", "cidr", "gt", "gte", "lt", "lte", "exists", "not", "wildcard"}


def check_selection(selection: Any) -> list[str]:
    """Static checks before a rule is accepted: known modifiers, regexes compile, CIDRs and numbers parse."""
    problems: list[str] = []
    if isinstance(selection, list):
        for item in selection:
            problems += check_selection(item)
        return problems
    if isinstance(selection, str):
        return problems
    if not isinstance(selection, dict):
        return [f"unsupported selection type: {type(selection).__name__}"]
    for spec, expected in selection.items():
        parts = str(spec).split("|")
        field, mods = parts[0].strip(), {m.strip().lower() for m in parts[1:]}
        if not field:
            problems.append(f"'{spec}': empty field name")
        unknown = sorted(mods - MODIFIERS)
        if unknown:
            problems.append(f"'{spec}': unknown modifier {', '.join(unknown)} (known: {', '.join(sorted(MODIFIERS))})")
        values = expected if isinstance(expected, list) else [expected]
        for value in values:
            if isinstance(value, (dict, list)):
                problems.append(f"'{spec}': value must be a scalar or a list of scalars")
            elif "re" in mods:
                try:
                    re.compile(str(value))
                except re.error as exc:
                    problems.append(f"'{spec}': bad regex {value!r}: {exc}")
            elif "cidr" in mods:
                try:
                    ipaddress.ip_network(str(value), strict=False)
                except ValueError:
                    problems.append(f"'{spec}': {value!r} is not a CIDR network")
            elif mods & _NUMERIC_MODS and _as_number(value) is None:
                problems.append(f"'{spec}': {value!r} is not a number")
    return problems


def match_selection(selection: Any, doc: dict) -> bool:
    if isinstance(selection, list):
        return any(match_selection(item, doc) for item in selection)
    if isinstance(selection, dict):
        return all(match_field(doc, spec, expected) for spec, expected in selection.items())
    if isinstance(selection, str):
        # bare string -> full-text style containment in message or original
        needle = selection.lower()
        for field in ("message", "event.original", "process.command_line"):
            val = doc.get(field)
            if val and needle in str(val).lower():
                return True
        return False
    raise MatchError(f"unsupported selection type: {type(selection).__name__}")
