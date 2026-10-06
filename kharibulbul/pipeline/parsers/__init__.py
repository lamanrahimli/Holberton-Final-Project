"""Parser registry.

Every parser is a function ``parse(raw: str, meta: dict) -> dict | None``.
``meta`` carries what the shipper knew: dataset hint, host, agent, input
labels and the original timestamp.  Parsers return a *flat* ECS-style dict
or None when they cannot handle the line (the pipeline then tries the next
candidate and finally the generic parser).
"""
from __future__ import annotations

from typing import Callable

ParserFn = Callable[[str, dict], "dict | None"]

_REGISTRY: dict[str, ParserFn] = {}


def register(name: str):
    def deco(fn: ParserFn) -> ParserFn:
        _REGISTRY[name] = fn
        return fn
    return deco


def get(name: str) -> ParserFn | None:
    _load_all()
    return _REGISTRY.get(name)


def names() -> list[str]:
    _load_all()
    return sorted(_REGISTRY)


_loaded = False


def _load_all() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    # importing registers the parsers
    from . import windows, sysmon, syslog, web, jsonlog, winfirewall, auditd, apache_error, windows_dhcp, generic  # noqa: F401
