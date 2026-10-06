"""Notification sinks: console, JSONL file, generic webhook, SMTP e-mail.

Sinks run in a background thread so a slow webhook never blocks ingest.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import smtplib
import threading
import urllib.request
from email.message import EmailMessage

from ..common.schema import SEVERITIES, SEVERITY_SCORE
from ..common.util import ensure_dir, json_dumps

log = logging.getLogger("kharibulbul.alerts")

_CONSOLE = logging.getLogger("kharibulbul.ALERT")


def _min_score(name: str | None) -> int:
    return SEVERITY_SCORE.get(str(name or "informational").lower(), 0)


class Notifier:
    def __init__(self, cfg: dict | None = None, base_dir: str = "."):
        cfg = cfg or {}
        self.cfg = cfg
        self.base_dir = base_dir
        self._queue: "queue.Queue[dict | None]" = queue.Queue()
        self._thread = threading.Thread(target=self._loop, name="kb-notify", daemon=True)
        self._thread.start()
        self.sent = {"console": 0, "file": 0, "webhook": 0, "smtp": 0, "escalations": 0}
        self.failures = 0
        file_cfg = cfg.get("file") or {}
        self._file_path = None
        if file_cfg.get("enabled"):
            path = file_cfg.get("path") or "data/alerts.jsonl"
            self._file_path = path if os.path.isabs(path) else os.path.join(base_dir, path)
            ensure_dir(os.path.dirname(self._file_path))

    def notify(self, alert: dict, new: bool, event: str | None = None) -> None:
        """``event="escalated"`` marks an analyst's escalation: it goes to every enabled sink."""
        self._queue.put({"alert": alert, "new": new, "event": event})

    def close(self) -> None:
        self._queue.put(None)
        self._thread.join(timeout=5)

    # ------------------------------------------------------------------ #
    def _loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            try:
                if item.get("event") == "escalated":
                    self._dispatch_escalation(item["alert"])
                else:
                    self._dispatch(item["alert"], item["new"])
            except Exception as exc:  # pragma: no cover
                self.failures += 1
                log.warning("notification failed: %s", exc)

    def _dispatch_escalation(self, alert: dict) -> None:
        """A human escalated the alert: tell every enabled sink, whatever its min_severity."""
        c = self.cfg
        esc = alert.get("escalation") or {}
        if (c.get("console") or {}).get("enabled", True):
            _CONSOLE.warning("[%s] ESCALATED L%s -> %s | %s | %s | by %s%s", str(alert.get("severity", "?")).upper(), esc.get("level"),
                             esc.get("to"), alert.get("rule.name"), alert.get("entity"), esc.get("by"),
                             f" | {esc['reason']}" if esc.get("reason") else "")
            self.sent["console"] += 1
        if self._file_path:
            with open(self._file_path, "a", encoding="utf-8") as fh:
                fh.write(json_dumps(alert) + "\n")
            self.sent["file"] += 1
        wh = c.get("webhook") or {}
        if wh.get("enabled") and wh.get("url"):
            self._webhook(wh, alert, prefix=f"ESCALATED (level {esc.get('level')}, to {esc.get('to')}) ")
        mail = c.get("smtp") or {}
        if mail.get("enabled") and mail.get("host"):
            self._smtp(mail, alert, prefix="ESCALATED ")
        self.sent["escalations"] += 1

    def _dispatch(self, alert: dict, new: bool) -> None:
        score = int(alert.get("severity_score") or 0)
        c = self.cfg
        if (c.get("console") or {}).get("enabled", True):
            level = logging.WARNING if score >= SEVERITY_SCORE["high"] else logging.INFO
            _CONSOLE.log(level, "[%s] %s %s | %s | count=%s", alert.get("severity", "?").upper(), "NEW" if new else "UPDATE",
                         alert.get("rule.name"), alert.get("entity"), alert.get("count"))
            self.sent["console"] += 1
        if self._file_path and new:
            with open(self._file_path, "a", encoding="utf-8") as fh:
                fh.write(json_dumps(alert) + "\n")
            self.sent["file"] += 1
        wh = c.get("webhook") or {}
        if wh.get("enabled") and wh.get("url") and new and score >= _min_score(wh.get("min_severity")):
            self._webhook(wh, alert)
        mail = c.get("smtp") or {}
        if mail.get("enabled") and mail.get("host") and new and score >= _min_score(mail.get("min_severity")):
            self._smtp(mail, alert)

    def _webhook(self, wh: dict, alert: dict, prefix: str = "") -> None:
        body = json_dumps({"source": "kharibulbul", "alert": alert,
                           "text": f"[{alert.get('severity', '').upper()}] {prefix}{alert.get('rule.name')}: {alert.get('summary')}"}).encode()
        req = urllib.request.Request(wh["url"], data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        for k, v in (wh.get("headers") or {}).items():
            req.add_header(str(k), str(v))
        try:
            with urllib.request.urlopen(req, timeout=float(wh.get("timeout", 10))) as resp:
                resp.read()
            self.sent["webhook"] += 1
        except Exception as exc:
            self.failures += 1
            log.warning("webhook %s failed: %s", wh["url"], exc)

    def _smtp(self, mail: dict, alert: dict, prefix: str = "") -> None:
        msg = EmailMessage()
        msg["Subject"] = f"[Kharibulbul {alert.get('severity', '').upper()}] {prefix}{alert.get('rule.name')} - {alert.get('entity')}"
        msg["From"] = mail.get("from") or mail.get("username")
        to = mail.get("to") or []
        msg["To"] = ", ".join(to if isinstance(to, list) else [to])
        msg.set_content(json.dumps(alert, indent=2, default=str))
        try:
            with smtplib.SMTP(mail["host"], int(mail.get("port", 587)), timeout=15) as s:
                if mail.get("starttls", True):
                    s.starttls()
                if mail.get("username"):
                    s.login(mail["username"], mail.get("password", ""))
                s.send_message(msg)
            self.sent["smtp"] += 1
        except Exception as exc:
            self.failures += 1
            log.warning("smtp notification failed: %s", exc)


__all__ = ["Notifier", "SEVERITIES"]
