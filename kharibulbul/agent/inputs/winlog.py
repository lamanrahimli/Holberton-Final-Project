"""Windows Event Log input (Security, System, Sysmon, PowerShell ... any channel).

Uses the built-in ``wevtutil`` tool (no extra Python packages) and bookmarks
the last EventRecordID per channel, so nothing is lost across restarts.
Each event is shipped as rendered XML; the server's windows parser maps it.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys

from . import Input, register

log = logging.getLogger("kharibulbul.agent.inputs.winlog")

_EVENT_RE = re.compile(r"<Event\b.*?</Event>", re.S)
_RECORD_RE = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")
_TIME_RE = re.compile(r'SystemTime="([^"]+)"')

DEFAULT_CHANNELS = ["Security", "System", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational"]


@register("winlog")
class WinlogInput(Input):
    """
    config:
      type: winlog
      channels: [Security, System, Microsoft-Windows-Sysmon/Operational]
      interval: 2
      batch: 500
      start: now          # 'now' (default) or 'beginning'
      exclude_event_ids: {Security: [5156, 5158]}   # optional noise filter
    """

    def __init__(self, cfg, emit, state_dir, host_fields):
        super().__init__(cfg, emit, state_dir, host_fields)
        self.interval = float(cfg.get("interval", 2))
        self.channels = cfg.get("channels") or DEFAULT_CHANNELS
        self.batch = int(cfg.get("batch", 500))
        self.start_now = str(cfg.get("start", "now")).lower() != "beginning"
        self.exclude = {str(k).lower(): {str(x) for x in v} for k, v in (cfg.get("exclude_event_ids") or {}).items()}
        self.state_file = os.path.join(state_dir, f"winlog-{cfg.get('id', '0')}.json")
        self.bookmarks: dict[str, int] = self._load()
        if sys.platform != "win32":
            log.error("winlog input only works on Windows")
            self.stop()

    def _load(self) -> dict[str, int]:
        try:
            with open(self.state_file, "r", encoding="utf-8") as fh:
                return {k: int(v) for k, v in json.load(fh).items()}
        except (OSError, json.JSONDecodeError, ValueError):
            return {}

    def _save(self) -> None:
        tmp = self.state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.bookmarks, fh)
        os.replace(tmp, self.state_file)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _wevtutil(args: list[str]) -> str:
        creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.run(["wevtutil"] + args, capture_output=True, timeout=60, creationflags=creation)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"wevtutil {' '.join(args[:2])}: {err[:200]}")
        return proc.stdout.decode("utf-8", errors="replace")

    def _latest_record(self, channel: str) -> int:
        out = self._wevtutil(["qe", channel, "/c:1", "/rd:true", "/f:xml"])
        m = _RECORD_RE.search(out)
        return int(m.group(1)) if m else 0

    def _query(self, channel: str, after: int) -> list[str]:
        out = self._wevtutil(["qe", channel, f"/q:*[System[EventRecordID > {after}]]", f"/c:{self.batch}", "/rd:false", "/f:renderedxml"])
        return _EVENT_RE.findall(out)

    # ------------------------------------------------------------------ #
    def run_once(self) -> None:
        changed = False
        for channel in self.channels:
            if channel not in self.bookmarks:
                try:
                    self.bookmarks[channel] = self._latest_record(channel) if self.start_now else 0
                except RuntimeError as exc:
                    log.warning("channel %s: %s (is the channel present / are you admin?)", channel, exc)
                    self.bookmarks[channel] = 0
                changed = True
                log.info("channel %s: starting after record %s", channel, self.bookmarks[channel])
            while not self._stop.is_set():
                events = self._query(channel, self.bookmarks[channel])
                if not events:
                    break
                dataset = "windows." + re.sub(r"[^a-z0-9]+", "_", channel.lower().split("/")[0].replace("microsoft-windows-", "")).strip("_")
                excluded = self.exclude.get(channel.lower(), set())
                for xml in events:
                    rec = _RECORD_RE.search(xml)
                    if rec:
                        self.bookmarks[channel] = max(self.bookmarks[channel], int(rec.group(1)))
                    if excluded:
                        m = re.search(r"<EventID(?: Qualifiers=\"\d+\")?>(\d+)</EventID>", xml)
                        if m and m.group(1) in excluded:
                            continue
                    ts = _TIME_RE.search(xml)
                    self.emit(xml, dataset=dataset, ts=ts.group(1) if ts else None, fields={"winlog.channel": channel})
                changed = True
                if len(events) < self.batch:
                    break
        if changed:
            self._save()
