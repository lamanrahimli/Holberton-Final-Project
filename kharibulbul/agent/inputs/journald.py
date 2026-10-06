"""journald input: streams ``journalctl -o json -f`` and remembers the cursor."""
from __future__ import annotations

import logging
import os
import subprocess
import time

from . import Input, register

log = logging.getLogger("kharibulbul.agent.inputs.journald")


@register("journald")
class JournaldInput(Input):
    """
    config:
      type: journald
      units: [ssh.service, sudo]      # optional: only these units / identifiers
      dataset: linux.journald
    """

    def __init__(self, cfg, emit, state_dir, host_fields):
        super().__init__(cfg, emit, state_dir, host_fields)
        self.cursor_file = os.path.join(state_dir, f"journald-{cfg.get('id', '0')}.cursor")
        self.units = cfg.get("units") or []
        self.interval = 2.0
        self._proc: subprocess.Popen | None = None

    def _cmd(self) -> list[str]:
        cmd = ["journalctl", "-o", "json", "-f", "--no-pager", "--cursor-file", self.cursor_file]
        if not os.path.exists(self.cursor_file):
            cmd += ["-n", "0"]  # start with new lines only
        for u in self.units:
            cmd += ["-u", u]
        return cmd

    def run_once(self) -> None:
        self._proc = subprocess.Popen(self._cmd(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        log.info("journald streaming started (%s)", " ".join(self._cmd()))
        assert self._proc.stdout is not None
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                line = line.strip()
                if line:
                    self.emit(line, dataset=self.cfg.get("dataset") or "linux.journald")
        finally:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
            err = self._proc.stderr.read().strip() if self._proc.stderr else ""
            if err and not self._stop.is_set():
                log.warning("journalctl exited: %s", err[:300])
            if not self._stop.is_set():
                time.sleep(2)
