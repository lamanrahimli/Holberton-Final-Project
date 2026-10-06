"""Command input: runs a command periodically and ships each output line (custom collectors)."""
from __future__ import annotations

import logging
import subprocess

from . import Input, register

log = logging.getLogger("kharibulbul.agent.inputs.command")


@register("command")
class CommandInput(Input):
    """
    config:
      type: command
      command: ["ss", "-tunap"]          # list (no shell) or string (shell=True)
      interval: 60
      dataset: linux.netstat
      skip_lines: 1                      # header lines to drop
    """

    def __init__(self, cfg, emit, state_dir, host_fields):
        super().__init__(cfg, emit, state_dir, host_fields)
        self.command = cfg.get("command")
        self.interval = float(cfg.get("interval", 60))
        self.skip = int(cfg.get("skip_lines", 0))
        self.timeout = float(cfg.get("timeout", 30))

    def run_once(self) -> None:
        if not self.command:
            self.stop()
            return
        shell = isinstance(self.command, str)
        proc = subprocess.run(self.command, shell=shell, capture_output=True, text=True, timeout=self.timeout)
        lines = proc.stdout.splitlines()[self.skip:]
        for line in lines:
            if line.strip():
                self.emit(line, dataset=self.cfg.get("dataset") or "command", fields={"command.exit_code": proc.returncode})
