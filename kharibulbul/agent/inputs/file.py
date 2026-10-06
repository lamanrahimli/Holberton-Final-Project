"""File input: tails one or more files (globs), survives rotation, remembers offsets."""
from __future__ import annotations

import glob
import json
import logging
import os

from . import Input, register

log = logging.getLogger("kharibulbul.agent.inputs.file")


@register("file")
class FileInput(Input):
    """
    config:
      type: file
      paths: ["/var/log/auth.log", "/var/log/nginx/*.log"]
      dataset: linux.auth
      start: end            # 'end' (only new lines, default) or 'beginning'
      interval: 0.5
      encoding: utf-8
      fields: {zone: dmz}
    """

    def __init__(self, cfg, emit, state_dir, host_fields):
        super().__init__(cfg, emit, state_dir, host_fields)
        self.interval = float(cfg.get("interval", 0.5))
        self.paths = cfg.get("paths") or ([cfg["path"]] if cfg.get("path") else [])
        self.encoding = cfg.get("encoding", "utf-8")
        self.start_at_end = str(cfg.get("start", "end")).lower() != "beginning"
        self.state_file = os.path.join(state_dir, f"file-{cfg.get('id', '0')}.json")
        self.state: dict[str, dict] = self._load_state()
        self._handles: dict[str, object] = {}
        self._partial: dict[str, str] = {}

    # ------------------------------------------------------------------ #
    def _load_state(self) -> dict:
        try:
            with open(self.state_file, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_state(self) -> None:
        tmp = self.state_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh)
        os.replace(tmp, self.state_file)

    @staticmethod
    def _identity(path: str) -> str:
        """Stable identity of the file behind ``path`` (changes when the file is rotated/replaced).

        Python exposes the NTFS file reference number as ``st_ino`` on Windows, so
        ``dev:ino`` works on both platforms.  (Hashing the first bytes, as an early
        version did, broke for files smaller than the hashed window: the identity
        changed as the file grew and lines were re-read - found in the Week 1 test.)
        """
        st = os.stat(path)
        if st.st_ino:
            return f"{st.st_dev}:{st.st_ino}"
        return f"ctime:{st.st_ctime_ns}"  # exotic filesystems without inode numbers

    def _open(self, path: str):
        try:
            ident = self._identity(path)
        except OSError:
            return None
        st = self.state.get(path) or {}
        offset = 0
        if st.get("identity") == ident:
            offset = int(st.get("offset", 0))
            if offset > os.path.getsize(path):  # truncated in place
                offset = 0
        elif not st and self.start_at_end:
            offset = os.path.getsize(path)
        fh = open(path, "rb")
        fh.seek(offset)
        self.state[path] = {"identity": ident, "offset": offset}
        self._handles[path] = fh
        return fh

    # ------------------------------------------------------------------ #
    def run_once(self) -> None:
        current = set()
        for pattern in self.paths:
            for path in glob.glob(pattern):
                if os.path.isfile(path):
                    current.add(path)
        changed = False
        for path in sorted(current):
            fh = self._handles.get(path)
            if fh is None:
                fh = self._open(path)
                if fh is None:
                    continue
            # rotation / truncation detection
            try:
                ident = self._identity(path)
                size = os.path.getsize(path)
            except OSError:
                continue
            st = self.state[path]
            if ident != st["identity"] or size < st["offset"]:
                fh.close()
                self._handles.pop(path, None)
                self.state[path] = {"identity": ident, "offset": 0}
                fh = self._open(path)
                if fh is None:
                    continue
            data = fh.read()
            if not data:
                continue
            text = self._partial.get(path, "") + data.decode(self.encoding, errors="replace")
            lines = text.split("\n")
            self._partial[path] = lines.pop()  # incomplete last line
            for line in lines:
                line = line.rstrip("\r")
                if line.strip():
                    self.emit(line, path=path)
            self.state[path]["offset"] = fh.tell()
            changed = True
        # files that disappeared
        for path in [p for p in self._handles if p not in current]:
            self._handles.pop(path).close()
        if changed:
            self._save_state()
