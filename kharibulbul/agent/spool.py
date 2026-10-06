"""Disk spool: batches that could not be delivered are kept as JSONL files and replayed later."""
from __future__ import annotations

import glob
import json
import logging
import os
import time
from typing import Callable

from ..common.util import ensure_dir, json_dumps

log = logging.getLogger("kharibulbul.agent.spool")


class Spool:
    def __init__(self, directory: str, max_mb: float = 200.0):
        self.dir = ensure_dir(directory)
        self.max_bytes = int(max_mb * 1024 * 1024)
        self._seq = 0

    def _files(self) -> list[str]:
        return sorted(glob.glob(os.path.join(self.dir, "batch-*.jsonl")))

    def size(self) -> int:
        return sum(os.path.getsize(f) for f in self._files())

    def pending(self) -> int:
        return len(self._files())

    def append(self, batch: list[dict]) -> None:
        if not batch:
            return
        self._seq += 1
        name = os.path.join(self.dir, f"batch-{time.time():.6f}-{self._seq:06d}.jsonl")
        with open(name, "w", encoding="utf-8") as fh:
            for env in batch:
                fh.write(json_dumps(env) + "\n")
        self._enforce_limit()

    def _enforce_limit(self) -> None:
        files = self._files()
        total = sum(os.path.getsize(f) for f in files)
        while total > self.max_bytes and files:
            oldest = files.pop(0)
            total -= os.path.getsize(oldest)
            os.remove(oldest)
            log.warning("spool over limit, dropped oldest batch %s", os.path.basename(oldest))

    def drain(self, sender: Callable[[list[dict]], int], max_files: int = 50) -> int:
        """Replay spooled batches through ``sender`` (returns the number of events it delivered, in order).

        Stops at the first batch that is not delivered completely; only its undelivered rest stays on disk.
        """
        sent = 0
        for path in self._files()[:max_files]:
            batch = []
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            batch.append(json.loads(line))
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("spool file %s unreadable (%s), removing", path, exc)
                os.remove(path)
                continue
            done = int(sender(batch)) if batch else 0
            sent += done
            if done < len(batch):
                if done:
                    tmp = path + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as fh:
                        for env in batch[done:]:
                            fh.write(json_dumps(env) + "\n")
                    os.replace(tmp, path)
                break
            os.remove(path)
        return sent
