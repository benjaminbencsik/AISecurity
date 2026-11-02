"""Append-only, hash-chained audit log.

Every event carries the hash of the one before it, so a deleted or edited
record breaks the chain and `verify()` will say exactly where. This is what
makes a finding traceable back to the agent, task and moment that produced it.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Iterator, Optional

GENESIS = "0" * 64


def _canon(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if not os.path.exists(path):
            open(path, "a", encoding="utf-8").close()

    def _last_hash(self) -> str:
        last = GENESIS
        if os.path.getsize(self.path) == 0:
            return last
        with open(self.path, "rb") as fh:
            # read the final non-empty line without loading the whole file
            try:
                fh.seek(-4096, os.SEEK_END)
            except OSError:
                fh.seek(0)
            tail = fh.read().decode("utf-8", "replace").strip().splitlines()
        for line in reversed(tail):
            line = line.strip()
            if line:
                return json.loads(line)["hash"]
        return last

    def log(self, actor: str, action: str, target: str = "",
            task_id: str = "", detail: Optional[dict] = None) -> dict:
        """Record one event and return it."""
        with self._lock:
            prev = self._last_hash()
            record = {
                "ts": time.time(),
                "actor": actor,
                "action": action,
                "target": target,
                "task_id": task_id,
                "detail": detail or {},
                "prev": prev,
            }
            record["hash"] = hashlib.sha256(
                (prev + _canon(record)).encode("utf-8")
            ).hexdigest()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            return record

    def entries(self) -> Iterator[dict]:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def tail(self, n: int = 50) -> list[dict]:
        return list(self.entries())[-n:]

    def verify(self) -> tuple[bool, str]:
        """Walk the chain; report the first break if any."""
        prev = GENESIS
        for i, rec in enumerate(self.entries()):
            if rec.get("prev") != prev:
                return False, f"chain break at entry {i}: prev mismatch"
            check = {k: rec[k] for k in rec if k != "hash"}
            expect = hashlib.sha256((prev + _canon(check)).encode("utf-8")).hexdigest()
            if expect != rec.get("hash"):
                return False, f"chain break at entry {i}: hash mismatch"
            prev = rec["hash"]
        return True, "intact"
