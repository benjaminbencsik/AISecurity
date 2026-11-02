"""SQLite persistence. One connection per call (WAL) so it's safe to touch from
the orchestrator's worker threads without a shared cursor.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Optional

from .models import Task, Finding, Evidence, TaskStatus, FindingStatus


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS surface (
    id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at REAL NOT NULL
);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    # -- tasks ------------------------------------------------------------
    def save_task(self, task: Task) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "REPLACE INTO tasks (id, data, updated_at) VALUES (?,?,?)",
                (task.id, json.dumps(task.to_dict()), time.time()),
            )

    def get_task(self, task_id: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()
            return json.loads(row["data"]) if row else None

    def all_tasks(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT data FROM tasks ORDER BY updated_at").fetchall()
            return [json.loads(r["data"]) for r in rows]

    # -- findings ---------------------------------------------------------
    def save_finding(self, finding: Finding) -> None:
        finding.updated_at = time.time()
        with self._lock, self._conn() as c:
            c.execute(
                "REPLACE INTO findings (id, data, updated_at) VALUES (?,?,?)",
                (finding.id, json.dumps(finding.to_dict()), finding.updated_at),
            )

    def get_finding(self, finding_id: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT data FROM findings WHERE id=?", (finding_id,)).fetchone()
            return json.loads(row["data"]) if row else None

    def all_findings(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT data FROM findings ORDER BY updated_at DESC").fetchall()
            return [json.loads(r["data"]) for r in rows]

    # -- approvals --------------------------------------------------------
    def save_approval(self, approval: dict) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "REPLACE INTO approvals (id, data, updated_at) VALUES (?,?,?)",
                (approval["id"], json.dumps(approval), time.time()),
            )

    def get_approval(self, approval_id: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT data FROM approvals WHERE id=?", (approval_id,)).fetchone()
            return json.loads(row["data"]) if row else None

    def all_approvals(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT data FROM approvals ORDER BY updated_at DESC").fetchall()
            return [json.loads(r["data"]) for r in rows]

    # -- live activity feed ----------------------------------------------
    def push_activity(self, event: dict) -> None:
        event = {**event, "ts": event.get("ts", time.time())}
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO activity (ts, data) VALUES (?,?)",
                      (event["ts"], json.dumps(event)))

    def recent_activity(self, n: int = 100) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT data FROM activity ORDER BY id DESC LIMIT ?", (n,)
            ).fetchall()
            return [json.loads(r["data"]) for r in reversed(rows)]

    # -- attack surface ---------------------------------------------------
    def upsert_surface(self, node: dict) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "REPLACE INTO surface (id, data, updated_at) VALUES (?,?,?)",
                (node["id"], json.dumps(node), time.time()),
            )

    def all_surface(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT data FROM surface ORDER BY updated_at").fetchall()
            return [json.loads(r["data"]) for r in rows]
