"""Continuous monitoring — the recon pipeline the high earners run.

Each run snapshots the attack surface (and confirmed findings) and diffs it
against the previous snapshot, so new assets, new disclosed paths, and new
confirmed findings surface the moment they appear. This is what makes you first
to a fresh attack surface on a program you watch.

It drives the same scoped, rate-limited, approval-gated agents — monitoring is
just the passive suite on a schedule, with diffing and alerting on top. Nothing
new touches the target that a one-off sweep wouldn't.
"""
from __future__ import annotations

import json
import os
import time
from typing import Callable, Optional

from .store import Store
from .audit import AuditLog


class Monitor:
    def __init__(self, store: Store, audit: AuditLog, snapshot_dir: str,
                 notifier: Optional[Callable[[dict], None]] = None):
        self.store = store
        self.audit = audit
        self.dir = snapshot_dir
        self.notifier = notifier
        os.makedirs(snapshot_dir, exist_ok=True)
        self._path = os.path.join(snapshot_dir, "last_snapshot.json")

    def _current(self) -> dict:
        surface = {n["id"] for n in self.store.all_surface()}
        findings = {f["id"]: {"title": f["title"], "severity": f["severity"],
                              "target": f["target"], "status": f["status"]}
                    for f in self.store.all_findings()
                    if f["status"] == "confirmed"}
        return {"surface": sorted(surface), "findings": findings, "ts": time.time()}

    def _load_prev(self) -> Optional[dict]:
        if not os.path.exists(self._path):
            return None
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return None

    def _save(self, snap: dict) -> None:
        with open(self._path, "w", encoding="utf-8") as fh:
            json.dump(snap, fh)

    def diff(self) -> dict:
        """Compare the current state to the last snapshot and return what's new.
        Also fires the notifier for each newly confirmed finding."""
        cur = self._current()
        prev = self._load_prev()
        if prev is None:
            self._save(cur)
            self.audit.log("monitor", "baseline_captured", "", "",
                           {"surface": len(cur["surface"]), "findings": len(cur["findings"])})
            return {"baseline": True, "new_assets": [], "new_findings": [],
                    "surface_total": len(cur["surface"])}

        new_assets = [a for a in cur["surface"] if a not in set(prev["surface"])]
        prev_f = prev.get("findings", {})
        new_findings = [{"id": fid, **meta} for fid, meta in cur["findings"].items()
                        if fid not in prev_f]

        for a in new_assets:
            self.audit.log("monitor", "new_asset", a, "", {})
        for nf in new_findings:
            self.audit.log("monitor", "new_finding", nf["target"], "",
                           {"finding_id": nf["id"], "severity": nf["severity"]})
            if self.notifier:
                try:
                    self.notifier({"type": "new_finding", **nf})
                except Exception:  # noqa: BLE001 — never let a webhook break the run
                    pass

        self._save(cur)
        return {"baseline": False, "new_assets": new_assets,
                "new_findings": new_findings, "surface_total": len(cur["surface"])}


def webhook_notifier(url: str) -> Callable[[dict], None]:
    """A fire-and-forget JSON POST notifier (e.g. a Slack/Discord incoming webhook).
    Errors are swallowed by the caller; this only builds the function."""
    import urllib.request

    def _notify(event: dict) -> None:
        text = (f":rotating_light: RedSwarm: new {event.get('severity','').upper()} "
                f"finding — {event.get('title','')} on {event.get('target','')}")
        payload = json.dumps({"text": text, "event": event}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=8).read()

    return _notify
