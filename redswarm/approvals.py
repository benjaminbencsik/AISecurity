"""Approval gate. Any task flagged `requires_approval` parks here until an
operator says yes. Nothing active runs on the operator's behalf without a
recorded, attributable decision.
"""
from __future__ import annotations

import time
from typing import Optional

from .models import new_id
from .store import Store
from .audit import AuditLog


class ApprovalQueue:
    def __init__(self, store: Store, audit: AuditLog):
        self.store = store
        self.audit = audit

    def request(self, task_id: str, agent: str, target: str, objective: str) -> dict:
        approval = {
            "id": new_id("appr"),
            "task_id": task_id,
            "agent": agent,
            "target": target,
            "objective": objective,
            "state": "pending",
            "requested_at": time.time(),
            "decided_at": None,
            "operator": None,
            "note": "",
        }
        self.store.save_approval(approval)
        self.audit.log("system", "approval_requested", target, task_id,
                       {"agent": agent, "objective": objective, "approval_id": approval["id"]})
        return approval

    def pending(self) -> list[dict]:
        return [a for a in self.store.all_approvals() if a["state"] == "pending"]

    def _decide(self, approval_id: str, state: str, operator: str, note: str) -> Optional[dict]:
        appr = self.store.get_approval(approval_id)
        if not appr or appr["state"] != "pending":
            return None
        appr.update(state=state, operator=operator, note=note, decided_at=time.time())
        self.store.save_approval(appr)
        self.audit.log(operator or "operator", f"approval_{state}",
                       appr["target"], appr["task_id"],
                       {"approval_id": approval_id, "note": note})
        return appr

    def approve(self, approval_id: str, operator: str = "operator", note: str = "") -> Optional[dict]:
        return self._decide(approval_id, "approved", operator, note)

    def deny(self, approval_id: str, operator: str = "operator", note: str = "") -> Optional[dict]:
        return self._decide(approval_id, "denied", operator, note)

    def state_for_task(self, task_id: str) -> Optional[str]:
        """Latest decision state for a task's approval, or None if never requested."""
        latest = None
        latest_ts = -1.0
        for a in self.store.all_approvals():
            if a["task_id"] == task_id and a["requested_at"] > latest_ts:
                latest, latest_ts = a, a["requested_at"]
        return latest["state"] if latest else None
