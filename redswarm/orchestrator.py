"""Orchestrator — the root coordinator.

It owns the task graph, enforces scope before anything is dispatched, parks
approval-gated tasks, runs ready tasks across a persistent worker pool (the
"swarm"), and emits a live event for every state change so the command center
can show what each agent is doing in real time.

Two control modes, same gates:

  * tick()        — advance one wave and block until it drains. Good for
                    scripts and tests; fully deterministic.
  * start_auto()  — a background loop keeps dispatching tasks as their
                    dependencies clear and approvals are granted, and parks the
                    moment the graph is blocked on an operator decision. This is
                    the "watch the swarm work" mode; the human still holds every
                    gate.

Live updates: subscribe() hands back a queue that receives every activity event
as it happens (used by the SSE endpoint). Nothing runs on a hidden timer that
the operator can't stop.
"""
from __future__ import annotations

import concurrent.futures
import queue
import threading
import time
from typing import Optional

from .models import Task, TaskStatus, PTESStage, PTES_ORDER, new_id
from .scope import ScopeGuard, ScopeViolation
from .audit import AuditLog
from .store import Store
from .approvals import ApprovalQueue
from .agents.base import AgentContext, build_agents


class Orchestrator:
    def __init__(self, scope: ScopeGuard, store: Store, audit: AuditLog,
                 approvals: ApprovalQueue, max_workers: int = 6, rps: float = 5.0):
        self.scope = scope
        self.store = store
        self.audit = audit
        self.approvals = approvals
        self.max_workers = max_workers
        from .net import RateLimiter
        self.limiter = RateLimiter(rps=rps, burst=max(1, int(rps)))
        self.ctx = AgentContext(scope=scope, audit=audit, store=store,
                                limiter=self.limiter, rps=rps)
        self.agents = build_agents(self.ctx)
        self._halt = threading.Event()   # kill-switch

        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers,
                                                           thread_name_prefix="swarm")
        self._inflight: dict[str, concurrent.futures.Future] = {}
        self._dispatch_lock = threading.Lock()

        # live event subscribers (SSE)
        self._subs: list[queue.Queue] = []
        self._subs_lock = threading.Lock()

        # background auto-run
        self._auto = threading.Event()
        self._pump_thread: Optional[threading.Thread] = None

    # -- task intake ------------------------------------------------------
    def submit(self, task: Task) -> Task:
        if task.agent not in self.agents:
            raise ValueError(f"unknown agent {task.agent!r}; "
                             f"registered: {sorted(self.agents)}")
        if task.target:
            ok, reason = self.scope.check(task.target)
            if not ok:
                task.status = TaskStatus.DENIED
                task.error = f"scope: {reason}"
                self.store.save_task(task)
                self.audit.log("system", "task_rejected_scope", task.target, task.id,
                               {"reason": reason})
                self._activity(task, "rejected (out of scope)")
                return task

        if self.agents[task.agent].default_requires_approval:
            task.requires_approval = True

        task.status = self._initial_status(task)
        self.store.save_task(task)
        self.audit.log("system", "task_submitted", task.target, task.id,
                       {"agent": task.agent, "stage": task.stage.value,
                        "objective": task.objective,
                        "requires_approval": task.requires_approval})
        if task.status == TaskStatus.AWAITING_APPROVAL:
            self.approvals.request(task.id, task.agent, task.target, task.objective)
        self._activity(task, f"submitted → {task.status.value}")
        return task

    def submit_many(self, tasks: list[Task]) -> list[Task]:
        return [self.submit(t) for t in tasks]

    def _initial_status(self, task: Task) -> TaskStatus:
        if task.depends_on and not self._deps_done(task.depends_on):
            return TaskStatus.BLOCKED
        if task.requires_approval:
            return TaskStatus.AWAITING_APPROVAL
        return TaskStatus.PENDING

    # -- dependency + readiness -------------------------------------------
    def _deps_done(self, dep_ids: list[str]) -> bool:
        for d in dep_ids:
            t = self.store.get_task(d)
            if not t or t["status"] != TaskStatus.DONE.value:
                return False
        return True

    def _refresh_statuses(self) -> None:
        for t in self.store.all_tasks():
            status = t["status"]
            if status == TaskStatus.BLOCKED.value and self._deps_done(t["depends_on"]):
                task = self._hydrate(t)
                task.status = (TaskStatus.AWAITING_APPROVAL
                               if task.requires_approval else TaskStatus.PENDING)
                self.store.save_task(task)
                if task.status == TaskStatus.AWAITING_APPROVAL and \
                        self.approvals.state_for_task(task.id) is None:
                    self.approvals.request(task.id, task.agent, task.target, task.objective)
                self._activity(task, f"unblocked → {task.status.value}")
            elif status == TaskStatus.AWAITING_APPROVAL.value:
                decision = self.approvals.state_for_task(t["id"])
                if decision == "approved":
                    task = self._hydrate(t)
                    task.status = TaskStatus.PENDING
                    self.store.save_task(task)
                    self._activity(task, "approved → pending")
                elif decision == "denied":
                    task = self._hydrate(t)
                    task.status = TaskStatus.DENIED
                    task.error = "approval denied by operator"
                    self.store.save_task(task)
                    self._activity(task, "denied by operator")

    def _ready_tasks(self) -> list[Task]:
        ready = []
        for t in self.store.all_tasks():
            if t["status"] == TaskStatus.PENDING.value and self._deps_done(t["depends_on"]):
                ready.append(self._hydrate(t))
        return ready

    # -- execution --------------------------------------------------------
    def _execute(self, task: Task) -> None:
        """Run an already-marked-RUNNING task to completion. Never raises."""
        self.audit.log(task.agent, "task_started", task.target, task.id, {})
        try:
            if task.target:
                self.scope.assert_in_scope(task.target)   # final gate
            result = self.agents[task.agent].run(task)
            task.result = result if isinstance(result, dict) else {"value": result}
            task.status = TaskStatus.DONE
            self.audit.log(task.agent, "task_done", task.target, task.id,
                           {"result_keys": list(task.result.keys())})
            self._activity(task, "done")
        except ScopeViolation as e:
            task.status = TaskStatus.DENIED
            task.error = str(e)
            self.audit.log(task.agent, "task_scope_violation", task.target, task.id,
                           {"error": str(e)})
            self._activity(task, "BLOCKED (scope violation)")
        except Exception as e:  # noqa: BLE001
            task.status = TaskStatus.FAILED
            task.error = f"{type(e).__name__}: {e}"
            self.audit.log(task.agent, "task_failed", task.target, task.id,
                           {"error": task.error})
            self._activity(task, f"failed: {task.error}")
        finally:
            task.finished_at = time.time()
            self.store.save_task(task)
            with self._dispatch_lock:
                self._inflight.pop(task.id, None)

    # -- kill-switch ------------------------------------------------------
    def stop_all(self, reason: str = "operator kill-switch") -> dict:
        """Halt immediately: stop auto-run, block new dispatch, and cancel every
        task still waiting in the pool. Running agents finish their current call
        (we can't force-kill a thread), but nothing new starts."""
        self._halt.set()
        self.stop_auto()
        cancelled = 0
        with self._dispatch_lock:
            for tid, fut in list(self._inflight.items()):
                if fut.cancel():
                    cancelled += 1
                    self._inflight.pop(tid, None)
        self.audit.log("operator", "kill_switch", "", "",
                       {"reason": reason, "cancelled": cancelled})
        return {"halted": True, "cancelled": cancelled,
                "still_running": self.inflight_count()}

    def resume(self) -> None:
        self._halt.clear()
        self.audit.log("operator", "kill_switch_cleared", "", "", {})

    @property
    def halted(self) -> bool:
        return self._halt.is_set()

    def pump(self) -> int:
        """Non-blocking: unblock what can run, dispatch every ready task onto the
        pool, and return how many were dispatched this call. Marks each task
        RUNNING synchronously before submitting so it can't be double-dispatched.
        """
        if self._halt.is_set():
            return 0
        with self._dispatch_lock:
            self._refresh_statuses()
            dispatched = 0
            for task in self._ready_tasks():
                if task.id in self._inflight:
                    continue
                task.status = TaskStatus.RUNNING
                task.started_at = time.time()
                self.store.save_task(task)
                self._activity(task, "running")
                self._inflight[task.id] = self._pool.submit(self._execute, task)
                dispatched += 1
            return dispatched

    def inflight_count(self) -> int:
        with self._dispatch_lock:
            return len(self._inflight)

    def _drain(self, timeout: Optional[float] = None) -> None:
        with self._dispatch_lock:
            futs = list(self._inflight.values())
        if futs:
            concurrent.futures.wait(futs, timeout=timeout)

    def tick(self) -> dict:
        """Advance one wave and block until it drains (deterministic)."""
        dispatched = self.pump()
        self._drain()
        self._refresh_statuses()
        return {"dispatched": dispatched, "ready": dispatched,
                "inflight": self.inflight_count(),
                "awaiting_approval": len(self.approvals.pending())}

    def run_until_idle(self, max_ticks: int = 50) -> list[dict]:
        history = []
        for _ in range(max_ticks):
            summary = self.tick()
            history.append(summary)
            if summary["dispatched"] == 0:
                break
        return history

    # -- background auto-run ----------------------------------------------
    def start_auto(self, interval: float = 0.4) -> None:
        """Keep dispatching as the graph opens up; park on approvals. Idempotent."""
        if self._pump_thread and self._pump_thread.is_alive():
            return
        self._auto.set()
        self.audit.log("operator", "auto_run_started", "", "", {})

        def loop():
            while self._auto.is_set():
                try:
                    self.pump()
                except Exception:  # noqa: BLE001 — never let the pump thread die
                    pass
                time.sleep(interval)

        self._pump_thread = threading.Thread(target=loop, daemon=True,
                                             name="swarm-pump")
        self._pump_thread.start()

    def stop_auto(self) -> None:
        if self._auto.is_set():
            self._auto.clear()
            self.audit.log("operator", "auto_run_stopped", "", "", {})

    @property
    def auto_on(self) -> bool:
        return self._auto.is_set()

    def shutdown(self) -> None:
        self.stop_auto()
        self._pool.shutdown(wait=False, cancel_futures=True)

    # -- live event bus (SSE) ---------------------------------------------
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=256)
        with self._subs_lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._subs_lock:
            if q in self._subs:
                self._subs.remove(q)

    def _broadcast(self, event: dict) -> None:
        with self._subs_lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass  # slow client; it'll catch up on the next full /api/state

    # -- PTES planning ----------------------------------------------------
    def plan_engagement(self, target: str,
                        stages: Optional[list[PTESStage]] = None) -> list[Task]:
        self.scope.assert_in_scope(target)
        stages = stages or PTES_ORDER
        agents_by_stage: dict[PTESStage, str] = {}
        for name, agent in self.agents.items():
            agents_by_stage.setdefault(agent.stage, name)

        tasks: list[Task] = []
        prev_id: Optional[str] = None
        for stage in stages:
            agent = agents_by_stage.get(stage, "")
            objective = f"[{stage.value}] plan step for {target}"
            if not agent:
                t = Task(objective=objective + " (assign an agent)",
                         stage=stage, agent="asset_catalog", target=target,
                         params={"notes": f"placeholder for {stage.value}"},
                         status=TaskStatus.PENDING)
            else:
                t = Task(objective=objective, stage=stage, agent=agent, target=target)
            if prev_id:
                t.depends_on = [prev_id]
            tasks.append(t)
            prev_id = t.id
        self.audit.log("root", "engagement_planned", target, "",
                       {"stages": [s.value for s in stages],
                        "task_ids": [t.id for t in tasks]})
        return tasks

    # -- helpers ----------------------------------------------------------
    def _hydrate(self, d: dict) -> Task:
        return Task(
            objective=d["objective"], stage=PTESStage(d["stage"]), agent=d["agent"],
            target=d.get("target", ""), params=d.get("params", {}),
            requires_approval=d.get("requires_approval", False),
            depends_on=d.get("depends_on", []), id=d["id"],
            status=TaskStatus(d["status"]), created_at=d.get("created_at", time.time()),
            started_at=d.get("started_at"), finished_at=d.get("finished_at"),
            result=d.get("result", {}), error=d.get("error", ""),
        )

    def _activity(self, task: Task, message: str) -> None:
        event = {
            "ts": time.time(), "task_id": task.id, "agent": task.agent,
            "stage": task.stage.value, "target": task.target,
            "status": task.status.value, "message": message,
        }
        self.store.push_activity(event)
        self._broadcast(event)
