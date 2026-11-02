"""BaseAgent + registry + the context object the orchestrator injects."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from ..models import Task, Finding, Evidence, PTESStage
from ..scope import ScopeGuard
from ..audit import AuditLog
from ..store import Store


@dataclass
class AgentContext:
    """Everything a sub-agent is allowed to reach. Note it gets the ScopeGuard,
    not a raw network client — an agent is expected to re-check scope on every
    target it touches, even ones derived mid-task."""
    scope: ScopeGuard
    audit: AuditLog
    store: Store
    limiter: object = None   # redswarm.net.RateLimiter (optional)

    def get(self, url: str, **kw):
        """Scope-checked, rate-limited, read-only GET. Use this for any request."""
        from ..net import safe_get
        return safe_get(self.scope, url, limiter=self.limiter, **kw)

    def add_finding(self, finding: Finding) -> None:
        self.store.save_finding(finding)
        self.audit.log(finding.agent or "agent", "finding_added",
                       finding.target, finding.task_id,
                       {"finding_id": finding.id, "title": finding.title,
                        "severity": finding.severity.value})

    def add_surface_node(self, node_id: str, kind: str, label: str,
                         target: str, meta: Optional[dict] = None) -> None:
        self.store.upsert_surface({
            "id": node_id, "kind": kind, "label": label,
            "target": target, "meta": meta or {},
        })


class BaseAgent:
    name: str = "base"
    stage: PTESStage = PTESStage.INTELLIGENCE_GATHERING
    description: str = ""
    # Default for tasks created for this agent; a task can still override.
    default_requires_approval: bool = False

    def __init__(self, ctx: AgentContext):
        self.ctx = ctx

    def run(self, task: Task) -> dict:
        """Do the work and return a result dict. May call ctx.add_finding().
        Scope has already been enforced by the orchestrator before dispatch,
        but agents touching additional targets must re-check with
        self.ctx.scope.assert_in_scope(...)."""
        raise NotImplementedError


REGISTRY: dict[str, type[BaseAgent]] = {}


def register(cls: type[BaseAgent]) -> type[BaseAgent]:
    if cls.name in REGISTRY:
        raise ValueError(f"agent name already registered: {cls.name}")
    REGISTRY[cls.name] = cls
    return cls


def build_agents(ctx: AgentContext) -> dict[str, BaseAgent]:
    """Instantiate every registered agent against a context."""
    return {name: cls(ctx) for name, cls in REGISTRY.items()}
