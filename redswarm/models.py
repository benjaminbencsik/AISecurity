"""Core data types shared across the framework."""
from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class PTESStage(str, enum.Enum):
    """The seven Penetration Testing Execution Standard stages."""
    PRE_ENGAGEMENT = "pre_engagement"
    INTELLIGENCE_GATHERING = "intelligence_gathering"
    THREAT_MODELING = "threat_modeling"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


# Natural order used when planning / displaying stages.
PTES_ORDER = [
    PTESStage.PRE_ENGAGEMENT,
    PTESStage.INTELLIGENCE_GATHERING,
    PTESStage.THREAT_MODELING,
    PTESStage.VULNERABILITY_ANALYSIS,
    PTESStage.EXPLOITATION,
    PTESStage.POST_EXPLOITATION,
    PTESStage.REPORTING,
]


class TaskStatus(str, enum.Enum):
    PENDING = "pending"                 # ready to run as soon as deps clear
    BLOCKED = "blocked"                 # waiting on dependencies
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    DENIED = "denied"                   # operator refused approval
    SKIPPED = "skipped"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class FindingStatus(str, enum.Enum):
    UNVALIDATED = "unvalidated"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _enumval(v: Any) -> Any:
    return v.value if isinstance(v, enum.Enum) else v


@dataclass
class Task:
    """A scoped unit of work handed to one sub-agent."""
    objective: str
    stage: PTESStage
    agent: str                                  # registered agent name
    target: str = ""                            # host / URL / ip the task touches
    params: dict = field(default_factory=dict)
    requires_approval: bool = False
    depends_on: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("task"))
    status: TaskStatus = TaskStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    result: dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["stage"] = _enumval(self.stage)
        d["status"] = _enumval(self.status)
        return d


@dataclass
class Evidence:
    """A single piece of proof attached to a finding."""
    kind: str                                   # "command_output", "http", "note", "file"
    content: str
    task_id: str = ""
    created_at: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: new_id("ev"))

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    title: str
    severity: Severity
    target: str
    description: str = ""
    stage: PTESStage = PTESStage.VULNERABILITY_ANALYSIS
    status: FindingStatus = FindingStatus.UNVALIDATED
    agent: str = ""                             # which agent surfaced it
    task_id: str = ""                           # the task it came from
    reproduction: str = ""                      # Burp steps / curl / notes
    evidence: list[Evidence] = field(default_factory=list)
    validation_log: str = ""                    # output of the last PoC run
    id: str = field(default_factory=lambda: new_id("find"))
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = _enumval(self.severity)
        d["stage"] = _enumval(self.stage)
        d["status"] = _enumval(self.status)
        d["evidence"] = [e.to_dict() for e in self.evidence]
        return d
