"""http_methods — sends one OPTIONS request and inspects the Allow header for
risky HTTP methods. OPTIONS is read-only; this never issues PUT/DELETE/TRACE
itself, it only reports which the server advertises.
"""
from __future__ import annotations

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_RISKY = {"PUT": "arbitrary file upload", "DELETE": "resource deletion",
          "TRACE": "Cross-Site Tracing (XST)", "CONNECT": "proxying",
          "PATCH": "unexpected modification"}


@register
class HttpMethodsAgent(BaseAgent):
    name = "http_methods"
    role_label = "HTTP Methods"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "One OPTIONS request; flags advertised risky methods (PUT/DELETE/TRACE). Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        url = task.target or (task.params or {}).get("url", "")
        if not url:
            raise ValueError("http_methods needs a target URL")
        r = self.ctx.get(url, method="OPTIONS")
        if r.get("error") and not r.headers:
            return {"url": r.get("url", url), "error": r["error"]}
        allow = r.headers.get("allow", "")
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        risky = [m for m in methods if m in _RISKY]
        if risky:
            sev = Severity.MEDIUM if ("PUT" in risky or "DELETE" in risky or "TRACE" in risky) else Severity.LOW
            f = Finding(title=f"Risky HTTP methods advertised: {', '.join(risky)}",
                        severity=sev, target=r.get("url", url),
                        stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                        task_id=task.id, status=FindingStatus.NEEDS_REVIEW,
                        description="Server's OPTIONS Allow header lists "
                                    + "; ".join(f"{m} ({_RISKY[m]})" for m in risky)
                                    + ". Verify they are actually usable.",
                        reproduction=f"curl -s -X OPTIONS -i {r.get('url', url)}  # see Allow header")
            f.evidence.append(Evidence(kind="http", task_id=task.id,
                                       content=f"Allow: {allow}"))
            self.ctx.add_finding(f)
        return {"url": r.get("url", url), "allow": allow, "risky": risky}
