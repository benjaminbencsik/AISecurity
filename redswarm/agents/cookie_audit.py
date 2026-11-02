"""cookie_audit — passive read-only check of Set-Cookie flags on an in-scope URL.

Flags cookies missing Secure / HttpOnly / SameSite. Self-evidencing (the
Set-Cookie line is the proof), so findings are emitted CONFIRMED.
"""
from __future__ import annotations

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register


@register
class CookieAuditAgent(BaseAgent):
    name = "cookie_audit"
    role_label = "Cookie Flags Audit"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Passive audit of Set-Cookie security flags (Secure/HttpOnly/SameSite). Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        url = task.target or (task.params or {}).get("url", "")
        if not url:
            raise ValueError("cookie_audit needs a target URL")
        r = self.ctx.get(url)
        if r.get("error"):
            return {"url": r["url"], "error": r["error"]}

        cookies = r.set_cookies
        issues = 0
        for raw in cookies:
            lower = raw.lower()
            name = raw.split("=", 1)[0].strip()
            missing = [flag for flag, tok in
                       (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite="))
                       if tok not in lower]
            if not missing:
                continue
            issues += 1
            sev = Severity.MEDIUM if "Secure" in missing or "HttpOnly" in missing else Severity.LOW
            f = Finding(
                title=f"Cookie '{name}' missing {', '.join(missing)}",
                severity=sev, target=r["url"], stage=PTESStage.VULNERABILITY_ANALYSIS,
                agent=self.name, task_id=task.id, status=FindingStatus.CONFIRMED,
                description=f"The '{name}' cookie is set without {', '.join(missing)}.",
                reproduction=f"curl -sI {r['url']}  # inspect Set-Cookie for '{name}'")
            f.evidence.append(Evidence(kind="http", task_id=task.id,
                                       content=f"Set-Cookie: {raw}"))
            self.ctx.add_finding(f)
        return {"url": r["url"], "cookies_seen": len(cookies), "issues": issues}
