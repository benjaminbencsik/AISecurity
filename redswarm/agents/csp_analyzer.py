"""csp_analyzer — parse the Content-Security-Policy the app already returned and
flag directives that defeat its purpose. Pure response analysis: one GET, no
payloads. (Missing CSP is header_audit's job; this checks a CSP that exists.)

Confirmed on the presence of a weak directive — the policy text is the evidence.
"""
from __future__ import annotations

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_WEAK = [
    ("'unsafe-inline'", "allows inline <script> — defeats XSS mitigation", Severity.MEDIUM),
    ("'unsafe-eval'", "allows eval()/Function() — widens script-injection impact", Severity.MEDIUM),
]


@register
class CspAnalyzerAgent(BaseAgent):
    name = "csp_analyzer"
    role_label = "CSP Weakness Analysis"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Parses the served Content-Security-Policy; flags unsafe-inline/unsafe-eval and wildcard script sources. Read-only. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        url = task.target or (task.params or {}).get("url", "")
        if not url:
            raise ValueError("csp_analyzer needs a target URL")
        r = self.ctx.get(url)
        if r.get("error"):
            return {"url": url, "error": r["error"]}
        csp = r.headers.get("content-security-policy", "")
        if not csp:
            return {"url": r.get("url", url), "csp": False}

        directives = {}
        for part in csp.split(";"):
            toks = part.strip().split()
            if toks:
                directives[toks[0].lower()] = toks[1:]
        # script-src governs scripts; fall back to default-src if absent
        script = directives.get("script-src") or directives.get("default-src") or []
        low = [t.lower() for t in script]

        issues = []
        for token, why, sev in _WEAK:
            if token in low:
                issues.append((f"CSP script-src allows {token}", why, sev))
        if "*" in low or "https:" in low or "http:" in low:
            issues.append(("CSP script-src uses wildcard/scheme-only source",
                           "any host (or any https origin) can serve scripts that the policy trusts",
                           Severity.MEDIUM))

        for title, why, sev in issues:
            f = Finding(title=title, severity=sev, target=r.get("url", url),
                        stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description=f"{title}: {why}.",
                        reproduction=f"curl -sI {url} | grep -i content-security-policy")
            f.evidence.append(Evidence(kind="http", task_id=task.id,
                                       content=f"Content-Security-Policy: {csp}"))
            self.ctx.add_finding(f)
        return {"url": r.get("url", url), "csp": True, "weaknesses": len(issues)}
