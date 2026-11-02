"""cors_audit — passive CORS misconfiguration probe.

Sends ONE read-only GET with a crafted Origin header and inspects the
Access-Control-Allow-Origin / -Credentials response. No payloads, no state
change — it just asks the server how it would treat a cross-origin reader.

Reports:
  * reflected arbitrary Origin + credentials allowed  -> HIGH
  * wildcard ACAO + credentials allowed               -> HIGH (invalid but seen)
  * reflected arbitrary Origin (no credentials)        -> MEDIUM
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_PROBE_ORIGIN = "https://redswarm-cors-probe.example"


@register
class CorsAuditAgent(BaseAgent):
    name = "cors_audit"
    role_label = "CORS Misconfiguration"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Passive CORS check: reflects a probe Origin and inspects ACAO/ACAC. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        url = task.target or (task.params or {}).get("url", "")
        if not url:
            raise ValueError("cors_audit needs a target URL")
        r = self.ctx.get(url, headers={"Origin": _PROBE_ORIGIN})
        if r.get("error"):
            return {"url": r["url"], "error": r["error"]}

        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
        result = {"url": r["url"], "acao": acao, "acac": acac, "finding": None}
        sev = why = None
        if acao == _PROBE_ORIGIN and acac:
            sev, why = Severity.HIGH, "Server reflects an arbitrary Origin AND allows credentials — cross-origin read of authenticated responses."
        elif acao == "*" and acac:
            sev, why = Severity.HIGH, "Wildcard ACAO with credentials allowed (browsers reject this combo, but it signals broken CORS policy)."
        elif acao == _PROBE_ORIGIN:
            sev, why = Severity.MEDIUM, "Server reflects an arbitrary Origin in ACAO without validation."
        if sev:
            f = Finding(title="CORS: reflected/over-permissive Access-Control-Allow-Origin",
                        severity=sev, target=r["url"], stage=PTESStage.VULNERABILITY_ANALYSIS,
                        agent=self.name, task_id=task.id, status=FindingStatus.CONFIRMED,
                        description=why,
                        reproduction=f"curl -s -H 'Origin: {_PROBE_ORIGIN}' -I {r['url']}\n"
                                     f"# observe Access-Control-Allow-Origin / -Credentials")
            f.evidence.append(Evidence(kind="http", task_id=task.id,
                content=f"Request Origin: {_PROBE_ORIGIN}\n"
                        f"Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"))
            self.ctx.add_finding(f)
            result["finding"] = f.id
        return result
