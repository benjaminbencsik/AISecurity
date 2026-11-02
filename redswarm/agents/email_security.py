"""email_security — SPF / DMARC / DKIM posture from DNS. Missing or weak records
let anyone spoof the domain's email; it's a real, reportable finding on many
programs. Passive DNS lookups only.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .. import dns
from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register


def _domain_of(target: str) -> str:
    host = urlparse(target).hostname if "://" in target else target.split("/")[0].split(":")[0]
    return (host or target).lstrip("*.").lower()


@register
class EmailSecurityAgent(BaseAgent):
    name = "email_security"
    role_label = "Email Security (SPF/DMARC)"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Checks SPF/DMARC/DKIM DNS posture; flags spoofing exposure. Passive. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        domain = _domain_of(task.target or (task.params or {}).get("domain", ""))
        if not domain:
            raise ValueError("email_security needs a domain")

        txt = dns.query(domain, "TXT")
        spf = next((t for t in txt if t.lower().startswith("v=spf1")), "")
        dmarc_txt = dns.query(f"_dmarc.{domain}", "TXT")
        dmarc = next((t for t in dmarc_txt if t.lower().startswith("v=dmarc1")), "")

        def add(title, sev, desc, ev):
            f = Finding(title=title, severity=sev, target=domain,
                        stage=PTESStage.INTELLIGENCE_GATHERING, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description=desc, reproduction=f"dig TXT {domain}; dig TXT _dmarc.{domain}")
            f.evidence.append(Evidence(kind="note", task_id=task.id, content=ev))
            self.ctx.add_finding(f)

        issues = []
        if not spf:
            add("No SPF record", Severity.LOW,
                "No SPF record published; senders aren't restricted.", "TXT: (no v=spf1)")
            issues.append("no-spf")
        elif "+all" in spf.replace(" ", ""):
            add("Overly permissive SPF (+all)", Severity.MEDIUM,
                "SPF ends in +all, allowing any host to send as the domain.", f"SPF: {spf}")
            issues.append("spf-+all")

        if not dmarc:
            add("No DMARC record", Severity.MEDIUM,
                "No DMARC policy; spoofed mail isn't rejected or reported.", "_dmarc TXT: (none)")
            issues.append("no-dmarc")
        else:
            pol = ""
            for part in dmarc.split(";"):
                if part.strip().lower().startswith("p="):
                    pol = part.strip()[2:].strip().lower()
            if pol == "none":
                add("DMARC policy is p=none", Severity.LOW,
                    "DMARC is monitor-only (p=none); spoofed mail is still delivered.", f"DMARC: {dmarc}")
                issues.append("dmarc-none")

        return {"domain": domain, "spf": bool(spf), "dmarc": bool(dmarc), "issues": issues}
