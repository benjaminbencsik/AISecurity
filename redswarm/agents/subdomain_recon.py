"""subdomain_recon — passive subdomain discovery from Certificate Transparency
logs (crt.sh). This never touches the target: it queries a public CT aggregator
for certificates issued to the domain, which routinely reveals subdomains an
org forgot about. It's the breadth half of recon and the main feed for the
monitoring diff.

Discovered hosts are added to the attack surface only if they're in scope;
out-of-scope discoveries are counted but not mapped.

crt.sh endpoint is overridable via REDSWARM_CRTSH (for testing / a private CT
mirror). This agent makes an OSINT request to that source, not to your target.
"""
from __future__ import annotations

import json
import os
import urllib.request
from urllib.parse import urlparse

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_CRTSH = os.environ.get("REDSWARM_CRTSH", "https://crt.sh/?q=%25.{domain}&output=json")


def _domain_of(target: str) -> str:
    host = urlparse(target).hostname if "://" in target else target.split("/")[0].split(":")[0]
    return (host or target).lstrip("*.").lower()


@register
class SubdomainReconAgent(BaseAgent):
    name = "subdomain_recon"
    role_label = "Subdomain Discovery (CT logs)"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Passive subdomain discovery via Certificate Transparency (crt.sh). OSINT; no target contact. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        domain = _domain_of(task.target or (task.params or {}).get("domain", ""))
        if not domain:
            raise ValueError("subdomain_recon needs a domain")
        url = _CRTSH.format(domain=domain)
        req = urllib.request.Request(url, headers={"User-Agent": "RedSwarm/subdomain_recon"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read(4 * 1024 * 1024).decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            return {"domain": domain, "error": str(e)}

        subs = set()
        for row in data if isinstance(data, list) else []:
            for nv in str(row.get("name_value", "")).splitlines():
                nv = nv.strip().lstrip("*.").lower()
                if nv and "@" not in nv and nv.endswith(domain):
                    subs.add(nv)

        in_scope, out_scope = [], []
        for s in sorted(subs):
            (in_scope if self.ctx.scope.allowed(s) else out_scope).append(s)
        for s in in_scope:
            self.ctx.add_surface_node(f"subdomain:{s}", "subdomain", s, s,
                                      {"via": self.role_label, "source": "crt.sh"})

        if in_scope:
            f = Finding(
                title=f"{len(in_scope)} in-scope subdomain(s) discovered via CT logs",
                severity=Severity.INFO, target=domain,
                stage=PTESStage.INTELLIGENCE_GATHERING, agent=self.name,
                task_id=task.id, status=FindingStatus.CONFIRMED,
                description="Certificate Transparency revealed in-scope hosts to assess.",
                reproduction=f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json'")
            f.evidence.append(Evidence(kind="note", task_id=task.id,
                                       content="\n".join(in_scope[:200])))
            self.ctx.add_finding(f)

        return {"domain": domain, "total_discovered": len(subs),
                "in_scope": len(in_scope), "out_of_scope": len(out_scope),
                "mapped": in_scope[:50]}
