"""wildcard_dns — detect wildcard DNS for a domain. If a random, never-issued
subdomain resolves, the domain answers for everything, so subdomain discovery
and takeover results will be full of noise. Recording this up front lets the
operator discount those results. One DNS lookup of a random name; passive.
"""
from __future__ import annotations

import secrets
from urllib.parse import urlparse

from .. import dns
from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register


def _domain_of(target: str) -> str:
    host = urlparse(target).hostname if "://" in target else target.split("/")[0].split(":")[0]
    return (host or target).lstrip("*.").lower()


@register
class WildcardDnsAgent(BaseAgent):
    name = "wildcard_dns"
    role_label = "Wildcard DNS Check"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Detects wildcard DNS by resolving a random never-issued subdomain. Passive DNS lookup. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        domain = _domain_of(task.target or (task.params or {}).get("domain", ""))
        if not domain:
            raise ValueError("wildcard_dns needs a domain")
        probe = f"redswarm-wc-{secrets.token_hex(6)}.{domain}"
        ips = dns.query(probe, "A") + dns.query(probe, "CNAME")
        if ips:
            f = Finding(title=f"Wildcard DNS on {domain}", severity=Severity.INFO,
                        target=domain, stage=PTESStage.INTELLIGENCE_GATHERING,
                        agent=self.name, task_id=task.id, status=FindingStatus.CONFIRMED,
                        description="A random subdomain resolves, so every name answers. Treat "
                                    "resolved subdomains as unverified until they serve distinct content.",
                        reproduction=f"dig A {probe}")
            f.evidence.append(Evidence(kind="note", task_id=task.id,
                                       content=f"{probe} → {', '.join(ips)}"))
            self.ctx.add_finding(f)
            self.ctx.add_surface_node(f"dns_policy:{domain}", "dns_policy", domain, domain,
                                      {"wildcard": True, "answers": ips})
        return {"domain": domain, "wildcard": bool(ips), "answers": ips}
