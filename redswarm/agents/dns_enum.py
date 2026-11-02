"""dns_enum — resolve DNS records for the target domain and any in-scope
subdomains already discovered (by subdomain_recon). Maps resolved IPs/hosts into
the attack surface. Passive: lookups go to a resolver, not the target.
"""
from __future__ import annotations

from urllib.parse import urlparse

from .. import dns
from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_MAX_SUBS = 60


def _domain_of(target: str) -> str:
    host = urlparse(target).hostname if "://" in target else target.split("/")[0].split(":")[0]
    return (host or target).lstrip("*.").lower()


@register
class DnsEnumAgent(BaseAgent):
    name = "dns_enum"
    role_label = "DNS Enumeration"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Resolve A/AAAA/CNAME/MX/NS/TXT for the domain + discovered subdomains. Passive. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        domain = _domain_of(task.target or (task.params or {}).get("domain", ""))
        if not domain:
            raise ValueError("dns_enum needs a domain")

        # base domain, multi-record
        base = {rt: dns.query(domain, rt) for rt in ("A", "AAAA", "NS", "MX", "TXT")}
        for ip in base["A"] + base["AAAA"]:
            self.ctx.add_surface_node(f"ip:{ip}", "ip", ip, ip,
                                      {"via": self.role_label, "for": domain})

        # in-scope subdomains discovered earlier → resolve A/CNAME
        subs = [n["target"] for n in self.store_subs()][:_MAX_SUBS]
        resolved = 0
        for s in subs:
            a = dns.query(s, "A")
            cname = dns.query(s, "CNAME")
            if a or cname:
                resolved += 1
                for ip in a:
                    self.ctx.add_surface_node(f"ip:{ip}", "ip", ip, ip,
                                              {"via": self.role_label, "for": s})
                if cname:
                    self.ctx.add_surface_node(f"host:{s}", "host", s, s,
                                              {"via": self.role_label, "cname": cname[0]})

        f = Finding(title=f"DNS records enumerated for {domain}",
                    severity=Severity.INFO, target=domain,
                    stage=PTESStage.INTELLIGENCE_GATHERING, agent=self.name,
                    task_id=task.id, status=FindingStatus.CONFIRMED,
                    description="Baseline DNS footprint for the engagement.",
                    reproduction=f"dig {domain} ANY")
        ev = "\n".join(f"{rt}: {', '.join(v)}" for rt, v in base.items() if v)
        f.evidence.append(Evidence(kind="note", task_id=task.id, content=ev or "(no records)"))
        self.ctx.add_finding(f)
        return {"domain": domain, "A": base["A"], "MX": base["MX"],
                "NS": base["NS"], "txt_records": len(base["TXT"]),
                "subdomains_resolved": resolved}

    def store_subs(self):
        return [n for n in self.ctx.store.all_surface() if n.get("kind") == "subdomain"]
