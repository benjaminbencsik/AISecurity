"""tech_fingerprint — passive recon. Read-only fetch of the homepage plus
robots.txt / sitemap.xml to fingerprint the stack and map disclosed paths into
the attack surface. No scanning, no guessing — only what the site publishes.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_DISALLOW = re.compile(r"(?im)^\s*Disallow:\s*(\S+)")
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_HINT_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "via"]


@register
class TechFingerprintAgent(BaseAgent):
    name = "tech_fingerprint"
    role_label = "Tech Fingerprint & Recon"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Passive recon: homepage headers + robots.txt/sitemap.xml → stack fingerprint and disclosed paths. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        base = task.target or (task.params or {}).get("url", "")
        if not base:
            raise ValueError("tech_fingerprint needs a target URL")
        if "://" not in base:
            base = "https://" + base
        root = self.ctx.get(base)
        tech = {}
        if not root.get("error"):
            for h in _HINT_HEADERS:
                if root.headers.get(h):
                    tech[h] = root.headers[h]

        disclosed = set()
        rob = self.ctx.get(urljoin(base, "/robots.txt"))
        if not rob.get("error") and rob.status == 200:
            for m in _DISALLOW.finditer(rob.body):
                disclosed.add(m.group(1))
        sm = self.ctx.get(urljoin(base, "/sitemap.xml"))
        if not sm.get("error") and sm.status == 200:
            for m in _LOC.finditer(sm.body):
                disclosed.add(m.group(1))

        # map disclosed paths into the attack surface (scope-checked)
        mapped = []
        for p in sorted(disclosed)[:100]:
            full = p if p.startswith("http") else urljoin(base, p)
            if not self.ctx.scope.allowed(full):
                continue
            self.ctx.add_surface_node(f"path:{full}", "path", full, full,
                                      {"via": self.role_label, "source": "robots/sitemap"})
            mapped.append(full)

        if tech:
            f = Finding(title="Technology disclosure via response headers",
                        severity=Severity.INFO, target=base,
                        stage=PTESStage.INTELLIGENCE_GATHERING, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description="Server advertises stack details that aid targeting.",
                        reproduction=f"curl -sI {base}")
            f.evidence.append(Evidence(kind="http", task_id=task.id,
                content="\n".join(f"{k}: {v}" for k, v in tech.items())))
            self.ctx.add_finding(f)

        return {"url": base, "tech": tech, "disclosed_paths": len(disclosed),
                "mapped_in_scope": len(mapped)}
