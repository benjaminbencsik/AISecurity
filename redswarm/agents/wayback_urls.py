"""wayback_urls — passive OSINT. Pulls historical URLs for a domain from the
Wayback Machine (web.archive.org CDX API). Never touches the target; great for
surfacing old endpoints and parameterized URLs (which make good open_redirect /
IDOR candidates). In-scope URLs are mapped into the attack surface.

CDX endpoint overridable via REDSWARM_WAYBACK (for testing / a mirror).
"""
from __future__ import annotations

import json
import os
import urllib.request
from urllib.parse import urlparse

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_CDX = os.environ.get(
    "REDSWARM_WAYBACK",
    "http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=5000")


def _domain_of(target: str) -> str:
    host = urlparse(target).hostname if "://" in target else target.split("/")[0].split(":")[0]
    return (host or target).lstrip("*.").lower()


@register
class WaybackUrlsAgent(BaseAgent):
    name = "wayback_urls"
    role_label = "Wayback URL Discovery"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Passive OSINT: historical URLs from the Wayback Machine. No target contact. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        domain = _domain_of(task.target or (task.params or {}).get("domain", ""))
        if not domain:
            raise ValueError("wayback_urls needs a domain")
        url = _CDX.format(domain=domain)
        req = urllib.request.Request(url, headers={"User-Agent": "RedSwarm/wayback_urls"})
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                rows = json.loads(resp.read(8 * 1024 * 1024).decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            return {"domain": domain, "error": str(e)}

        # CDX returns [["original"], "<url>", "<url>", ...]
        urls = [r[0] if isinstance(r, list) else r for r in rows[1:]] if rows else []
        with_params = [u for u in urls if "?" in u and "=" in u]
        in_scope = [u for u in urls if self.ctx.scope.allowed(u)]
        for u in in_scope[:300]:
            self.ctx.add_surface_node(f"url:{u}", "url", u, u,
                                      {"via": self.role_label, "source": "wayback"})
        if in_scope:
            f = Finding(title=f"{len(in_scope)} historical in-scope URL(s) from Wayback",
                        severity=Severity.INFO, target=domain,
                        stage=PTESStage.INTELLIGENCE_GATHERING, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description="Archived URLs reveal old endpoints/params worth testing.",
                        reproduction=f"curl 'http://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original'")
            f.evidence.append(Evidence(kind="note", task_id=task.id,
                                       content="\n".join(in_scope[:150])))
            self.ctx.add_finding(f)
        return {"domain": domain, "total": len(urls), "in_scope": len(in_scope),
                "with_params": len(with_params)}
