"""host_liveness — the httpx step. Takes the in-scope subdomains discovered in
recon, probes each for a live HTTP/HTTPS service (read-only GET), and records
status / title / server into the attack surface. Turns a flat subdomain list
into the set of live hosts actually worth testing.
"""
from __future__ import annotations

import re

from ..models import Task, PTESStage
from .base import BaseAgent, register

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_MAX_HOSTS = 80


@register
class HostLivenessAgent(BaseAgent):
    name = "host_liveness"
    role_label = "Live Host Probing"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Probes discovered in-scope subdomains for live HTTP(S) services (status/title/server). Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        subs = [n["target"] for n in self.ctx.store.all_surface()
                if n.get("kind") == "subdomain"]
        # include the primary target host too
        primary = task.target
        if primary and "://" in primary:
            from urllib.parse import urlparse
            primary = urlparse(primary).hostname
        if primary and primary not in subs:
            subs.insert(0, primary)

        live = []
        for host in subs[:_MAX_HOSTS]:
            if not self.ctx.scope.allowed(host):
                continue
            hit = None
            for scheme in ("https", "http"):
                r = self.ctx.get(f"{scheme}://{host}/", timeout=8)
                if not r.get("error") and r.status:
                    m = _TITLE.search(r.body or "")
                    hit = {"url": f"{scheme}://{host}/", "status": r.status,
                           "server": r.headers.get("server", ""),
                           "title": (m.group(1).strip()[:120] if m else "")}
                    break
            if hit:
                live.append(hit)
                self.ctx.add_surface_node(f"live:{hit['url']}", "live_host",
                                          host, hit["url"],
                                          {"via": self.role_label, "status": hit["status"],
                                           "server": hit["server"], "title": hit["title"]})
        return {"probed": min(len(subs), _MAX_HOSTS), "live": len(live),
                "hosts": [h["url"] for h in live[:40]]}
