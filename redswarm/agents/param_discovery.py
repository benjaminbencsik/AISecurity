"""param_discovery — build a parameter inventory from everything recon has
collected (Wayback URLs, JS-extracted endpoints, mapped paths). Parameters are
where most web bugs live, so this feeds open_redirect / IDOR / injection
testing. Passive: it reads the shared attack-surface map, makes no new requests.
"""
from __future__ import annotations

from urllib.parse import urlparse, parse_qs

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_INTERESTING = {"redirect", "url", "next", "return", "returnurl", "dest", "destination",
                "continue", "file", "path", "id", "user", "account", "page", "callback",
                "template", "lang", "q", "search", "token", "key", "debug"}


@register
class ParamDiscoveryAgent(BaseAgent):
    name = "param_discovery"
    role_label = "Parameter Discovery"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Inventories URL parameters from collected surface (Wayback/JS/paths); flags interesting ones. Passive. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        urls = [n["target"] for n in self.ctx.store.all_surface()
                if n.get("kind") in ("url", "endpoint", "path", "live_host")]
        params: dict[str, set] = {}
        endpoints_with_params = []
        for u in urls:
            q = parse_qs(urlparse(u if "://" in u else "https://" + u).query)
            if not q:
                continue
            endpoints_with_params.append(u)
            path = urlparse(u if "://" in u else "https://" + u).path
            for k in q:
                params.setdefault(k.lower(), set()).add(path)

        interesting = sorted(set(params) & _INTERESTING)
        all_params = sorted(params)
        if all_params:
            f = Finding(title=f"{len(all_params)} URL parameter(s) catalogued",
                        severity=Severity.INFO, target=task.target or "",
                        stage=PTESStage.INTELLIGENCE_GATHERING, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description="Parameters harvested from recon — test these for "
                                    "redirect/injection/IDOR."
                                    + (f" Notable: {', '.join(interesting)}." if interesting else ""),
                        reproduction="aggregated from Wayback + JS endpoints in the attack-surface map")
            f.evidence.append(Evidence(kind="note", task_id=task.id,
                content="\n".join(f"{p}  ← {', '.join(sorted(params[p])[:5])}"
                                  for p in all_params[:80])))
            self.ctx.add_finding(f)

        # map parameterized endpoints so open_redirect has candidates
        for u in endpoints_with_params[:100]:
            if self.ctx.scope.allowed(u):
                self.ctx.add_surface_node(f"param_endpoint:{u}", "endpoint", u, u,
                                          {"via": self.role_label, "has_params": True})

        return {"params_found": len(all_params), "interesting": interesting,
                "parameterized_endpoints": len(endpoints_with_params)}
