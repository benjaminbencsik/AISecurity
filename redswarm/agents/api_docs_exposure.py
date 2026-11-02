"""api_docs_exposure — check for publicly reachable API documentation: Swagger /
OpenAPI specs and GraphQL IDE pages. Public docs enumerate every endpoint and
parameter, which is a major recon gift and often a reportable finding.

Same anti-false-positive design as dir_exposure: a negative-control request for a
path that cannot exist establishes the catch-all baseline, a body identical to it
is ignored, and a path only counts when its CONTENT matches the doc format.
"""
from __future__ import annotations

import secrets
from urllib.parse import urljoin

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

# path -> (severity, kind, content signature that must appear)
_CHECKS = {
    "/swagger.json":          (Severity.MEDIUM, "OpenAPI/Swagger spec", ('"swagger"', '"openapi"')),
    "/openapi.json":          (Severity.MEDIUM, "OpenAPI spec", ('"openapi"',)),
    "/v2/api-docs":           (Severity.MEDIUM, "Swagger API docs", ('"swagger"', '"paths"')),
    "/v3/api-docs":           (Severity.MEDIUM, "OpenAPI API docs", ('"openapi"', '"paths"')),
    "/api-docs":              (Severity.MEDIUM, "API docs", ('"paths"', '"swagger"', '"openapi"')),
    "/swagger-ui.html":       (Severity.LOW,    "Swagger UI", ("swagger-ui",)),
    "/graphiql":              (Severity.LOW,    "GraphiQL IDE", ("graphiql",)),
    "/playground":            (Severity.LOW,    "GraphQL Playground", ("graphql-playground", "playground")),
}


@register
class ApiDocsExposureAgent(BaseAgent):
    name = "api_docs_exposure"
    role_label = "Exposed API Docs"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Finds publicly reachable Swagger/OpenAPI specs and GraphQL IDEs; signature + catch-all checked. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        base = task.target or (task.params or {}).get("url", "")
        if not base:
            raise ValueError("api_docs_exposure needs a target URL")
        if "://" not in base:
            base = "https://" + base

        # negative control: a path that cannot exist, to detect catch-all pages
        bl = self.ctx.get(urljoin(base, f"/redswarm-{secrets.token_hex(6)}-404"))
        bl_body = (bl.body or "") if not bl.get("error") else ""

        exposed = []
        for path, (sev, kind, sigs) in _CHECKS.items():
            url = urljoin(base, path)
            if not self.ctx.scope.allowed(url):
                continue
            r = self.ctx.get(url)
            if r.get("error") or r.status != 200 or not r.body:
                continue
            body = r.body
            if body == bl_body:
                continue
            low = body.lower()
            if not any(s.lower() in low for s in sigs):
                continue
            exposed.append(path)
            f = Finding(title=f"Public {kind} exposed: {path}", severity=sev, target=url,
                        stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description=f"{kind} is publicly reachable at {path}, enumerating API "
                                    f"surface to any unauthenticated client.",
                        reproduction=f"curl -s {url}")
            f.evidence.append(Evidence(kind="http", task_id=task.id,
                                       content=f"GET {url} → 200\n\n{body[:600]}"))
            self.ctx.add_finding(f)
            self.ctx.add_surface_node(f"docs:{url}", "endpoint", url, url,
                                      {"via": self.role_label, "kind": kind})
        return {"base": base, "exposed": exposed}
