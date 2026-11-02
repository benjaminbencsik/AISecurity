"""graphql_introspection — checks whether a GraphQL endpoint has introspection
enabled. Sends ONE read-only introspection query (a standard GraphQL query, not
a mutation — it changes nothing) to a few common GraphQL paths and reports if
the schema comes back. Exposed introspection on a production API is a common,
reportable finding (it maps the whole API for an attacker).
"""
from __future__ import annotations

import json
from urllib.parse import urljoin

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/query"]
_QUERY = json.dumps({"query": "{__schema{queryType{name}}}"}).encode("utf-8")


@register
class GraphqlIntrospectionAgent(BaseAgent):
    name = "graphql_introspection"
    role_label = "GraphQL Introspection"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Read-only introspection query to common GraphQL paths; flags if the schema is exposed. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        base = task.target or (task.params or {}).get("url", "")
        if not base:
            raise ValueError("graphql_introspection needs a target URL")
        if "://" not in base:
            base = "https://" + base
        checked, exposed = [], []
        for path in _PATHS:
            url = urljoin(base, path)
            if not self.ctx.scope.allowed(url):
                continue
            checked.append(path)
            r = self.ctx.get(url, data=_QUERY,
                             headers={"Content-Type": "application/json"})
            if r.get("error") or not r.body:
                continue
            try:
                doc = json.loads(r.body)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(doc, dict) and doc.get("data", {}).get("__schema"):
                exposed.append(path)
                f = Finding(title="GraphQL introspection enabled",
                            severity=Severity.MEDIUM, target=url,
                            stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                            task_id=task.id, status=FindingStatus.CONFIRMED,
                            description="The endpoint answers introspection queries, exposing the full "
                                        "API schema (types, queries, mutations) to any client.",
                            reproduction=f"curl -s {url} -H 'Content-Type: application/json' "
                                         f"-d '{{\"query\":\"{{__schema{{queryType{{name}}}}}}\"}}'")
                f.evidence.append(Evidence(kind="http", task_id=task.id,
                                           content=f"POST {url}\n\n{r.body[:600]}"))
                self.ctx.add_finding(f)
        return {"base": base, "checked": checked, "exposed": exposed}
