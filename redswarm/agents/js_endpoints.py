"""js_endpoints — read-only JavaScript analysis. Fetches a page, pulls its
script sources, and mines them for endpoints / API routes (which expand the
attack surface) and for things that look like leaked secrets.

Everything is read-only and scope-gated. Secret-looking matches are emitted as
NEEDS_REVIEW (not auto-confirmed) because these patterns are noisy — an operator
confirms before it becomes a finding. Endpoints are mapped into the surface.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# endpoint-ish strings inside JS
_PATHS = re.compile(r'["\'](/(?:api|v\d|graphql|rest|internal|admin|user|auth|account)[\w\-/.{}:]*)["\']', re.I)
_FULLURL = re.compile(r'["\'](https?://[\w.\-]+/[\w\-/.{}:?=&%]*)["\']')
# secret-ish patterns (noisy on purpose -> NEEDS_REVIEW)
_SECRETS = [
    ("AWS access key id", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("Google API key", re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("Slack token", re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,48}')),
    ("Generic bearer/api key assignment", re.compile(r'(?i)(api[_-]?key|secret|token)["\']?\s*[:=]\s*["\'][0-9A-Za-z\-_]{16,}["\']')),
    ("Private key block", re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
]
_MAX_SCRIPTS = 15


@register
class JsEndpointsAgent(BaseAgent):
    name = "js_endpoints"
    role_label = "JS Endpoint & Secret Extraction"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Read-only: mine a page's JavaScript for endpoints/API routes and possible leaked secrets. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        base = task.target or (task.params or {}).get("url", "")
        if not base:
            raise ValueError("js_endpoints needs a target URL")
        if "://" not in base:
            base = "https://" + base
        page = self.ctx.get(base)
        if page.get("error"):
            return {"url": base, "error": page["error"]}

        script_urls = []
        for src in _SCRIPT_SRC.findall(page.body):
            full = urljoin(base, src)
            if self.ctx.scope.allowed(full) and full not in script_urls:
                script_urls.append(full)

        endpoints, secrets = set(), []
        blobs = [("inline", page.body)]
        for su in script_urls[:_MAX_SCRIPTS]:
            r = self.ctx.get(su)
            if not r.get("error"):
                blobs.append((su, r.body))

        for origin, blob in blobs:
            for m in _PATHS.findall(blob):
                endpoints.add(m)
            for m in _FULLURL.findall(blob):
                endpoints.add(m)
            for label, rx in _SECRETS:
                for hit in rx.findall(blob):
                    sample = hit if isinstance(hit, str) else hit[0]
                    secrets.append((label, origin, str(sample)[:12] + "…"))

        mapped = 0
        for ep in sorted(endpoints)[:200]:
            full = ep if ep.startswith("http") else urljoin(base, ep)
            if not self.ctx.scope.allowed(full):
                continue
            self.ctx.add_surface_node(f"endpoint:{full}", "endpoint", full, full,
                                      {"via": self.role_label, "source": "javascript"})
            mapped += 1

        if endpoints:
            f = Finding(title=f"{len(endpoints)} endpoint(s) extracted from JavaScript",
                        severity=Severity.INFO, target=base,
                        stage=PTESStage.INTELLIGENCE_GATHERING, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description="Client-side JS references routes worth testing.",
                        reproduction=f"fetch {base} and its <script> sources; grep for /api, /v1, graphql")
            f.evidence.append(Evidence(kind="note", task_id=task.id,
                                       content="\n".join(sorted(endpoints)[:120])))
            self.ctx.add_finding(f)

        for label, origin, sample in secrets[:25]:
            f = Finding(title=f"Possible secret in JS: {label}", severity=Severity.MEDIUM,
                        target=base, stage=PTESStage.VULNERABILITY_ANALYSIS,
                        agent=self.name, task_id=task.id,
                        status=FindingStatus.NEEDS_REVIEW,   # operator verifies (noisy class)
                        description=f"A {label} pattern appeared in {origin}. Verify it is live/sensitive.",
                        reproduction=f"review the script: {origin}")
            f.evidence.append(Evidence(kind="note", task_id=task.id,
                                       content=f"{label} (redacted): {sample}  in {origin}"))
            self.ctx.add_finding(f)

        return {"url": base, "scripts": len(script_urls), "endpoints": len(endpoints),
                "endpoints_mapped": mapped, "possible_secrets": len(secrets)}
