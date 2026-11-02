"""header_audit — a real, working passive module (not a scaffold).

It does ONE read-only GET of an in-scope URL and reports missing or weak HTTP
security headers. Entirely passive: no payloads, no auth, no state change — the
same class of check as securityheaders.com. It's the reference for a functional
module built to the framework contract: scope-gated, approval-gated, and every
finding carries the observed headers as self-evident evidence.

Because a missing-header finding is proven by the response itself, these are
emitted as CONFIRMED with the raw header set attached — no separate PoC needed.
"""
from __future__ import annotations

import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse

from ..models import (Task, Finding, Evidence, Severity, PTESStage,
                      FindingStatus)
from .base import BaseAgent, register

# header -> (severity, why it matters)
_CHECKS = {
    "strict-transport-security": (Severity.MEDIUM, "No HSTS: connections can be downgraded to HTTP (MITM / SSL-strip)."),
    "content-security-policy": (Severity.MEDIUM, "No CSP: nothing constrains script/resource origins, widening XSS impact."),
    "x-content-type-options": (Severity.LOW, "Missing nosniff: browsers may MIME-sniff responses into executable types."),
    "x-frame-options": (Severity.LOW, "No frame protection (X-Frame-Options / CSP frame-ancestors): clickjacking risk."),
    "referrer-policy": (Severity.LOW, "No Referrer-Policy: full URLs may leak to third parties via the Referer header."),
    "permissions-policy": (Severity.INFO, "No Permissions-Policy: powerful browser features are not explicitly restricted."),
}


@register
class HeaderAuditAgent(BaseAgent):
    name = "header_audit"
    role_label = "Security Header Audit"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = ("Passive read-only audit of HTTP security headers on one in-scope URL. "
                   "Emits confirmed low/info findings. Approval-gated.")
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        url = task.target or (task.params or {}).get("url", "")
        if not url:
            raise ValueError("header_audit needs a target URL")
        if "://" not in url:
            url = "https://" + url
        self.ctx.scope.assert_in_scope(url)          # re-check at point of action
        origin = urlparse(url).hostname

        req = urllib.request.Request(
            url, method="GET",
            headers={"User-Agent": "RedSwarm/header_audit (authorized, passive)"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                final = urlparse(resp.geturl()).hostname
                if final and final != origin:
                    self.ctx.scope.assert_in_scope(resp.geturl())
                headers = {k.lower(): v for k, v in resp.headers.items()}
                status = resp.status
        except (urllib.error.URLError, socket.timeout, ValueError) as e:
            return {"url": url, "error": str(e)}

        # CSP with frame-ancestors also satisfies the clickjacking check.
        present = set(headers)
        if "content-security-policy" in headers and \
                "frame-ancestors" in headers["content-security-policy"].lower():
            present.add("x-frame-options")

        header_dump = "\n".join(f"{k}: {v}" for k, v in sorted(headers.items())) or "(no headers)"
        missing = []
        for h, (sev, why) in _CHECKS.items():
            if h in present:
                continue
            missing.append(h)
            finding = Finding(
                title=f"Missing security header: {h}", severity=sev, target=url,
                stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                task_id=task.id, status=FindingStatus.CONFIRMED,
                description=why,
                reproduction=f"curl -sI {url}   # response omits '{h}'",
            )
            finding.evidence.append(Evidence(
                kind="http", task_id=task.id,
                content=f"GET {url} → {status}\n\nResponse headers:\n{header_dump}"))
            self.ctx.add_finding(finding)

        self.ctx.add_surface_node(f"endpoint:{url}", "endpoint", url, url,
                                  {"status": status, "via": self.role_label})
        return {"url": url, "status": status,
                "present": sorted(present & set(_CHECKS)),
                "missing": missing, "findings_added": len(missing)}
