"""open_redirect — detector for open-redirect on an in-scope endpoint.

For each common redirect parameter, it sends ONE request with a benign external
marker value and checks whether the server issues a 3xx to that marker (without
following it). If so, the parameter is an open redirect. No payload beyond a URL
value, no redirect ever followed, one probe per parameter, rate-limited and
scope-gated. It flags only on an actual off-domain redirect, so findings are
self-evident (your "confirm it's real" rule, enforced).

Point it at the endpoint you want tested (ideally one that already takes a
redirect-like parameter). It does not crawl or fuzz the whole app.
"""
from __future__ import annotations

from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_MARKER_HOST = "redswarm-oob.example"
_PROBE = f"https://{_MARKER_HOST}/redirect-check"
_PARAMS = ["next", "url", "redirect", "redirect_uri", "redirect_url", "return",
           "returnUrl", "return_to", "dest", "destination", "continue", "r", "u", "to"]
_MAX = 14


def _with_param(url: str, key: str, value: str) -> str:
    u = urlparse(url if "://" in url else "https://" + url)
    q = parse_qs(u.query)
    q[key] = [value]
    return urlunparse(u._replace(query=urlencode({k: v[-1] for k, v in q.items()})))


@register
class OpenRedirectAgent(BaseAgent):
    name = "open_redirect"
    role_label = "Open Redirect"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Detects open redirects: one benign off-domain probe per redirect param, no redirect followed. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        base = task.target or (task.params or {}).get("url", "")
        if not base:
            raise ValueError("open_redirect needs a target URL")
        if "://" not in base:
            base = "https://" + base
        self.ctx.scope.assert_in_scope(base)

        # Prefer params already present on the URL; else try the common set.
        present = list(parse_qs(urlparse(base).query).keys())
        candidates = [p for p in present if p.lower() in _PARAMS] or _PARAMS
        tested, vulnerable = [], []

        for key in candidates[:_MAX]:
            probe_url = _with_param(base, key, _PROBE)
            r = self.ctx.get(probe_url, allow_redirects=False)
            tested.append(key)
            if r.get("error"):
                continue
            loc = (r.location or "").strip()
            if 300 <= (r.status or 0) < 400 and loc:
                loc_host = urlparse(loc if "://" in loc else "https://" + loc.lstrip("/")).hostname or ""
                if loc_host == _MARKER_HOST or loc.startswith(_PROBE):
                    vulnerable.append((key, r.status, loc))
                    f = Finding(
                        title=f"Open redirect via '{key}' parameter",
                        severity=Severity.MEDIUM, target=base,
                        stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description=f"The '{key}' parameter redirects to an attacker-supplied "
                                    f"external host without validation.",
                        reproduction=f"GET {probe_url}\n→ {r.status} Location: {loc}")
                    f.evidence.append(Evidence(kind="http", task_id=task.id,
                        content=f"Request: {probe_url}\nResponse: {r.status}\nLocation: {loc}"))
                    self.ctx.add_finding(f)

        return {"url": base, "params_tested": tested,
                "vulnerable": [v[0] for v in vulnerable]}
