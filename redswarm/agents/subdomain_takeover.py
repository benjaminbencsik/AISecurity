"""subdomain_takeover — detect dangling subdomains pointing at unclaimed
third-party services. For each in-scope subdomain with a CNAME to a known
provider, fetch it and match the provider's "unclaimed" fingerprint. A match is
a confirmed, high-value takeover. One GET per candidate, scope- and rate-gated.
"""
from __future__ import annotations

from .. import dns
from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

# cname substring -> (service, body fingerprint of an unclaimed target)
_FINGERPRINTS = {
    "github.io":            ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com":        ("Heroku", "No such app"),
    "s3.amazonaws.com":     ("AWS S3", "NoSuchBucket"),
    "amazonaws.com":        ("AWS S3", "NoSuchBucket"),
    "cloudfront.net":       ("CloudFront", "ERROR: The request could not be satisfied"),
    "github.map.fastly.net": ("Fastly", "Fastly error: unknown domain"),
    "wordpress.com":        ("WordPress", "Do you want to register"),
    "ghost.io":             ("Ghost", "The thing you were looking for is no longer here"),
    "surge.sh":             ("Surge", "project not found"),
    "bitbucket.io":         ("Bitbucket", "Repository not found"),
    "netlify.app":          ("Netlify", "Not Found - Request ID"),
    "readthedocs.io":       ("Read the Docs", "unknown to Read the Docs"),
    "zendesk.com":          ("Zendesk", "Help Center Closed"),
    "fastly.net":           ("Fastly", "Fastly error: unknown domain"),
}
_MAX = 80


@register
class SubdomainTakeoverAgent(BaseAgent):
    name = "subdomain_takeover"
    role_label = "Subdomain Takeover"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Detects dangling CNAMEs to unclaimed services via provider fingerprints. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        subs = [n["target"] for n in self.ctx.store.all_surface()
                if n.get("kind") == "subdomain"]
        checked, candidates, vulnerable = 0, [], []
        for host in subs[:_MAX]:
            if not self.ctx.scope.allowed(host):
                continue
            cnames = dns.query(host, "CNAME")
            if not cnames:
                continue
            cname = cnames[0].lower()
            provider = next((v for k, v in _FINGERPRINTS.items() if k in cname), None)
            if not provider:
                continue
            checked += 1
            service, sig = provider
            candidates.append({"host": host, "cname": cname, "service": service})
            for scheme in ("https", "http"):
                r = self.ctx.get(f"{scheme}://{host}/", timeout=8)
                if r.get("error"):
                    continue
                if sig.lower() in (r.body or "").lower():
                    vulnerable.append(host)
                    f = Finding(
                        title=f"Subdomain takeover: {host} → {service}",
                        severity=Severity.HIGH, target=host,
                        stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description=f"{host} has a dangling CNAME to {cname} ({service}) whose "
                                    f"target is unclaimed — register it to take over the subdomain.",
                        reproduction=f"dig CNAME {host}  # → {cname}\ncurl {scheme}://{host}/  # unclaimed fingerprint")
                    f.evidence.append(Evidence(kind="http", task_id=task.id,
                        content=f"CNAME: {cname}\nFingerprint matched: {sig!r}"))
                    self.ctx.add_finding(f)
                    break
        return {"cname_candidates": len(candidates), "checked": checked,
                "vulnerable": vulnerable}
