"""dir_exposure — checks a SMALL CURATED list of high-signal sensitive paths for
exposure (not a wordlist fuzzer). One GET per path, scope- and rate-gated, and a
path is only flagged when the response both returns 200 and matches a content
signature for that file type — so a catch-all 200 page doesn't cause false
positives (your confirm-it's-real rule, built in).
"""
from __future__ import annotations

import secrets
from urllib.parse import urljoin

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

# path -> (severity, signature substring that must appear in the body)
_CHECKS = {
    "/.git/HEAD":            (Severity.HIGH,   "ref:"),
    "/.git/config":          (Severity.HIGH,   "[core]"),
    "/.env":                 (Severity.HIGH,   "="),
    "/.svn/entries":         (Severity.MEDIUM, ""),
    "/.DS_Store":            (Severity.LOW,    ""),
    "/.htaccess":            (Severity.MEDIUM, ""),
    "/server-status":        (Severity.MEDIUM, "Apache Server Status"),
    "/phpinfo.php":          (Severity.MEDIUM, "phpinfo()"),
    "/.well-known/security.txt": (Severity.INFO, "Contact"),
}


def _looks_like_env(body: str) -> bool:
    lines = [l for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]
    return bool(lines) and sum("=" in l for l in lines) >= max(1, len(lines) // 2)


@register
class DirExposureAgent(BaseAgent):
    name = "dir_exposure"
    role_label = "Sensitive File Exposure"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Checks a small curated list of sensitive paths (.git/.env/backups) with signature matching. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        base = task.target or (task.params or {}).get("url", "")
        if not base:
            raise ValueError("dir_exposure needs a target URL")
        if "://" not in base:
            base = "https://" + base

        # Negative control: a path that cannot exist. If the server returns 200
        # for THIS, it's a catch-all — we then require a positive content
        # signature and a body different from the catch-all page before flagging.
        bl = self.ctx.get(urljoin(base, f"/redswarm-{secrets.token_hex(6)}-404check"))
        catch_all = (not bl.get("error")) and bl.status == 200
        bl_body = bl.body or ""

        found = []
        for path, (sev, sig) in _CHECKS.items():
            url = urljoin(base, path)
            if not self.ctx.scope.allowed(url):
                continue
            r = self.ctx.get(url)
            if r.get("error") or r.status != 200 or not r.body:
                continue
            body = r.body
            if body == bl_body:            # identical to the catch-all page
                continue
            # content signature gate (defeats catch-all false positives)
            if path == "/.env":
                hit = _looks_like_env(body)
            elif path == "/.DS_Store":
                hit = "Bud1" in body or "\x00\x00\x00\x01" in body
            elif sig:
                hit = sig.lower() in body.lower()
            else:
                # no strong signature: only trust it on a non-catch-all server
                low = body[:300].lower()
                hit = (not catch_all) and "<html" not in low and "<title" not in low
            if not hit:
                continue
            info = path in ("/.well-known/security.txt",)
            f = Finding(title=("security.txt present" if info else f"Exposed sensitive path: {path}"),
                        severity=sev, target=url, stage=PTESStage.VULNERABILITY_ANALYSIS,
                        agent=self.name, task_id=task.id,
                        status=FindingStatus.CONFIRMED,
                        description=("A security.txt contact policy is published." if info else
                                     f"{path} is reachable and returns matching content — potential data/source exposure."),
                        reproduction=f"curl -s {url}")
            f.evidence.append(Evidence(kind="http", task_id=task.id,
                                       content=f"GET {url} → 200\n\n{body[:800]}"))
            self.ctx.add_finding(f)
            found.append(path)
        return {"base": base, "checked": len(_CHECKS), "exposed": found}
