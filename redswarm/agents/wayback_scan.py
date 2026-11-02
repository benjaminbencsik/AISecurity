"""wayback_scan — the archive-driven scan. Takes the parameterized URLs recon
collected from the Wayback Machine (and JS / parameter discovery), keeps only
in-scope ones, collapses near-duplicates, caps the list, and runs nuclei
templates across that set in one rate-limited batch.

Why it's useful: historical URLs often point at endpoints the live app has
dropped but still serves, so a template match there is a strong lead.
"""
from __future__ import annotations

import os
import tempfile
from urllib.parse import urlparse, parse_qs

from .. import nuclei
from ..models import Task, PTESStage
from .base import BaseAgent, register

_MAX_URLS = 200


def _key(u: str):
    p = urlparse(u)
    return (p.netloc.lower(), p.path, tuple(sorted(parse_qs(p.query).keys())))


@register
class WaybackScanAgent(BaseAgent):
    name = "wayback_scan"
    role_label = "Wayback Archive Scan"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = ("Runs nuclei templates across in-scope parameterized URLs collected from the Wayback "
                   "archive and recon (deduplicated, capped). Matches need review. Approval-gated.")
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        profile = (task.params or {}).get("profile", "full")
        tags = nuclei.TAGS_BY_PROFILE.get(profile, nuclei.TAGS_BY_PROFILE["full"])

        candidates = [n["target"] for n in self.ctx.store.all_surface()
                      if n.get("kind") in ("url", "endpoint", "param_endpoint")
                      and "?" in (n.get("target") or "")]
        seen, urls = set(), []
        for u in candidates:
            if not self.ctx.scope.allowed(u):
                continue
            k = _key(u)
            if k in seen:
                continue
            seen.add(k)
            urls.append(u)
            if len(urls) >= _MAX_URLS:
                break
        if not urls:
            return {"urls": 0, "note": "no in-scope parameterized URLs in the attack surface yet"}

        fd, path = tempfile.mkstemp(prefix="redswarm-wayback-", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(urls) + "\n")
            args = nuclei.build_args(tags, self.ctx.rps, targets_file=path)
            rows, rc, err = nuclei.run(args)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

        out = nuclei.ingest(self.ctx, task, self.name, rows)
        out.update({"urls": len(urls), "profile": profile, "exit": rc})
        if rc != 0 and err.strip():
            out["stderr_tail"] = err.strip()[-300:]
        return out
