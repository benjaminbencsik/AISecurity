"""nuclei_scan — runs ProjectDiscovery nuclei templates against one in-scope target.
Tag set depends on the scan profile (medium: exposure/misconfig/tech/takeover/token;
full adds cve + vuln). See redswarm/nuclei.py for the safety defaults.
"""
from __future__ import annotations

import os

from .. import nuclei
from ..models import Task, PTESStage
from .base import BaseAgent, register


@register
class NucleiScanAgent(BaseAgent):
    name = "nuclei_scan"
    role_label = "Nuclei Template Scan"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = ("Runs nuclei templates against the target (tags chosen by profile). "
                   "dos/fuzz/brute-force/default-login excluded; matches need review. Approval-gated.")
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        url = task.target or (task.params or {}).get("url", "")
        if not url:
            raise ValueError("nuclei_scan needs a target URL")
        if "://" not in url:
            url = "https://" + url
        self.ctx.scope.assert_in_scope(url)
        profile = (task.params or {}).get("profile", "medium")
        tags = nuclei.TAGS_BY_PROFILE.get(profile, nuclei.TAGS_BY_PROFILE["medium"])

        args = nuclei.build_args(tags, self.ctx.rps, target=url)
        rows, rc, err = nuclei.run(args)
        out = nuclei.ingest(self.ctx, task, self.name, rows)
        out.update({"url": url, "profile": profile, "exit": rc})
        if rc != 0 and err.strip():
            out["stderr_tail"] = err.strip()[-300:]
        return out
