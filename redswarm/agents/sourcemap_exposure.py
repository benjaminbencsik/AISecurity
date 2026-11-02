"""sourcemap_exposure — check whether a page's JavaScript source maps are publicly
downloadable. A readable .map file hands over the original, un-minified source
(internal routes, comments, sometimes keys), which is a recognized bug class.

Method: read the page's <script> sources (read-only), then for each script look
for a sourceMappingURL hint and the conventional <script>.map. A map is only
flagged when it returns 200 AND parses as a real source map (has "mappings" and
"sources") — the content check is the anti-false-positive gate.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_SCRIPT = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_MAPHINT = re.compile(r"sourceMappingURL=([^\s'\"*]+)")
_MAX_SCRIPTS = 15


@register
class SourcemapExposureAgent(BaseAgent):
    name = "sourcemap_exposure"
    role_label = "Exposed Source Maps"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Finds publicly downloadable JS source maps (.map) that leak original source. Read-only. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        base = task.target or (task.params or {}).get("url", "")
        if not base:
            raise ValueError("sourcemap_exposure needs a target URL")
        if "://" not in base:
            base = "https://" + base
        page = self.ctx.get(base)
        if page.get("error"):
            return {"url": base, "error": page["error"]}

        scripts = []
        for src in _SCRIPT.findall(page.body or ""):
            full = urljoin(base, src)
            if self.ctx.scope.allowed(full) and full not in scripts:
                scripts.append(full)

        exposed = []
        for s in scripts[:_MAX_SCRIPTS]:
            candidates = []
            js = self.ctx.get(s)
            if not js.get("error") and js.body:
                m = _MAPHINT.search(js.body)
                if m:
                    candidates.append(urljoin(s, m.group(1)))
            candidates.append(s + ".map")

            for cand in dict.fromkeys(candidates):          # de-dup, keep order
                if not self.ctx.scope.allowed(cand):
                    continue
                r = self.ctx.get(cand)
                if r.get("error") or r.status != 200 or not r.body:
                    continue
                try:
                    doc = json.loads(r.body)
                except (ValueError, json.JSONDecodeError):
                    continue
                if not (isinstance(doc, dict) and "mappings" in doc and "sources" in doc):
                    continue
                srcs = doc.get("sources") or []
                exposed.append(cand)
                f = Finding(title=f"JavaScript source map exposed: {cand.rsplit('/', 1)[-1]}",
                            severity=Severity.MEDIUM, target=cand,
                            stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                            task_id=task.id, status=FindingStatus.CONFIRMED,
                            description=f"The source map exposes {len(srcs)} original source file(s), "
                                        f"which can reveal internal routes, comments and logic.",
                            reproduction=f"curl -s {cand} | python -m json.tool | head")
                f.evidence.append(Evidence(kind="http", task_id=task.id,
                    content=f"GET {cand} → 200 (valid source map)\nsources: "
                            + ", ".join(str(x) for x in srcs[:20])))
                self.ctx.add_finding(f)
                break                                       # one map per script is enough

        return {"url": base, "scripts": len(scripts), "exposed_maps": exposed}
