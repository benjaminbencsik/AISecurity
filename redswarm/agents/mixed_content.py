"""mixed_content — read-only check for insecure (http://) subresources loaded by
an HTTPS page. Parses the HTML only; makes no request to the subresources.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_SRC = re.compile(r'(?:src|href)=["\'](http://[^"\']+)["\']', re.I)
_LOADERS = re.compile(r'<(script|iframe|link|img|audio|video|source)\b[^>]*?(?:src|href)=["\'](http://[^"\']+)', re.I)


@register
class MixedContentAgent(BaseAgent):
    name = "mixed_content"
    role_label = "Mixed Content"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Read-only: flag http:// subresources on an HTTPS page (mixed content). Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        url = task.target or (task.params or {}).get("url", "")
        if not url:
            raise ValueError("mixed_content needs a target URL")
        if "://" not in url:
            url = "https://" + url
        if urlparse(url).scheme != "https":
            return {"url": url, "skipped": "target is not https"}
        r = self.ctx.get(url)
        if r.get("error"):
            return {"url": url, "error": r["error"]}

        active = [(tag, u) for tag, u in _LOADERS.findall(r.body)
                  if tag.lower() in ("script", "iframe", "link")]
        passive = set(_SRC.findall(r.body))
        if active or passive:
            sev = Severity.MEDIUM if active else Severity.LOW
            f = Finding(title="Mixed content: http:// resources on an HTTPS page",
                        severity=sev, target=url, stage=PTESStage.VULNERABILITY_ANALYSIS,
                        agent=self.name, task_id=task.id, status=FindingStatus.CONFIRMED,
                        description=("Active mixed content (script/iframe/link) can be MITM'd to run "
                                     "attacker code." if active else
                                     "Passive mixed content leaks and can be tampered in transit."),
                        reproduction=f"view-source:{url}  # grep for http:// src/href")
            f.evidence.append(Evidence(kind="http", task_id=task.id,
                content="\n".join(sorted({u for _, u in active} | passive)[:50])))
            self.ctx.add_finding(f)
        return {"url": url, "active_mixed": len(active), "passive_mixed": len(passive)}
