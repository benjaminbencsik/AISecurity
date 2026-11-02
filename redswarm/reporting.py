"""Reporting — turn confirmed findings into a client-ready document.

Pure synthesis: it reads what's in the store and writes Markdown (and a simple
standalone HTML rendering). Every finding is printed with its traceability
block — the agent, the task id, and the evidence — so a reader can follow any
claim back to where it came from. By default only CONFIRMED findings go in the
body; everything else is listed in an appendix so nothing is silently dropped.
"""
from __future__ import annotations

import html
import time
from typing import Optional

from .models import Finding, FindingStatus, Severity, SEVERITY_ORDER, PTES_ORDER
from .store import Store
from .scope import ScopeGuard
from .audit import AuditLog


def _hydrate_finding(d: dict) -> Finding:
    from .models import Evidence
    f = Finding(
        title=d["title"], severity=Severity(d["severity"]), target=d["target"],
        description=d.get("description", ""),
        status=FindingStatus(d["status"]), agent=d.get("agent", ""),
        task_id=d.get("task_id", ""), reproduction=d.get("reproduction", ""),
        validation_log=d.get("validation_log", ""), id=d["id"],
        created_at=d.get("created_at", 0), updated_at=d.get("updated_at", 0),
    )
    f.evidence = [Evidence(**e) for e in d.get("evidence", [])]
    return f


class ReportBuilder:
    def __init__(self, store: Store, scope: ScopeGuard, audit: AuditLog):
        self.store = store
        self.scope = scope
        self.audit = audit

    def _findings(self) -> list[Finding]:
        fs = [_hydrate_finding(d) for d in self.store.all_findings()]
        fs.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
        return fs

    def build_markdown(self, engagement: Optional[str] = None) -> str:
        findings = self._findings()
        confirmed = [f for f in findings if f.status == FindingStatus.CONFIRMED]
        others = [f for f in findings if f.status != FindingStatus.CONFIRMED]
        name = engagement or self.scope.scope.name
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        counts = {s: 0 for s in Severity}
        for f in confirmed:
            counts[f.severity] += 1

        out: list[str] = []
        out.append(f"# Penetration Test Report — {name}\n")
        out.append(f"_Generated {ts}_\n")
        out.append("## Scope\n")
        s = self.scope.summary()
        out.append(f"- **Engagement:** {s['name']}")
        if s["domains"]:
            out.append(f"- **In-scope domains:** {', '.join(s['domains'])}")
        if s["cidrs"]:
            out.append(f"- **In-scope ranges:** {', '.join(s['cidrs'])}")
        if s["url_prefixes"]:
            out.append(f"- **In-scope URL prefixes:** {', '.join(s['url_prefixes'])}")
        if s["exclude_domains"] or s["exclude_cidrs"]:
            ex = s["exclude_domains"] + s["exclude_cidrs"]
            out.append(f"- **Explicitly out of scope:** {', '.join(ex)}")
        out.append("")

        out.append("## Executive summary\n")
        out.append(
            f"This assessment confirmed **{len(confirmed)}** finding(s): "
            + ", ".join(f"{counts[s]} {s.value}" for s in
                        [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                         Severity.LOW, Severity.INFO] if counts[s]) + "."
            if confirmed else
            "No findings were confirmed during this assessment."
        )
        out.append("")

        ok, chain = self.audit.verify()
        out.append(f"_Audit trail integrity: **{chain}**._\n")

        out.append("## Confirmed findings\n")
        if not confirmed:
            out.append("_None._\n")
        for i, f in enumerate(confirmed, 1):
            out.append(self._finding_md(i, f))

        if others:
            out.append("## Appendix: unconfirmed / excluded\n")
            out.append("| Finding | Severity | Status | Target |")
            out.append("|---|---|---|---|")
            for f in others:
                out.append(f"| {f.title} | {f.severity.value} | "
                           f"{f.status.value} | {f.target} |")
            out.append("")

        return "\n".join(out)

    def _finding_md(self, idx: int, f: Finding) -> str:
        lines = [f"### {idx}. {f.title}  `[{f.severity.value.upper()}]`\n"]
        lines.append(f"- **Target:** {f.target}")
        lines.append(f"- **Status:** {f.status.value}")
        lines.append(f"- **Surfaced by agent:** `{f.agent or 'n/a'}`")
        lines.append(f"- **Traceability:** task `{f.task_id or 'n/a'}` · finding `{f.id}`")
        lines.append("")
        if f.description:
            lines.append("**Description**\n")
            lines.append(f.description + "\n")
        if f.reproduction:
            lines.append("**Reproduction**\n")
            lines.append("```\n" + f.reproduction.strip() + "\n```\n")
        if f.evidence:
            lines.append("**Evidence**\n")
            for ev in f.evidence:
                snippet = ev.content.strip()
                if len(snippet) > 4000:
                    snippet = snippet[:4000] + "\n... [truncated]"
                lines.append(f"<details><summary>{ev.kind} · {ev.id}</summary>\n")
                lines.append("```\n" + snippet + "\n```\n")
                lines.append("</details>\n")
        lines.append("")
        return "\n".join(lines)

    def build_html(self, engagement: Optional[str] = None) -> str:
        md = self.build_markdown(engagement)
        # Minimal, dependency-free rendering: present the Markdown in a styled
        # <pre>. (Swap in your Markdown engine if you want rich HTML.)
        safe = html.escape(md)
        return f"""<!doctype html><meta charset="utf-8">
<title>Report — {html.escape(engagement or self.scope.scope.name)}</title>
<style>
 body{{background:#0f1115;color:#e6e6e6;font:14px/1.6 ui-monospace,Menlo,Consolas,monospace;margin:0;padding:2rem;}}
 pre{{white-space:pre-wrap;max-width:60rem;margin:auto;}}
 a{{color:#7aa2f7;}}
</style>
<pre>{safe}</pre>"""

    def write(self, md_path: str, html_path: Optional[str] = None,
              engagement: Optional[str] = None) -> None:
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(self.build_markdown(engagement))
        if html_path:
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(self.build_html(engagement))
        self.audit.log("system", "report_generated", "", "",
                       {"md": md_path, "html": html_path})
