"""nuclei integration — runs ProjectDiscovery's nuclei templates through a
scope-gated, rate-limited, approval-gated wrapper.

Safety defaults baked into every run:
  -ni                no interactsh (no OOB callbacks sent to third-party servers)
  -duc               no implicit update check over the network
  (no -fr)           redirects are NOT followed, so a template can't wander out of scope
  -exclude-tags      dos, fuzz, brute-force, default-login are never run
  -rl                rate limit from the framework's --rps setting
Every matched-at URL is re-checked against the ScopeGuard before it is kept.

Matches are recorded as NEEDS_REVIEW, not CONFIRMED: template matches are good
leads but are not proof, and you confirm each one by hand before reporting.

Requires the nuclei binary. Find it on PATH, or set REDSWARM_NUCLEI to its path.
Set REDSWARM_NUCLEI_TEMPLATES to point at a templates directory.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Optional

from .models import Finding, Evidence, Severity, PTESStage, FindingStatus

TAGS_BY_PROFILE = {
    "medium": "exposure,misconfig,tech,takeover,token",
    "full":   "exposure,misconfig,tech,takeover,token,cve,vuln",
}
EXCLUDE_TAGS = "dos,fuzz,brute-force,default-login"
_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}


class NucleiNotInstalled(RuntimeError):
    """Raised when the nuclei binary cannot be found."""


def binary() -> str:
    path = os.environ.get("REDSWARM_NUCLEI") or shutil.which("nuclei")
    if not path:
        raise NucleiNotInstalled(
            "nuclei not found. Install it (go install -v "
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest) "
            "or set REDSWARM_NUCLEI to its path.")
    return path


def build_args(tags: str, rps: float, *, target: Optional[str] = None,
               targets_file: Optional[str] = None, timeout: int = 10) -> list[str]:
    if bool(target) == bool(targets_file):
        raise ValueError("pass exactly one of target or targets_file")
    args = [binary(), "-jsonl", "-silent", "-nc", "-duc", "-ni",
            "-tags", tags, "-exclude-tags", EXCLUDE_TAGS,
            "-rl", str(max(1, int(rps))), "-timeout", str(timeout), "-retries", "1"]
    tdir = os.environ.get("REDSWARM_NUCLEI_TEMPLATES")
    if tdir:
        args += ["-t", tdir]
    args += ["-u", target] if target else ["-l", targets_file]
    return args


def run(args: list[str], timeout: int = 1200) -> tuple[list[dict], int, str]:
    """Run nuclei without a shell and parse its JSONL output."""
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    rows = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows, proc.returncode, (proc.stderr or "")[-500:]


def ingest(ctx, task, agent_name: str, rows: list[dict]) -> dict:
    """Turn nuclei rows into NEEDS_REVIEW findings. Drops out-of-scope matches."""
    kept = dropped = 0
    for row in rows:
        info = row.get("info") or {}
        matched = row.get("matched-at") or row.get("host") or ""
        if not matched or not ctx.scope.allowed(matched):
            dropped += 1
            continue
        tid = row.get("template-id", "unknown")
        name = info.get("name") or tid
        sev = _SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
        f = Finding(
            title=f"[nuclei] {name}", severity=sev, target=matched,
            stage=PTESStage.VULNERABILITY_ANALYSIS, agent=agent_name,
            task_id=task.id, status=FindingStatus.NEEDS_REVIEW,
            description=(info.get("description") or f"Template {tid} matched. "
                         "Verify it is a real issue before reporting."),
            reproduction=row.get("curl-command") or f"nuclei -id {tid} -u {matched}")
        slim = {k: row.get(k) for k in ("template-id", "matched-at", "matcher-name",
                                        "type", "extracted-results", "timestamp")}
        f.evidence.append(Evidence(kind="http", task_id=task.id,
                                   content=json.dumps(slim, default=str)[:4000]))
        ctx.add_finding(f)
        kept += 1
    return {"matches": len(rows), "kept": kept, "out_of_scope_dropped": dropped}
