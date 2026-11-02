"""Validation harness — prove a finding is real before it ships.

It runs an operator-written PoC (a Python script) in an isolated subprocess and
decides CONFIRMED / FALSE_POSITIVE / NEEDS_REVIEW from the PoC's own verdict.
The framework does NOT write exploits for you; it runs the ones you wrote and
records the outcome as evidence. This is the "no false positives" rule, made
mechanical.

PoC contract
------------
Your PoC is a normal Python file. It must print a single verdict line to stdout:

    REDSWARM_RESULT: CONFIRMED      # the vulnerability reproduced
    REDSWARM_RESULT: FALSE_POSITIVE # it did not reproduce
    REDSWARM_RESULT: NEEDS_REVIEW   # inconclusive — a human should look

Anything else on stdout/stderr is captured as evidence. The harness passes the
finding's target as argv[1] and sets REDSWARM_TARGET in the environment. It will
refuse to run if that target is out of scope.

Safety
------
  * The PoC runs with `python -I` (isolated: ignores env PYTHONPATH and the
    user site dir, so a planted module can't hijack imports).
  * Hard timeout; killed if it overruns.
  * cwd is the PoC's own directory, nothing is run from the target's files.
  * Scope is re-checked against the finding target immediately before launch.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Optional

from .models import Finding, Evidence, FindingStatus
from .scope import ScopeGuard
from .audit import AuditLog
from .store import Store

_VERDICT_PREFIX = "REDSWARM_RESULT:"
_VERDICTS = {
    "CONFIRMED": FindingStatus.CONFIRMED,
    "FALSE_POSITIVE": FindingStatus.FALSE_POSITIVE,
    "NEEDS_REVIEW": FindingStatus.NEEDS_REVIEW,
}


class ValidationHarness:
    def __init__(self, scope: ScopeGuard, store: Store, audit: AuditLog,
                 timeout: int = 60):
        self.scope = scope
        self.store = store
        self.audit = audit
        self.timeout = timeout

    def _parse_verdict(self, stdout: str) -> Optional[FindingStatus]:
        verdict = None
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith(_VERDICT_PREFIX):
                token = line[len(_VERDICT_PREFIX):].strip().upper()
                verdict = _VERDICTS.get(token)  # last one wins
        return verdict

    def validate(self, finding: Finding, poc_path: str,
                 operator: str = "operator") -> Finding:
        if not os.path.isfile(poc_path):
            raise FileNotFoundError(poc_path)

        # Scope gate on the finding's own target.
        self.scope.assert_in_scope(finding.target)

        self.audit.log(operator, "validation_started", finding.target,
                       finding.task_id, {"finding_id": finding.id, "poc": poc_path})

        env = {
            "PATH": os.environ.get("PATH", ""),
            "REDSWARM_TARGET": finding.target,
            "REDSWARM_FINDING": finding.id,
        }
        started = time.time()
        try:
            proc = subprocess.run(
                [sys.executable, "-I", poc_path, finding.target],
                cwd=os.path.dirname(os.path.abspath(poc_path)) or ".",
                capture_output=True, text=True, timeout=self.timeout,
                env=env, check=False,
            )
            stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as e:
            stdout = e.stdout or ""
            stderr = (e.stderr or "") + f"\n[harness] timed out after {self.timeout}s"
            rc = -1
            timed_out = True
        elapsed = time.time() - started

        verdict = self._parse_verdict(stdout)
        if timed_out or verdict is None:
            new_status = FindingStatus.NEEDS_REVIEW
        else:
            new_status = verdict

        log_blob = (
            f"$ python -I {os.path.basename(poc_path)} {finding.target}\n"
            f"[exit {rc}  {elapsed:.2f}s]\n"
            f"--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n"
        )

        finding.status = new_status
        finding.validation_log = log_blob
        finding.evidence.append(Evidence(
            kind="command_output",
            content=log_blob[:20000],
            task_id=finding.task_id,
        ))
        self.store.save_finding(finding)

        self.audit.log(operator, "validation_result", finding.target,
                       finding.task_id,
                       {"finding_id": finding.id, "status": new_status.value,
                        "exit_code": rc, "elapsed_s": round(elapsed, 2)})
        return finding

    def mark_manual(self, finding: Finding, status: FindingStatus,
                    note: str, operator: str = "operator") -> Finding:
        """Operator sets a status by hand (e.g. after manual Burp repro)."""
        finding.status = status
        if note:
            finding.evidence.append(Evidence(kind="note", content=note,
                                             task_id=finding.task_id))
        self.store.save_finding(finding)
        self.audit.log(operator, "validation_manual", finding.target,
                       finding.task_id,
                       {"finding_id": finding.id, "status": status.value, "note": note})
        return finding
