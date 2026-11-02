"""Run RedSwarm on a VPS over SSH.

Why: scans then come from a server you control, not your home IP, and you can
pick the region. Everything goes through plain `ssh`, so your existing keys,
~/.ssh/config and agent are used. Nothing is stored here: no passwords, no tokens.

    python -m redswarm vps setup user@host          # copy the project up, run doctor
    python -m redswarm go TARGET --via user@host    # scope + scan on the VPS, report back
    python -m redswarm vps tunnel user@host         # forward the dashboard to localhost:8700

Requirements: ssh on this machine, key-based login to the VPS (BatchMode is on,
so it never prompts for a password), and python3 3.10+ on the VPS.
The dashboard stays bound to 127.0.0.1 on the VPS. You reach it through the tunnel.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EXCLUDES = ["--exclude=.git", "--exclude=data", "--exclude=reports", "--exclude=__pycache__"]


def _ssh(via: str, port: int | None, remote_cmd: str) -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    if port:
        cmd += ["-p", str(port)]
    return cmd + [via, remote_cmd]


def check(via: str, port: int | None = None) -> bool:
    r = subprocess.run(_ssh(via, port, "echo redswarm-ok"), capture_output=True, text=True)
    if r.returncode != 0 or "redswarm-ok" not in r.stdout:
        print(f"Cannot reach {via} over ssh (exit {r.returncode}).", file=sys.stderr)
        print((r.stderr or "").strip()[-400:], file=sys.stderr)
        print("Check: key-based login works (ssh " + via + "), and the host is correct.",
              file=sys.stderr)
        return False
    return True


def setup(via: str, port: int | None = None, remote_dir: str = "redswarm") -> int:
    """Copy the project to the VPS and run its doctor there."""
    if not check(via, port):
        return 1
    print(f"Copying project to {via}:{remote_dir} ...")
    tar = subprocess.Popen(["tar", "-C", PROJECT_ROOT, *_EXCLUDES, "-cf", "-", "."],
                           stdout=subprocess.PIPE)
    put = subprocess.run(
        _ssh(via, port, f"mkdir -p {shlex.quote(remote_dir)} && tar -xf - -C {shlex.quote(remote_dir)}"),
        stdin=tar.stdout, capture_output=True, text=True)
    tar.stdout.close()
    tar.wait()
    # tar exits 1 for warnings such as "file changed as we read it"; the copy can still be complete
    if put.returncode:
        print("Copy failed:", (put.stderr or "").strip()[-400:], file=sys.stderr)
        return 1
    if tar.returncode not in (0, 1):
        print("Packing the project failed (tar exit %d)." % tar.returncode, file=sys.stderr)
        return 1
    print("Running doctor on the VPS:\n")
    d = subprocess.run(_ssh(via, port, f"cd {shlex.quote(remote_dir)} && python3 -m redswarm doctor"))
    return d.returncode


def run_remote_scan(via: str, port: int | None, remote_dir: str, scope_text: str,
                    scope_rel: str, target: str, profile: str, rps: float,
                    report_rel: str, local_report: str) -> int:
    """Ship the scope, run one scan on the VPS, and copy the report back."""
    if not check(via, port):
        return 1
    rd = shlex.quote(remote_dir)
    put = subprocess.run(
        _ssh(via, port, f"mkdir -p {rd}/{shlex.quote(os.path.dirname(scope_rel))} && "
                        f"cat > {rd}/{shlex.quote(scope_rel)}"),
        input=scope_text, capture_output=True, text=True)
    if put.returncode:
        print("Could not send scope:", (put.stderr or "").strip()[-400:], file=sys.stderr)
        return 1

    scan = ["python3", "-m", "redswarm", "--data", "data", "--rps", str(rps), "scan",
            "--scope", scope_rel, "--target", target, "--profile", profile,
            "--authorize", "--report", report_rel]
    print(f"Running on {via}: {profile} scan of {target}")
    code = subprocess.run(
        _ssh(via, port, f"cd {rd} && mkdir -p data reports && "
                        + " ".join(shlex.quote(x) for x in scan))).returncode

    got = subprocess.run(_ssh(via, port, f"cat {rd}/{shlex.quote(report_rel)}"),
                         capture_output=True, text=True)
    if got.returncode == 0 and got.stdout:
        os.makedirs(os.path.dirname(os.path.abspath(local_report)), exist_ok=True)
        with open(local_report, "w", encoding="utf-8") as fh:
            fh.write(got.stdout)
        print(f"Report copied back: {local_report}")
    else:
        print(f"No report found on the VPS at {report_rel} (scan exit {code}).", file=sys.stderr)
    return code


def tunnel(via: str, port: int | None = None, local_port: int = 8700) -> int:
    """Forward localhost:local_port to the dashboard on the VPS (127.0.0.1:8700 there).
    Start the dashboard on the VPS first:  python3 -m redswarm serve --scope data/...json"""
    if not check(via, port):
        return 1
    cmd = ["ssh", "-o", "BatchMode=yes", "-N", "-L", f"{local_port}:127.0.0.1:8700"]
    if port:
        cmd += ["-p", str(port)]
    print(f"Dashboard: http://127.0.0.1:{local_port}  (Ctrl-C to close the tunnel)")
    try:
        return subprocess.run(cmd + [via]).returncode
    except KeyboardInterrupt:
        return 0
