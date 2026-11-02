"""RedSwarm CLI.

    python -m redswarm serve  --scope scope.json [--port 8700]
    python -m redswarm scan   --scope scope.json --target URL --authorize [--report out.md]
    python -m redswarm watch  --scope scope.json --target URL --authorize
                              [--interval 900] [--webhook URL]

`scan` runs the passive, read-only suite once. `watch` repeats it on an interval
and diffs each run, reporting new assets / findings (and optionally POSTing them
to a webhook). Both require --authorize: you are asserting you have written
authorization for every in-scope target. Passive modules are approval-gated in
the UI; --authorize is that approval, given explicitly on the command line.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from .scope import Scope, ScopeGuard
from .store import Store
from .audit import AuditLog
from .approvals import ApprovalQueue
from .orchestrator import Orchestrator
from .reporting import ReportBuilder
from .monitor import Monitor, webhook_notifier
from .models import Task, PTESStage
from .agents import PASSIVE_SUITE, SCAN_SUITE


def _boot(scope_path: str, data_dir: str, rps: float):
    os.makedirs(data_dir, exist_ok=True)
    scope = ScopeGuard(Scope.load(scope_path))
    store = Store(os.path.join(data_dir, "redswarm.db"))
    audit = AuditLog(os.path.join(data_dir, "audit.log"))
    approvals = ApprovalQueue(store, audit)
    orch = Orchestrator(scope, store, audit, approvals, rps=rps)
    return scope, store, audit, approvals, orch


_RECON_AGENTS = {"subdomain_recon", "tech_fingerprint", "js_endpoints"}


def _submit_suite(orch, approvals, target: str, authorize: bool, suite):
    ids = []
    for agent in suite:
        stage = (PTESStage.INTELLIGENCE_GATHERING if agent in _RECON_AGENTS
                 else PTESStage.VULNERABILITY_ANALYSIS)
        t = Task(objective=f"{agent} on {target}", stage=stage, agent=agent, target=target)
        orch.submit(t)
        ids.append(t.id)
    if authorize:
        for a in approvals.pending():
            approvals.approve(a["id"], operator="cli --authorize",
                              note="operator authorized via CLI")
    return ids


def cmd_scan(args):
    scope, store, audit, approvals, orch = _boot(args.scope, args.data, args.rps)
    if not scope.allowed(args.target):
        print(f"[scope] {args.target} is NOT in scope — refusing.", file=sys.stderr)
        return 2
    suite = PASSIVE_SUITE if getattr(args, "passive_only", False) else SCAN_SUITE
    _submit_suite(orch, approvals, args.target, args.authorize, suite)
    if not args.authorize:
        print("Tasks submitted but gated. Re-run with --authorize to run them.")
        return 0
    orch.run_until_idle()
    rb = ReportBuilder(store, scope, audit)
    confirmed = [f for f in store.all_findings() if f["status"] == "confirmed"]
    print(f"[scan] {args.target}: {len(confirmed)} confirmed finding(s)")
    for f in sorted(confirmed, key=lambda x: x["severity"]):
        print(f"  [{f['severity'].upper():8}] {f['title']}")
    if args.report:
        rb.write(args.report)
        print(f"[scan] report → {args.report}")
    print(f"[audit] chain: {audit.verify()[1]}")
    orch.shutdown()
    return 0


def cmd_watch(args):
    scope, store, audit, approvals, orch = _boot(args.scope, args.data, args.rps)
    if not scope.allowed(args.target):
        print(f"[scope] {args.target} is NOT in scope — refusing.", file=sys.stderr)
        return 2
    notifier = webhook_notifier(args.webhook) if args.webhook else None
    mon = Monitor(store, audit, os.path.join(args.data, "snapshots"), notifier=notifier)
    print(f"[watch] {args.target} every {args.interval}s (Ctrl-C to stop)")
    try:
        while True:
            # fresh tasks each cycle; gated passive suite auto-approved by --authorize
            for a in list(approvals.pending()):
                approvals.deny(a["id"], note="superseded by new watch cycle")
            _submit_suite(orch, approvals, args.target, args.authorize, SCAN_SUITE)
            orch.run_until_idle()
            d = mon.diff()
            if d.get("baseline"):
                print(f"[watch] baseline: {d['surface_total']} assets")
            else:
                if d["new_assets"] or d["new_findings"]:
                    print(f"[watch] CHANGES — new assets: {len(d['new_assets'])}, "
                          f"new findings: {len(d['new_findings'])}")
                    for nf in d["new_findings"]:
                        print(f"        + [{nf['severity'].upper()}] {nf['title']} ({nf['target']})")
                else:
                    print(f"[watch] no change ({d['surface_total']} assets)")
            time.sleep(max(30, args.interval))
    except KeyboardInterrupt:
        print("\n[watch] stopped")
    finally:
        orch.shutdown()
    return 0


def cmd_serve(args):
    from .server import CommandCenter, serve
    scope, store, audit, approvals, orch = _boot(args.scope, args.data, args.rps)
    cc = CommandCenter(orch, approvals, store, scope, audit)
    serve(cc, host=args.host, port=args.port, block=True)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="redswarm", description="RedSwarm CLI")
    p.add_argument("--data", default="data", help="data directory (default: ./data)")
    p.add_argument("--rps", type=float, default=5.0, help="per-host requests/sec cap")
    sub = p.add_subparsers(dest="cmd", required=True)

    sv = sub.add_parser("serve", help="run the command center")
    sv.add_argument("--scope", required=True)
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8700)
    sv.set_defaults(fn=cmd_serve)

    sc = sub.add_parser("scan", help="run the passive suite once")
    sc.add_argument("--scope", required=True)
    sc.add_argument("--target", required=True)
    sc.add_argument("--authorize", action="store_true",
                    help="assert written authorization; approves gated passive tasks")
    sc.add_argument("--report", help="write a Markdown report to this path")
    sc.add_argument("--passive-only", action="store_true",
                    help="skip light-active checks (open_redirect)")
    sc.set_defaults(fn=cmd_scan)

    wt = sub.add_parser("watch", help="monitor a target on an interval and diff")
    wt.add_argument("--scope", required=True)
    wt.add_argument("--target", required=True)
    wt.add_argument("--authorize", action="store_true")
    wt.add_argument("--interval", type=int, default=900, help="seconds between sweeps")
    wt.add_argument("--webhook", help="POST new findings to this URL (e.g. Slack)")
    wt.set_defaults(fn=cmd_watch)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
