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
from .agents import SCAN_PROFILES, RECON_AGENTS, AGENT_DEPS


def _boot(scope_path: str, data_dir: str, rps: float):
    os.makedirs(data_dir, exist_ok=True)
    scope = ScopeGuard(Scope.load(scope_path))
    store = Store(os.path.join(data_dir, "redswarm.db"))
    audit = AuditLog(os.path.join(data_dir, "audit.log"))
    approvals = ApprovalQueue(store, audit)
    orch = Orchestrator(scope, store, audit, approvals, rps=rps)
    return scope, store, audit, approvals, orch


def _submit_suite(orch, approvals, target: str, authorize: bool, suite, profile: str = "medium"):
    """Submit a suite, wiring producer→consumer dependencies so recon that reads
    the shared attack-surface map runs after the recon that fills it."""
    from .easy import _host, _is_ip
    from .agents import DOMAIN_ONLY
    if _is_ip(_host(target)):
        suite = [a for a in suite if a not in DOMAIN_ONLY]
    in_suite = set(suite)
    task_by_agent: dict[str, str] = {}
    ids = []
    # submit in suite order (already producers-before-consumers), resolving deps
    for agent in suite:
        stage = (PTESStage.INTELLIGENCE_GATHERING if agent in RECON_AGENTS
                 else PTESStage.VULNERABILITY_ANALYSIS)
        deps = [task_by_agent[d] for d in AGENT_DEPS.get(agent, [])
                if d in in_suite and d in task_by_agent]
        t = Task(objective=f"{agent} on {target}", stage=stage, agent=agent,
                 target=target, depends_on=deps, params={"profile": profile})
        orch.submit(t)
        task_by_agent[agent] = t.id
        ids.append(t.id)
    return ids


def _drain(orch, approvals, authorize, max_rounds: int = 60):
    """Tick to completion, auto-approving gated tasks as they become ready
    (dependencies unblock consumers mid-run)."""
    for _ in range(max_rounds):
        if authorize:
            for a in approvals.pending():
                approvals.approve(a["id"], operator="cli --authorize",
                                  note="operator authorized via CLI")
        summary = orch.tick()
        if summary["dispatched"] == 0 and not (authorize and approvals.pending()):
            break


def cmd_scan(args):
    scope, store, audit, approvals, orch = _boot(args.scope, args.data, args.rps)
    if not scope.allowed(args.target):
        print(f"[scope] {args.target} is NOT in scope — refusing.", file=sys.stderr)
        return 2
    suite = SCAN_PROFILES[args.profile]
    _submit_suite(orch, approvals, args.target, args.authorize, suite, profile=args.profile)
    if not args.authorize:
        print(f"[{args.profile}] tasks submitted but gated. Re-run with --authorize to run them.")
        return 0
    _drain(orch, approvals, args.authorize)
    rb = ReportBuilder(store, scope, audit)
    confirmed = [f for f in store.all_findings() if f["status"] == "confirmed"]
    nreview = [f for f in store.all_findings() if f["status"] == "needs_review"]
    print(f"[scan:{args.profile}] {args.target}: {len(confirmed)} confirmed, "
          f"{len(nreview)} needs-review")
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
            _submit_suite(orch, approvals, args.target, args.authorize,
                          SCAN_PROFILES[args.profile], profile=args.profile)
            _drain(orch, approvals, args.authorize)
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

    sc = sub.add_parser("scan", help="run a scan profile once")
    sc.add_argument("--scope", required=True)
    sc.add_argument("--target", required=True)
    sc.add_argument("--profile", choices=["light", "medium", "full"], default="medium",
                    help="intensity: light=recon only, medium=+benign probes, full=+intrusive")
    sc.add_argument("--authorize", action="store_true",
                    help="assert written authorization; approves the gated tasks")
    sc.add_argument("--report", help="write a Markdown report to this path")
    sc.set_defaults(fn=cmd_scan)

    wt = sub.add_parser("watch", help="monitor a target on an interval and diff")
    wt.add_argument("--scope", required=True)
    wt.add_argument("--target", required=True)
    wt.add_argument("--profile", choices=["light", "medium", "full"], default="light",
                    help="intensity per sweep (default light for continuous monitoring)")
    wt.add_argument("--authorize", action="store_true")
    wt.add_argument("--interval", type=int, default=900, help="seconds between sweeps")
    wt.add_argument("--webhook", help="POST new findings to this URL (e.g. Slack)")
    wt.set_defaults(fn=cmd_watch)

    # ---- easy mode -------------------------------------------------------
    from . import easy, vps

    dr = sub.add_parser("doctor", help="check your setup")
    dr.add_argument("--scope", default="scope.json")
    dr.set_defaults(fn=easy.doctor_cmd)
    ini = sub.add_parser("init", help="interactively write scope.json")
    ini.add_argument("--scope", default="scope.json")
    ini.set_defaults(fn=lambda a: easy.init_cmd(a))

    go = sub.add_parser("go", help="one command: scope + scan + report for one target")
    go.add_argument("target", help="URL or host you are authorized to test")
    go.add_argument("--profile", choices=["light", "medium", "full"], default="light")
    go.add_argument("--wildcard", action="store_true",
                    help="also include *.host in scope (subdomains)")
    go.add_argument("--yes", action="store_true",
                    help="skip the typed authorization prompt (you accept responsibility)")
    go.add_argument("--via", metavar="USER@HOST",
                    help="run the scan on this VPS over ssh instead of locally")
    go.add_argument("--port", type=int, help="ssh port for --via")
    go.add_argument("--remote-dir", default="redswarm", help="project folder on the VPS")
    go.set_defaults(fn=easy.go_cmd)

    vp = sub.add_parser("vps", help="set up and use a VPS over ssh")
    vsub = vp.add_subparsers(dest="vps_cmd", required=True)
    vs = vsub.add_parser("setup", help="copy the project to a VPS and run its doctor")
    vs.add_argument("via", metavar="USER@HOST")
    vs.add_argument("--port", type=int)
    vs.add_argument("--remote-dir", default="redswarm")
    vs.set_defaults(fn=lambda a: vps.setup(a.via, a.port, a.remote_dir))
    vt = vsub.add_parser("tunnel", help="forward the VPS dashboard to localhost:8700")
    vt.add_argument("via", metavar="USER@HOST")
    vt.add_argument("--port", type=int)
    vt.add_argument("--local-port", type=int, default=8700)
    vt.set_defaults(fn=lambda a: vps.tunnel(a.via, a.port, a.local_port))

    args = p.parse_args(argv)
    return args.fn(args)


def entry():
    """Console-script entry point (see pyproject.toml)."""
    raise SystemExit(main())


if __name__ == "__main__":
    raise SystemExit(main())
