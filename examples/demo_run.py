#!/usr/bin/env python3
"""End-to-end demo of the RedSwarm workflow against an in-scope lab target.

Run from the repo root:   python -m examples.demo_run
Then open http://127.0.0.1:8700 and click "Run swarm". Watch the PTES chain
execute live; it parks at the approval-gated probe — approve it in the UI and
the swarm continues.

Pass --no-ui to run the whole loop headless (deterministic) and print results.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redswarm.scope import Scope, ScopeGuard
from redswarm.store import Store
from redswarm.audit import AuditLog
from redswarm.approvals import ApprovalQueue
from redswarm.orchestrator import Orchestrator
from redswarm.validation import ValidationHarness
from redswarm.reporting import ReportBuilder
from redswarm.models import Task, Finding, Severity, PTESStage, FindingStatus
from redswarm.server import CommandCenter, serve

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
TARGET = "securebank.local"


def setup():
    os.makedirs(DATA, exist_ok=True)
    scope = ScopeGuard(Scope.load(os.path.join(ROOT, "scope.example.json")))
    store = Store(os.path.join(DATA, "redswarm.db"))
    audit = AuditLog(os.path.join(DATA, "audit.log"))
    approvals = ApprovalQueue(store, audit)
    orch = Orchestrator(scope, store, audit, approvals, max_workers=6)
    return scope, store, audit, approvals, orch


def build_graph(orch, store):
    """A fan-out PTES DAG across the specialist roster, with gated exploitation
    nodes at the end. This is what lights up the swarm graph."""
    def T(agent, stage, objective, target=TARGET, deps=None, params=None):
        return Task(objective=objective, stage=stage, agent=agent, target=target,
                    depends_on=deps or [], params=params or {})

    assets = {"assets": ["securebank.local", "http://127.0.0.1:8081/login",
                         "http://127.0.0.1:8081/transfer"]}
    # Intelligence gathering — parallel
    recon = T("recon", PTESStage.INTELLIGENCE_GATHERING, "map hosts & services", params=assets)
    osint = T("osint", PTESStage.INTELLIGENCE_GATHERING, "passive OSINT sweep")
    surf = T("attack_surface", PTESStage.INTELLIGENCE_GATHERING, "enumerate attack surface", params=assets)
    infra = T("network_infra", PTESStage.INTELLIGENCE_GATHERING, "infrastructure fingerprint")
    intel = [recon, osint, surf, infra]
    # Threat modeling — joins on intel
    tmodel = T("threat_model", PTESStage.THREAT_MODELING, "build threat model",
               deps=[recon.id, surf.id])
    # Vulnerability analysis — parallel, depend on threat model
    web = T("web_app", PTESStage.VULNERABILITY_ANALYSIS, "web app analysis", deps=[tmodel.id])
    api = T("api_identity", PTESStage.VULNERABILITY_ANALYSIS, "API & auth analysis", deps=[tmodel.id])
    cloud = T("cloud_security", PTESStage.VULNERABILITY_ANALYSIS, "cloud posture review", deps=[tmodel.id])
    triage = T("vuln_triage", PTESStage.VULNERABILITY_ANALYSIS, "triage candidate vulns",
               deps=[web.id, api.id])
    vuln = [web, api, cloud, triage]
    # Exploitation — ACTIVE, approval-gated
    exval = T("exploitation_validation", PTESStage.EXPLOITATION,
              "validate exploitability (gated)", deps=[triage.id])
    adsec = T("ad_security", PTESStage.EXPLOITATION, "AD attack paths (gated)", deps=[triage.id])
    # Post-exploitation — ACTIVE, gated
    post = T("post_exploitation", PTESStage.POST_EXPLOITATION,
             "assess impact of confirmed access (gated)", deps=[exval.id])
    # Reporting
    bounty = T("bug_bounty", PTESStage.REPORTING, "assemble report-ready findings", deps=[post.id])
    # An out-of-scope task that the guard rejects at intake
    oos = T("recon", PTESStage.INTELLIGENCE_GATHERING, "probe production (blocked)",
            target="prod.securebank.local")

    everything = intel + [tmodel] + vuln + [exval, adsec, post, bounty, oos]
    orch.submit_many(everything)
    return {"gated": [exval, adsec, post], "oos": oos}


def seed_findings(store, audit, scope):
    """Several findings across severities; two pre-validated as confirmed."""
    specs = [
        ("SQL injection in /api/accounts lookup", Severity.CRITICAL, "api_identity",
         "The `id` parameter concatenates into the query; a UNION payload returns other users' rows.",
         "GET /api/accounts?id=1 UNION SELECT ... → other account data in response"),
        ("Reflected XSS on /transfer memo field", Severity.HIGH, "web_app",
         "The `memo` parameter is reflected without output encoding.",
         "POST /transfer memo=<script>alert(document.domain)</script> → unescaped reflection"),
        ("IDOR on /statements/{id}", Severity.HIGH, "api_identity",
         "Statement IDs are sequential and not authorization-checked.",
         "GET /statements/1002 as user 1001 → another user's statement"),
        ("Verbose stack traces on 500", Severity.MEDIUM, "web_app",
         "Unhandled errors leak framework versions and file paths.",
         "POST /transfer amount=abc → stack trace in response body"),
        ("Missing HSTS header", Severity.LOW, "network_infra",
         "Responses omit Strict-Transport-Security.", "curl -I → no HSTS header"),
    ]
    findings = []
    for title, sev, agent, desc, repro in specs:
        f = Finding(title=title, severity=sev, target=TARGET,
                    stage=PTESStage.VULNERABILITY_ANALYSIS, agent=agent,
                    description=desc, reproduction=repro)
        store.save_finding(f)
        findings.append(f)

    # Pre-validate the top two so the UI shows confirmed results with evidence.
    open(os.path.join(ROOT, "examples", "_poc_fixture.txt"), "w").write("marker\n")
    harness = ValidationHarness(scope, store, audit, timeout=30)
    for f in findings[:2]:
        harness.validate(f, os.path.join(ROOT, "examples", "poc_example.py"))
    return findings


def main(serve_ui=True):
    scope, store, audit, approvals, orch = setup()
    print("scope check :", scope.check(TARGET))
    print("out-of-scope:", scope.check("prod.securebank.local"))

    g = build_graph(orch, store)
    seed_findings(store, audit, scope)
    print(f"submitted swarm DAG ({len(store.all_tasks())} tasks, "
          f"{len(g['gated'])} gated); "
          f"out-of-scope task → {store.get_task(g['oos'].id)['status']}")

    if serve_ui:
        cc = CommandCenter(orch, approvals, store, scope, audit)
        print("open the UI and click 'Run swarm'.")
        serve(cc, port=8700, block=True)
        return

    # headless: run until it parks on the approval, then approve and finish
    print("\nrun_until_idle (parks on approval):")
    for h in orch.run_until_idle():
        print("  ", h)
    pend = approvals.pending()
    print("pending approvals:", [a["agent"] for a in pend])
    for a in pend:
        approvals.approve(a["id"], note="authorized in RoE")
    if pend:
        print("approved all; continuing:")
        for h in orch.run_until_idle():
            print("  ", h)
    done = sum(1 for t in store.all_tasks() if t["status"] == "done")
    print(f"tasks done: {done}/{len(store.all_tasks())}")

    rb = ReportBuilder(store, scope, audit)
    rb.write(os.path.join(DATA, "report.md"), os.path.join(DATA, "report.html"))
    print("report written; audit chain:", audit.verify()[1])
    print("surface nodes:", len(store.all_surface()),
          "| findings:", len(store.all_findings()))
    orch.shutdown()


if __name__ == "__main__":
    main(serve_ui="--no-ui" not in sys.argv)
