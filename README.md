# RedSwarm

A human-in-the-loop orchestration framework for **authorized** penetration
testing and bug-bounty work. One root coordinator delegates scoped tasks to a
swarm of specialist sub-agents across the seven PTES stages, and a live command
center gives you a swarm-graph view, approval control, finding validation, and
client-ready reports.

It's the control room and the workbench — not a push-button attack tool. The
shipped code contains **no exploit logic**. The specialist roster ships as
scaffolds; you plug in your own modules and your own PoCs, and the framework's
job is to keep them inside the rules of engagement and make every result
traceable.

## Command center

A single-file, zero-dependency console (`dashboard/index.html`) served by the
stdlib HTTP server:

* **Agent Swarm** — a node graph of the root supervisor and every specialist,
  colored by live status, with an event-replay scrubber over the persisted
  activity stream.
* **Run swarm / Tick once** — auto-run cascades the task DAG and *parks* the
  moment it hits an approval gate; or step one wave at a time.
* **Live** — a Server-Sent Events stream pushes every state change; the UI
  updates in real time (with a polling fallback).
* Views for the **PTES board**, **vulnerabilities**, **attack surface**,
  **evidence & activity**, **approvals**, and the **skills & agents** roster.

## The three gates

Every action an agent takes passes through:

1. **ScopeGuard** — the target must be explicitly in scope. Exclusions always
   win; no DNS resolution (so a wildcard can't be widened by a surprise CNAME).
   Enforced at task intake *and* again immediately before dispatch *and* inside
   agents for any target they derive mid-task.
2. **ApprovalQueue** — any task flagged active parks until an operator clicks
   Approve/Deny in the command center. Nothing active runs unattended.
3. **AuditLog** — an append-only, SHA-256 hash-chained log. Edit or delete a
   record and `verify()` tells you exactly where the chain breaks. This is what
   makes a finding traceable to the agent, task, and moment behind it.

## Validation, not vibes

The `ValidationHarness` runs *your* PoC (a Python script) against an in-scope
target in an isolated subprocess (`python -I`, hard timeout, scope re-checked at
launch) and marks the finding **CONFIRMED / FALSE_POSITIVE / NEEDS_REVIEW** from
the PoC's own verdict line. The framework never writes exploits for you — it runs
the ones you wrote and records the outcome as evidence. No finding ships
unproven.

## Quick start

```bash
cd redswarm
python -m examples.demo_run          # seeds a swarm engagement, then serves the UI
# open http://127.0.0.1:8700  → click "Run swarm"
# watch the PTES DAG cascade; it parks at the gated exploitation nodes —
# approve them in the UI (or the Approvals view) and it continues.
```

Zero runtime dependencies — Python 3.10+ stdlib only.
Run the whole thing headless with `python -m examples.demo_run --no-ui`.

## Running it against a real target (CLI)

```bash
# the command center
python -m redswarm serve --scope scope.json

# a scan at a chosen intensity (light | medium | full)
python -m redswarm scan  --scope scope.json --target https://app.example.com/ \
    --profile medium --authorize --report out.md

# continuous monitoring: re-sweep on an interval, diff, alert on new surface
python -m redswarm watch --scope scope.json --target https://app.example.com/ \
    --profile light --authorize --interval 900 --webhook https://hooks.slack.com/...
```

`--authorize` is you asserting written authorization for every in-scope target;
it's the CLI equivalent of approving the gated passive tasks. Out-of-scope
targets are refused. A global **kill-switch** (STOP in the UI, `stop_all()` in
code) halts the swarm instantly, and every request is **rate-limited per host**
(`--rps`, default 5/s) to respect program throttle rules.

### The passive suite (real, working modules)

### Scan profiles

`scan`/`watch` take `--profile` to dial intensity to the program's rules:

| profile | what runs | target contact |
|---|---|---|
| **light** | recon + passive read-only checks | GETs only; OSINT where possible |
| **medium** (scan default) | light + single benign probes | one crafted request per check |
| **full** | medium + intrusive checks | path probing, introspection POST |

`watch` defaults to **light** (quiet continuous monitoring). Every module is
scope- and approval-gated and rate-limited regardless of profile.

### Recon methodology → checks

A full recon pipeline feeds the checks. Producers fill the shared attack-surface
map; consumers read from it, and the orchestrator runs them in dependency order
(`dns_enum` after `subdomain_recon`, `host_liveness`/`subdomain_takeover` after
`dns_enum`, `open_redirect` after `param_discovery`, …).

| module | profile | stage | checks |
|---|---|---|---|
| `subdomain_recon` | light | recon | subdomain discovery via Certificate Transparency (crt.sh); OSINT |
| `wayback_urls` | light | recon | historical URLs from the Wayback Machine; OSINT |
| `dns_enum` | light | recon | A/AAAA/CNAME/MX/NS/TXT for domain + discovered subdomains |
| `email_security` | light | recon | SPF/DMARC/DKIM posture → spoofing exposure |
| `tech_fingerprint` | light | recon | stack headers + robots.txt / sitemap.xml paths |
| `favicon_hash` | light | recon | Shodan mmh3 favicon hash for asset correlation |
| `js_endpoints` | light | recon | endpoints/API routes + possible leaked secrets from JS |
| `param_discovery` | light | recon | parameter inventory from collected URLs (feeds redirect/IDOR) |
| `mixed_content` | light | check | http:// subresources on an HTTPS page |
| `header_audit` | light | check | missing/weak HTTP security headers |
| `host_liveness` | medium | recon | probe discovered subdomains for live HTTP(S) (httpx-style) |
| `subdomain_takeover` | medium | check | dangling CNAMEs to unclaimed services (provider fingerprints) |
| `cors_audit` | medium | check | reflected / over-permissive Access-Control-Allow-Origin |
| `http_methods` | medium | check | OPTIONS Allow header → risky verbs (PUT/DELETE/TRACE) |
| `open_redirect` | medium | check | one off-domain probe per redirect param; confirms on an actual external 3xx |
| `wildcard_dns` | light | recon | detects wildcard DNS so subdomain results can be discounted |
| `csp_analyzer` | light | check | weak CSP directives: unsafe-inline / unsafe-eval / wildcard script sources |
| `jwt_analyzer` | light | check | decodes JWTs the app returns: alg=none, missing/long expiry, sensitive claims (token redacted) |
| `sourcemap_exposure` | light | check | publicly downloadable JS source maps that leak original source |
| `dir_exposure` | full | check | curated sensitive paths (.git/.env/backups) with a negative-control baseline |
| `graphql_introspection` | full | check | read-only introspection query to common GraphQL paths |
| `api_docs_exposure` | full | check | public Swagger/OpenAPI specs and GraphQL IDEs, signature + catch-all checked |

JWT analysis is decode-only: it never verifies, forges, or replays a token, and
it redacts tokens in evidence so reports don't carry live credentials.

Zero-dependency DNS is built in (`redswarm/dns.py`, UDP resolver; set
`REDSWARM_DNS` to override). Noisy classes (`js_endpoints` secrets,
`http_methods`) are emitted **needs-review**, not confirmed — you verify.
Discovery modules only map in-scope hosts, feeding the monitor diff so new
surface alerts the moment it appears.

### Monitoring

`watch` snapshots the attack surface each cycle and diffs it against the last
run, so **new assets and new confirmed findings surface the moment they appear**
— optionally POSTed to a Slack/Discord webhook. This is the continuous-recon
loop, kept scope-bound and rate-limited.

## Layout

```
redswarm/
  scope.py          ScopeGuard + Scope (JSON rules of engagement)
  audit.py          hash-chained AuditLog
  approvals.py      ApprovalQueue (operator decisions)
  store.py          SQLite persistence
  models.py         Task / Finding / Evidence / PTES stages / enums
  orchestrator.py   root coordinator: task DAG, deps, bounded swarm, PTES planner
  validation.py     PoC runner → confirmed / false-positive / needs-review
  reporting.py      findings → Markdown + HTML, with traceability
  server.py         stdlib HTTP API serving the command center
  agents/
    base.py         BaseAgent + registry + injected context
    asset_catalog.py  benign default agent (no network I/O)
    http_probe.py     read-only GET, scope- AND approval-gated (reference module)
    specialists.py    the swarm roster (17 PTES specialist scaffolds)
dashboard/index.html  single-file command center UI (swarm graph + views)
examples/
  demo_run.py       end-to-end walkthrough
  poc_example.py    PoC contract example for the validation harness
scope.example.json  rules-of-engagement template
```

## Writing a sub-agent

```python
from redswarm.agents.base import BaseAgent, register
from redswarm.models import Task, Finding, Severity, PTESStage, FindingStatus

@register
class MyAgent(BaseAgent):
    name = "my_agent"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "what it does"
    default_requires_approval = True      # True for anything active

    def run(self, task: Task) -> dict:
        self.ctx.scope.assert_in_scope(task.target)   # re-check every target
        # ... your scoped logic ...
        self.ctx.add_finding(Finding(
            title="...", severity=Severity.HIGH, target=task.target,
            agent=self.name, task_id=task.id,
            status=FindingStatus.UNVALIDATED,         # let the harness confirm it
            reproduction="curl / Burp steps",
        ))
        return {"ok": True}
```

Scope enforcement, approval gating, audit logging, and the activity feed are
handled for you by the orchestrator — write the logic, the gates come free.

Set your real engagement in `scope.json` and point the harness at your PoCs.
This framework assumes you have **written authorization** for every target you
put in scope.
