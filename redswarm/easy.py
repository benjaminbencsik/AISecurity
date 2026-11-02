"""Easy mode: check your setup, define scope, and run one scan with one command.

    python -m redswarm doctor                 # is everything installed?
    python -m redswarm init                   # interactive: write scope.json
    python -m redswarm go https://target/     # scope + scan + report, one command

`go` only scans what you name, asks you to confirm authorization (unless --yes),
records the scope it used in data/, and writes a report under reports/.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import shutil
import sys
from urllib.parse import urlparse

AUTH_PHRASE = "I have written authorization"
_PROFILES = ["light", "medium", "full"]


def _host(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    return (urlparse(t).hostname or "").lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- doctor
def doctor_cmd(args) -> int:
    print("RedSwarm doctor\n")
    required_ok = True

    py = sys.version_info
    good = py >= (3, 10)
    required_ok &= good
    print(f"  {'OK  ' if good else 'FAIL'} python {py.major}.{py.minor} (need 3.10+)")

    try:
        import sqlite3  # noqa: F401
        print("  OK   sqlite3 available")
    except ImportError:
        required_ok = False
        print("  FAIL sqlite3 missing (rebuild Python with sqlite support)")

    data = os.path.abspath(args.data)
    try:
        os.makedirs(data, exist_ok=True)
        probe = os.path.join(data, ".write-test")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
        print(f"  OK   data directory writable: {data}")
    except OSError as e:
        required_ok = False
        print(f"  FAIL data directory not writable ({data}): {e}")

    nuc = os.environ.get("REDSWARM_NUCLEI") or shutil.which("nuclei")
    if nuc:
        print(f"  OK   nuclei found: {nuc}")
    else:
        print("  WARN nuclei not installed (nuclei_scan will fail until it is)")
        print("       install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    tdir = os.environ.get("REDSWARM_NUCLEI_TEMPLATES") or os.path.expanduser("~/nuclei-templates")
    if nuc and os.path.isdir(tdir):
        print(f"  OK   nuclei templates: {tdir}")
    elif nuc:
        print("  WARN nuclei templates not found: run `nuclei -ut`")

    if shutil.which("go"):
        print("  OK   go available (can install nuclei)")
    else:
        print("  INFO go not installed (only needed to install nuclei)")

    if os.path.exists(args.scope):
        print(f"  OK   scope file: {args.scope}")
    else:
        print(f"  INFO no {args.scope} yet: run `python -m redswarm init` or `go <target>`")

    print("\n" + ("Required checks passed." if required_ok else "Fix the FAIL lines above."))
    return 0 if required_ok else 1


# ---------------------------------------------------------------- scope writing
def _write_scope(path: str, name: str, domains: list[str], cidrs: list[str]) -> None:
    doc = {"name": name, "domains": domains, "cidrs": cidrs,
           "url_prefixes": [], "exclude_domains": [], "exclude_cidrs": []}
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


def _valid_cidrs(raw: str) -> list[str]:
    out = []
    for part in [p.strip() for p in raw.split(",") if p.strip()]:
        ipaddress.ip_network(part, strict=False)   # raises ValueError if invalid
        out.append(part)
    return out


# ---------------------------------------------------------------- init
def init_cmd(args, input_fn=input, out=print) -> int:
    out("Create scope.json (the rules of engagement the scanner will enforce).\n")
    name = input_fn("Engagement name [My engagement]: ").strip() or "My engagement"
    domains = [d.strip().lower().lstrip("*.") for d in
               input_fn("Domains/hosts in scope, comma-separated (e.g. app.example.com): ").split(",")
               if d.strip()]
    try:
        cidrs = _valid_cidrs(input_fn("IP ranges in scope, CIDR, comma-separated (optional): "))
    except ValueError as e:
        out(f"Invalid IP range: {e}")
        return 2
    if not domains and not cidrs:
        out("Nothing in scope. Add at least one domain or IP range.")
        return 2

    out("\nScope to be written:")
    out(f"  name:    {name}")
    out(f"  domains: {', '.join(domains) or '-'}")
    out(f"  ranges:  {', '.join(cidrs) or '-'}")
    try:
        ans = input_fn(f'\nType exactly "{AUTH_PHRASE}" to confirm you may test these: ').strip()
    except EOFError:
        ans = ""
    if ans != AUTH_PHRASE:
        out("Not confirmed. scope.json was not written.")
        return 2

    _write_scope(args.scope, name, domains, cidrs)
    out(f"\nWrote {args.scope}. Next: python -m redswarm scan --scope {args.scope} "
        f"--target https://{domains[0] if domains else cidrs[0]}/ --authorize")
    return 0


# ---------------------------------------------------------------- go
def go_cmd(args) -> int:
    from .__main__ import cmd_scan   # late import: avoid a cycle

    host = _host(args.target)
    if not host:
        print(f"Could not read a host from {args.target!r}")
        return 2
    ip = _is_ip(host)
    domains = [] if ip else [host] + ([f"*.{host}"] if args.wildcard else [])
    cidrs = [f"{host}/32"] if ip else []

    if not args.yes:
        print(f"About to scan {args.target}")
        print(f"  scope: {host}" + (" and its subdomains" if args.wildcard else " only"))
        print(f"  profile: {args.profile}  (light = recon + passive; medium/full send more requests)")
        try:
            ans = input(f'Type exactly "{AUTH_PHRASE}" to confirm you may test this: ').strip()
        except EOFError:
            ans = ""
        if ans != AUTH_PHRASE:
            print("Not confirmed. Nothing was scanned.")
            return 2

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    scope_path = os.path.join(args.data, f"scope-{host}.json")
    _write_scope(scope_path, f"{host} (authorized)", domains, cidrs)
    report = os.path.join("reports", f"{host}-{stamp}.md")
    os.makedirs("reports", exist_ok=True)

    via = getattr(args, "via", None)
    if via:
        from .vps import run_remote_scan
        with open(scope_path, encoding="utf-8") as fh:
            scope_text = fh.read()
        code = run_remote_scan(
            via, getattr(args, "port", None), getattr(args, "remote_dir", "redswarm"),
            scope_text, scope_rel=f"data/scope-{host}.json", target=args.target,
            profile=args.profile, rps=args.rps,
            report_rel=f"reports/{host}-{stamp}.md", local_report=report)
        print("Review each needs-review finding by hand before you report it.")
        return code

    if args.profile != "light" and not (os.environ.get("REDSWARM_NUCLEI") or shutil.which("nuclei")):
        print("Note: nuclei is not installed, so nuclei checks will report a failure. "
              "Run `python -m redswarm doctor` for install steps.")

    scan_args = argparse.Namespace(scope=scope_path, target=args.target, profile=args.profile,
                                   authorize=True, report=report, data=args.data, rps=args.rps)
    code = cmd_scan(scan_args)
    print(f"\nReport: {report}")
    print("Review each needs-review finding by hand before you report it.")
    return code
