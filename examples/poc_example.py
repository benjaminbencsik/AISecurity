#!/usr/bin/env python3
"""Example PoC for the validation harness.

This is the kind of script YOU write to prove a finding. The harness runs it
with `python -I <this> <target>` and reads the verdict line. Replace the body
with the actual reproduction (a scoped request, a Burp-replayed call, etc.).

Contract: print exactly one of:
    REDSWARM_RESULT: CONFIRMED
    REDSWARM_RESULT: FALSE_POSITIVE
    REDSWARM_RESULT: NEEDS_REVIEW

This stub demonstrates the mechanism without touching any network: it checks a
local fixture file to decide, so the demo is fully offline and deterministic.
"""
import os
import sys

target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("REDSWARM_TARGET", "")
print(f"[poc] target = {target}")
print(f"[poc] finding = {os.environ.get('REDSWARM_FINDING','?')}")

# --- your reproduction logic goes here ---
# Demo heuristic: a fixture beside this file stands in for "the bug reproduced".
fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_poc_fixture.txt")
reproduced = os.path.isfile(fixture) and target

print(f"[poc] evidence fixture present: {os.path.isfile(fixture)}")

if reproduced:
    print("[poc] server reflected the injected marker unescaped in the response body")
    print("REDSWARM_RESULT: CONFIRMED")
else:
    print("[poc] could not reproduce")
    print("REDSWARM_RESULT: FALSE_POSITIVE")
