"""Sub-agent registry.

Each sub-agent is a small class that knows how to carry out one kind of scoped
task and hand back structured results + findings. Register yours with the
`@register` decorator and the orchestrator can delegate to it by name.

The two agents shipped here are intentionally benign — an asset cataloguer that
makes no network calls, and a read-only HTTP probe that is scope-gated AND
approval-gated. They exist to demonstrate the gates, not to attack anything.
Your own modules go beside them.
"""
from .base import BaseAgent, AgentContext, register, REGISTRY, build_agents
from . import asset_catalog     # noqa: F401  (registers on import)
from . import http_probe        # noqa: F401
from . import header_audit      # noqa: F401
from . import cors_audit        # noqa: F401
from . import tech_fingerprint  # noqa: F401
from . import subdomain_recon   # noqa: F401
from . import js_endpoints      # noqa: F401
from . import open_redirect     # noqa: F401
from . import specialists       # noqa: F401

# Passive, read-only recon + checks (no payloads, no state change).
PASSIVE_SUITE = ["subdomain_recon", "tech_fingerprint", "js_endpoints",
                 "header_audit", "cors_audit"]
# Light-active checks that send a benign probe (still read-only to the target).
ACTIVE_SUITE = ["open_redirect"]
# Default for `scan` — everything; --passive-only drops ACTIVE_SUITE.
SCAN_SUITE = PASSIVE_SUITE + ACTIVE_SUITE

# Register the specialist roster (the swarm's sub-agents) on import.
specialists.register_roster()

__all__ = ["BaseAgent", "AgentContext", "register", "REGISTRY", "build_agents",
           "specialists"]
