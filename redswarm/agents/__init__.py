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
from . import wayback_urls      # noqa: F401
from . import js_endpoints      # noqa: F401
from . import mixed_content     # noqa: F401
from . import open_redirect     # noqa: F401
from . import http_methods      # noqa: F401
from . import dir_exposure      # noqa: F401
from . import graphql_introspection  # noqa: F401
from . import specialists       # noqa: F401

# Scan profiles — dial intensity to the program's rules of engagement.
#   light  : pure recon + passive read-only checks (near-zero target noise)
#   medium : light + single benign probes to the target
#   full   : medium + the more intrusive checks (path probing, introspection)
SCAN_PROFILES = {
    "light":  ["subdomain_recon", "wayback_urls", "tech_fingerprint",
               "js_endpoints", "mixed_content", "header_audit"],
    "medium": ["subdomain_recon", "wayback_urls", "tech_fingerprint",
               "js_endpoints", "mixed_content", "header_audit",
               "cors_audit", "http_methods", "open_redirect"],
    "full":   ["subdomain_recon", "wayback_urls", "tech_fingerprint",
               "js_endpoints", "mixed_content", "header_audit",
               "cors_audit", "http_methods", "open_redirect",
               "dir_exposure", "graphql_introspection"],
}

# Back-compat aliases.
PASSIVE_SUITE = SCAN_PROFILES["light"]
SCAN_SUITE = SCAN_PROFILES["full"]
RECON_AGENTS = {"subdomain_recon", "wayback_urls", "tech_fingerprint", "js_endpoints"}

# Register the specialist roster (the swarm's sub-agents) on import.
specialists.register_roster()

__all__ = ["BaseAgent", "AgentContext", "register", "REGISTRY", "build_agents",
           "specialists"]
