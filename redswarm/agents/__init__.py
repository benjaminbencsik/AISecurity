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
from . import dns_enum          # noqa: F401
from . import email_security    # noqa: F401
from . import favicon_hash      # noqa: F401
from . import js_endpoints      # noqa: F401
from . import param_discovery   # noqa: F401
from . import host_liveness     # noqa: F401
from . import subdomain_takeover  # noqa: F401
from . import mixed_content     # noqa: F401
from . import open_redirect     # noqa: F401
from . import http_methods      # noqa: F401
from . import dir_exposure      # noqa: F401
from . import graphql_introspection  # noqa: F401
from . import csp_analyzer      # noqa: F401
from . import jwt_analyzer      # noqa: F401
from . import sourcemap_exposure  # noqa: F401
from . import api_docs_exposure   # noqa: F401
from . import wildcard_dns      # noqa: F401
from . import nuclei_scan       # noqa: F401
from . import wayback_scan      # noqa: F401
from . import specialists       # noqa: F401

# Full recon methodology → vuln checks, grouped by intensity.
#   light  : passive recon + read-only checks (OSINT, DNS, passive parse)
#   medium : light + probing of discovered hosts and single benign probes
#   full   : medium + the more intrusive checks (path probing, introspection)
_RECON_LIGHT = ["subdomain_recon", "wayback_urls", "dns_enum", "email_security",
                "wildcard_dns", "tech_fingerprint", "favicon_hash", "js_endpoints",
                "param_discovery", "mixed_content", "header_audit", "csp_analyzer",
                "jwt_analyzer", "sourcemap_exposure"]
_PROBE_MEDIUM = ["host_liveness", "subdomain_takeover", "cors_audit",
                 "http_methods", "open_redirect", "nuclei_scan"]
_INTRUSIVE_FULL = ["dir_exposure", "graphql_introspection", "api_docs_exposure",
                   "wayback_scan"]
SCAN_PROFILES = {
    "light":  list(_RECON_LIGHT),
    "medium": _RECON_LIGHT + _PROBE_MEDIUM,
    "full":   _RECON_LIGHT + _PROBE_MEDIUM + _INTRUSIVE_FULL,
}

# Producer → consumer ordering within a scan: a consumer runs only after the
# producers that fill the attack-surface map it reads from.
AGENT_DEPS = {
    "dns_enum":           ["subdomain_recon"],
    "email_security":     [],
    "host_liveness":      ["subdomain_recon", "dns_enum"],
    "subdomain_takeover": ["subdomain_recon", "dns_enum"],
    "param_discovery":    ["wayback_urls", "js_endpoints"],
    "open_redirect":      ["param_discovery"],
    "sourcemap_exposure": ["js_endpoints"],
    "api_docs_exposure":  ["js_endpoints"],
    "wayback_scan":       ["wayback_urls", "param_discovery"],
}

# Agents that need a domain name. They are skipped when the target is a bare IP,
# so a scan of 1.2.3.4 doesn't query certificate logs or DNS for "1.2.3.4".
DOMAIN_ONLY = {"subdomain_recon", "wayback_urls", "dns_enum", "email_security",
               "wildcard_dns", "subdomain_takeover"}

# Agents whose natural target is a domain/host rather than a single URL.
RECON_AGENTS = {"subdomain_recon", "wayback_urls", "dns_enum", "email_security",
                "wildcard_dns", "tech_fingerprint", "favicon_hash", "js_endpoints",
                "param_discovery", "host_liveness", "subdomain_takeover"}

# Back-compat aliases.
PASSIVE_SUITE = SCAN_PROFILES["light"]
SCAN_SUITE = SCAN_PROFILES["full"]

# Register the specialist roster (the swarm's sub-agents) on import.
specialists.register_roster()

__all__ = ["BaseAgent", "AgentContext", "register", "REGISTRY", "build_agents",
           "specialists"]
