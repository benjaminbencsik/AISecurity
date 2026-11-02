"""Specialist roster — the swarm's sub-agents, one per domain, grouped by PTES
stage. These are the nodes you see in the command center's swarm graph.

They are deliberately SCAFFOLDS, not attack modules. A specialist here:
  * declares its role, stage, and whether it's active (approval-gated),
  * structures any operator-supplied data in `task.params["assets"]` into the
    attack-surface map,
  * otherwise returns a "no module wired" result so you know exactly where to
    plug your own analyzer / scanner / PoC logic.

This gives the swarm a real shape to orchestrate and visualize while keeping the
shipped framework free of exploit code. Wire your modules into these, keep the
gates, and the command center shows them working.

Active-category roles (exploitation, post-exploitation, brute-force, etc.)
default to approval-gated; passive roles do not.
"""
from __future__ import annotations

from ..models import Task, PTESStage
from .base import BaseAgent, register


# (name, nice label, stage, active?) — active ⇒ default_requires_approval
_ROSTER = [
    # Intelligence gathering
    ("recon", "Reconnaissance", PTESStage.INTELLIGENCE_GATHERING, False),
    ("osint", "OSINT", PTESStage.INTELLIGENCE_GATHERING, False),
    ("attack_surface", "Attack Surface Mapping", PTESStage.INTELLIGENCE_GATHERING, False),
    ("network_infra", "Network & Infrastructure", PTESStage.INTELLIGENCE_GATHERING, False),
    # Threat modeling
    ("threat_model", "Threat Modeling", PTESStage.THREAT_MODELING, False),
    # Vulnerability analysis
    ("web_app", "Web Application", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("api_identity", "API & Identity", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("auth_session", "Auth & Session", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("business_logic", "Business Logic", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("cloud_security", "Cloud Security", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("container_security", "Container & K8s", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("cicd_security", "CI/CD Security", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("secrets_hygiene", "Secrets & Credentials", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("mobile_security", "Mobile Security", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("ai_security", "AI / LLM Security", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("source_review", "Source Code Review", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("reverse_engineering", "Reverse Engineering", PTESStage.VULNERABILITY_ANALYSIS, False),
    ("vuln_triage", "Vulnerability Triage", PTESStage.VULNERABILITY_ANALYSIS, False),
    # Exploitation (active — gated)
    ("exploitation_validation", "Exploitation Validation", PTESStage.EXPLOITATION, True),
    ("ad_security", "Active Directory", PTESStage.EXPLOITATION, True),
    ("windows_security", "Windows Security", PTESStage.EXPLOITATION, True),
    ("privilege_escalation", "Privilege Escalation", PTESStage.EXPLOITATION, True),
    # Post-exploitation (active — gated)
    ("post_exploitation", "Post-Exploitation", PTESStage.POST_EXPLOITATION, True),
    ("lateral_movement", "Lateral Movement", PTESStage.POST_EXPLOITATION, True),
    ("forensics", "Forensics", PTESStage.POST_EXPLOITATION, False),
    # Reporting
    ("bug_bounty", "Bug Bounty Hunter", PTESStage.REPORTING, False),
]


def _make(name: str, label: str, stage: PTESStage, active: bool) -> type[BaseAgent]:
    class _Specialist(BaseAgent):
        pass
    _Specialist.name = name
    _Specialist.role_label = label
    _Specialist.stage = stage
    _Specialist.description = (f"{label} specialist ({stage.value}). "
                               f"{'Active — approval-gated. ' if active else ''}"
                               f"Scaffold: wire your module here.")
    _Specialist.default_requires_approval = active

    def run(self, task: Task) -> dict:
        assets = (task.params or {}).get("assets", [])
        added = []
        for a in assets:
            target = a if isinstance(a, str) else a.get("target", "")
            if not target:
                continue
            self.ctx.scope.assert_in_scope(target)          # re-check every target
            nid = f"{name}:{target}"
            self.ctx.add_surface_node(nid, "asset", target, target,
                                      {"via": label, "stage": stage.value})
            added.append(nid)
        return {
            "role": label, "stage": stage.value,
            "module_wired": False,
            "note": f"no analyzer wired for '{label}'. Attach your module in "
                    f"redswarm/agents/specialists.py or as a dedicated agent.",
            "assets_mapped": added,
        }

    _Specialist.run = run
    _Specialist.__name__ = f"{name.title().replace('_','')}Agent"
    return _Specialist


def register_roster() -> list[str]:
    """Register every specialist. Returns the names registered."""
    names = []
    for name, label, stage, active in _ROSTER:
        register(_make(name, label, stage, active))
        names.append(name)
    return names


# Metadata the UI uses to lay out the swarm graph (name → label/stage/active).
ROSTER_META = {name: {"label": label, "stage": stage.value, "active": active}
               for name, label, stage, active in _ROSTER}
