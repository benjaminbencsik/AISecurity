"""asset_catalog — turns operator-supplied facts about an in-scope target into
attack-surface nodes. Makes ZERO network calls. This is the safe default agent
and a template for your own passive modules.

Task params it understands:
    {
      "hosts":     ["app.lab.local", ...],
      "endpoints": ["https://app.lab.local/api/login", ...],
      "tech":      ["nginx", "php 8.1", ...],
      "notes":     "free text"
    }
"""
from __future__ import annotations

from ..models import Task, PTESStage
from .base import BaseAgent, register


@register
class AssetCatalogAgent(BaseAgent):
    name = "asset_catalog"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Structures operator-provided target facts into the attack-surface map (no network I/O)."
    default_requires_approval = False

    def run(self, task: Task) -> dict:
        p = task.params or {}
        added = []

        for host in p.get("hosts", []):
            # re-check every target, even operator-supplied ones
            self.ctx.scope.assert_in_scope(host)
            nid = f"host:{host}"
            self.ctx.add_surface_node(nid, "host", host, host,
                                      {"tech": p.get("tech", [])})
            added.append(nid)

        for ep in p.get("endpoints", []):
            self.ctx.scope.assert_in_scope(ep)
            nid = f"endpoint:{ep}"
            self.ctx.add_surface_node(nid, "endpoint", ep, ep, {})
            added.append(nid)

        if task.target and not (p.get("hosts") or p.get("endpoints")):
            self.ctx.scope.assert_in_scope(task.target)
            nid = f"host:{task.target}"
            self.ctx.add_surface_node(nid, "host", task.target, task.target, {})
            added.append(nid)

        return {
            "nodes_added": added,
            "tech": p.get("tech", []),
            "notes": p.get("notes", ""),
        }
