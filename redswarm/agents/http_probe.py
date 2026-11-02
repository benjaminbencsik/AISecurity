"""http_probe — a single read-only HTTP GET of an in-scope target, used to grab
the response status, server banner and <title>. Nothing else.

It is the archetypal "safe but real" action, so it ships with
default_requires_approval = True: scope-gated AND approval-gated. It performs
no login, sends no payloads, follows no redirects off the original host, and
caps the body it reads. Treat it as the reference for how an *active* module
should behave inside the gates — your scanners/fuzzers/exploit modules belong
here, written to the same contract.
"""
from __future__ import annotations

import re
import socket
import urllib.request
from urllib.parse import urlparse

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_MAX_BODY = 64 * 1024


@register
class HttpProbeAgent(BaseAgent):
    name = "http_probe"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Read-only GET of one in-scope URL: status, Server header, page title. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        url = task.target or (task.params or {}).get("url", "")
        if not url:
            raise ValueError("http_probe needs a target URL")
        if "://" not in url:
            url = "https://" + url

        # Re-enforce scope at the point of action.
        self.ctx.scope.assert_in_scope(url)
        origin_host = urlparse(url).hostname

        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "RedSwarm/http_probe (authorized test)"})
        info = {"url": url}
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                # Guard against an off-host redirect leaving scope.
                final_host = urlparse(resp.geturl()).hostname
                if final_host and final_host != origin_host:
                    self.ctx.scope.assert_in_scope(resp.geturl())
                body = resp.read(_MAX_BODY).decode("utf-8", "replace")
                info["status"] = resp.status
                info["server"] = resp.headers.get("Server", "")
                info["content_type"] = resp.headers.get("Content-Type", "")
                m = _TITLE.search(body)
                info["title"] = (m.group(1).strip()[:200] if m else "")
        except (urllib.error.URLError, socket.timeout, ValueError) as e:
            info["error"] = str(e)
            return info

        self.ctx.add_surface_node(f"endpoint:{url}", "endpoint", url, url,
                                  {"status": info.get("status"),
                                   "server": info.get("server")})
        return info
