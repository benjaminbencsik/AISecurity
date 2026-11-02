"""Command-center server. Zero runtime dependencies — stdlib http.server only.

Binds to 127.0.0.1 by default (local operator console, not a public service).
State-changing endpoints are approvals, the auto-run toggle, and a manual tick;
everything else is read-only.

    GET  /                       -> dashboard
    GET  /api/state              -> full snapshot for the UI
    GET  /api/events             -> Server-Sent Events: live activity stream
    GET  /api/report             -> live Markdown report (text)
    POST /api/tick               -> advance one wave (blocking)
    POST /api/auto               -> {"on": true|false}  start/stop the swarm
    POST /api/approvals/approve  -> {"id": ..., "note": ...}
    POST /api/approvals/deny     -> {"id": ..., "note": ...}
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .orchestrator import Orchestrator
from .approvals import ApprovalQueue
from .reporting import ReportBuilder
from .store import Store
from .scope import ScopeGuard
from .audit import AuditLog

_DASH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "dashboard", "index.html")


class CommandCenter:
    def __init__(self, orch: Orchestrator, approvals: ApprovalQueue,
                 store: Store, scope: ScopeGuard, audit: AuditLog):
        self.orch = orch
        self.approvals = approvals
        self.store = store
        self.scope = scope
        self.audit = audit
        self.report = ReportBuilder(store, scope, audit)

    def state(self) -> dict:
        ok, chain = self.audit.verify()
        findings = self.store.all_findings()
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev[f.get("severity", "info")] = sev.get(f.get("severity", "info"), 0) + 1
        return {
            "engagement": self.scope.scope.name,
            "scope": self.scope.summary(),
            "auto_on": self.orch.auto_on,
            "inflight": self.orch.inflight_count(),
            "supervisor": {"name": "Root Supervisor", "role": "root"},
            "agents": [
                {"name": n, "stage": a.stage.value, "description": a.description,
                 "label": getattr(a, "role_label", n.replace("_", " ").title()),
                 "requires_approval": a.default_requires_approval}
                for n, a in self.orch.agents.items()
            ],
            "severity_counts": sev,
            "tasks": self.store.all_tasks(),
            "findings": findings,
            "approvals_pending": self.approvals.pending(),
            "surface": self.store.all_surface(),
            "activity": self.store.recent_activity(200),
            "audit_tail": self.audit.tail(40),
            "audit_integrity": {"ok": ok, "detail": chain},
        }


def make_handler(cc: CommandCenter):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RedSwarm/0.2"
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, code, body: bytes, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if not length:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except json.JSONDecodeError:
                return {}

        # -- SSE -------------------------------------------------------
        def _stream_events(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = cc.orch.subscribe()
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while True:
                    try:
                        event = q.get(timeout=15)
                        payload = "data: " + json.dumps(event) + "\n\n"
                        self.wfile.write(payload.encode("utf-8"))
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")  # hold the connection
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass  # client closed the tab
            finally:
                cc.orch.unsubscribe(q)

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/index.html"):
                try:
                    with open(_DASH, "rb") as fh:
                        self._send(200, fh.read(), "text/html; charset=utf-8")
                except FileNotFoundError:
                    self._send(404, b"dashboard/index.html not found", "text/plain")
            elif self.path == "/api/state":
                self._json(cc.state())
            elif self.path == "/api/events":
                self._stream_events()
            elif self.path == "/api/report":
                self._send(200, cc.report.build_markdown().encode("utf-8"),
                           "text/plain; charset=utf-8")
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            if self.path == "/api/tick":
                self._json(cc.orch.tick())
            elif self.path == "/api/auto":
                on = bool(self._read_json().get("on", True))
                cc.orch.start_auto() if on else cc.orch.stop_auto()
                self._json({"auto_on": cc.orch.auto_on})
            elif self.path == "/api/approvals/approve":
                b = self._read_json()
                res = cc.approvals.approve(b.get("id", ""), b.get("operator", "operator"),
                                           b.get("note", ""))
                cc.orch.pump()  # let it take effect immediately (non-blocking)
                self._json(res or {"error": "not found or already decided"},
                           200 if res else 404)
            elif self.path == "/api/approvals/deny":
                b = self._read_json()
                res = cc.approvals.deny(b.get("id", ""), b.get("operator", "operator"),
                                        b.get("note", ""))
                cc.orch.pump()
                self._json(res or {"error": "not found or already decided"},
                           200 if res else 404)
            else:
                self._json({"error": "not found"}, 404)

    return Handler


def serve(cc: CommandCenter, host: str = "127.0.0.1", port: int = 8700,
          block: bool = True) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), make_handler(cc))
    httpd.daemon_threads = True
    print(f"[RedSwarm] command center → http://{host}:{port}")
    if block:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[RedSwarm] shutting down")
            cc.orch.shutdown()
            httpd.shutdown()
    else:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd
