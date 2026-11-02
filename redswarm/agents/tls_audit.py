"""tls_audit — passive TLS/certificate inspection for an in-scope host.

Opens a TLS connection, reads the certificate and negotiated protocol, and
reports expiry, hostname mismatch, self-signed chains, and legacy protocol
versions. It transmits no application data — it completes the handshake and
inspects what the server presents.
"""
from __future__ import annotations

import datetime as _dt
import socket
import ssl
from urllib.parse import urlparse

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


@register
class TlsAuditAgent(BaseAgent):
    name = "tls_audit"
    role_label = "TLS / Certificate Audit"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Passive TLS check: cert expiry, hostname match, self-signed, legacy protocol. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        target = task.target or (task.params or {}).get("url", "")
        if not target:
            raise ValueError("tls_audit needs a host or URL")
        if "://" in target:
            u = urlparse(target)
            host, port = u.hostname, (u.port or 443)
        else:
            hp = target.split("/", 1)[0]
            if ":" in hp:
                host, _p = hp.rsplit(":", 1)
                port = int(_p) if _p.isdigit() else 443
            else:
                host, port = hp, 443
        self.ctx.scope.assert_in_scope(host)

        # First, a validating handshake to catch self-signed / untrusted chains.
        validated = True
        chain_err = ""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    proto = ss.version()
        except ssl.SSLCertVerificationError as e:
            validated = False
            chain_err = str(e)
            # Re-handshake without verification purely to read the presented cert.
            ctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert() or {}
                    proto = ss.version()
        except (socket.timeout, socket.gaierror, ConnectionError, OSError) as e:
            return {"host": host, "error": str(e)}

        findings = []

        def add(title, sev, desc, repro, ev):
            f = Finding(title=title, severity=sev, target=f"{host}:{port}",
                        stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                        task_id=task.id, status=FindingStatus.CONFIRMED,
                        description=desc, reproduction=repro)
            f.evidence.append(Evidence(kind="note", task_id=task.id, content=ev))
            self.ctx.add_finding(f)
            findings.append(title)

        if not validated:
            add("TLS certificate chain does not validate", Severity.MEDIUM,
                "The certificate is self-signed or issued by an untrusted CA.",
                f"openssl s_client -connect {host}:{port}", chain_err)

        if proto in _WEAK_PROTOCOLS:
            add(f"Legacy TLS protocol negotiated ({proto})", Severity.MEDIUM,
                "The server negotiated a deprecated protocol version.",
                f"openssl s_client -connect {host}:{port}", f"Negotiated: {proto}")

        not_after = cert.get("notAfter") if cert else None
        if not_after:
            try:
                exp = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - _dt.datetime.utcnow()).days
                if days < 0:
                    add("TLS certificate expired", Severity.HIGH,
                        f"Certificate expired {abs(days)} day(s) ago.",
                        f"openssl s_client -connect {host}:{port} | openssl x509 -noout -dates",
                        f"notAfter: {not_after}")
                elif days <= 21:
                    add("TLS certificate expiring soon", Severity.LOW,
                        f"Certificate expires in {days} day(s).",
                        f"openssl s_client -connect {host}:{port} | openssl x509 -noout -dates",
                        f"notAfter: {not_after}")
            except ValueError:
                pass

        self.ctx.add_surface_node(f"host:{host}", "host", host, host,
                                  {"via": self.role_label, "tls": proto})
        return {"host": host, "protocol": proto, "validated": validated,
                "not_after": not_after, "findings_added": len(findings)}
