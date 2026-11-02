"""jwt_analyzer — decode JWTs that the app already returned (response body or
Set-Cookie) and flag weak token hygiene. Decode-only: it never verifies,
forges, or replays a token. Tokens are REDACTED in evidence so the report
doesn't carry live credentials.

Flags:
  alg=none                 -> HIGH (needs-review: confirm the server accepts it)
  no exp claim             -> LOW  (confirmed: token never expires)
  lifetime over 30 days    -> LOW  (confirmed)
  sensitive claim names    -> MEDIUM (confirmed: secrets inside a client-readable token)
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import re

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_SENSITIVE = {"password", "passwd", "secret", "ssn", "credit_card", "card_number", "private_key"}
_MAX_TOKENS = 20


def _b64(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _redact(tok: str) -> str:
    return tok[:14] + "…[redacted]"


@register
class JwtAnalyzerAgent(BaseAgent):
    name = "jwt_analyzer"
    role_label = "JWT Analysis"
    stage = PTESStage.VULNERABILITY_ANALYSIS
    description = "Decodes JWTs the app returns; flags alg=none, missing/long expiry, sensitive claims. Decode-only, redacted. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        url = task.target or (task.params or {}).get("url", "")
        if not url:
            raise ValueError("jwt_analyzer needs a target URL")
        r = self.ctx.get(url)
        if r.get("error"):
            return {"url": url, "error": r["error"]}

        found = set()
        for blob in [r.body or ""] + list(r.set_cookies or []):
            found.update(_JWT.findall(blob))
        decoded = 0
        for tok in list(found)[:_MAX_TOKENS]:
            parts = tok.split(".")
            try:
                header = json.loads(_b64(parts[0]))
                payload = json.loads(_b64(parts[1]))
            except (ValueError, json.JSONDecodeError):
                continue
            decoded += 1
            where = r.get("url", url)
            shown = _redact(tok)

            def add(title, sev, status, desc):
                f = Finding(title=title, severity=sev, target=where,
                            stage=PTESStage.VULNERABILITY_ANALYSIS, agent=self.name,
                            task_id=task.id, status=status, description=desc,
                            reproduction=f"inspect the token served at {where} (decode header/payload only)")
                f.evidence.append(Evidence(kind="note", task_id=task.id,
                    content=f"token: {shown}\nheader: {json.dumps(header)}\n"
                            f"payload claim names: {sorted(payload)}"))
                self.ctx.add_finding(f)

            if str(header.get("alg", "")).lower() == "none":
                add("JWT served with alg=none", Severity.HIGH, FindingStatus.NEEDS_REVIEW,
                    "The app issues an unsigned token. Verify whether the server accepts it "
                    "(this is the signature-bypass class).")
            if "exp" not in payload:
                add("JWT without expiry (exp)", Severity.LOW, FindingStatus.CONFIRMED,
                    "The token never expires; a leaked token stays valid indefinitely.")
            elif "iat" in payload and isinstance(payload["exp"], (int, float)) \
                    and isinstance(payload["iat"], (int, float)) \
                    and payload["exp"] - payload["iat"] > 30 * 86400:
                add("Long-lived JWT (over 30 days)", Severity.LOW, FindingStatus.CONFIRMED,
                    "Token lifetime exceeds 30 days, widening the window for a stolen token.")
            sens = sorted(k for k in payload if k.lower() in _SENSITIVE)
            if sens:
                add("Sensitive claim inside client-readable JWT", Severity.MEDIUM,
                    FindingStatus.CONFIRMED,
                    f"Claims {', '.join(sens)} are readable by anyone holding the token (JWT payloads are not encrypted).")

        return {"url": r.get("url", url), "tokens_found": len(found), "decoded": decoded}
