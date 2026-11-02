"""favicon_hash — fetch /favicon.ico and compute its Shodan-style MurmurHash3
(mmh3 of the base64-encoded body). The hash fingerprints the tech/framework and
lets you pivot to related hosts via `http.favicon.hash:<value>` on Shodan/Censys.
Read-only, one GET. Pure-Python murmur3 (zero deps).
"""
from __future__ import annotations

import base64
from urllib.parse import urljoin

from ..models import Task, Finding, Evidence, Severity, PTESStage, FindingStatus
from .base import BaseAgent, register


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded = (length // 4) * 4
    for i in range(0, rounded, 4):
        k1 = int.from_bytes(data[i:i + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = data[rounded:]
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1   # signed int32, Shodan-style


@register
class FaviconHashAgent(BaseAgent):
    name = "favicon_hash"
    role_label = "Favicon Fingerprint"
    stage = PTESStage.INTELLIGENCE_GATHERING
    description = "Computes the Shodan mmh3 favicon hash for asset correlation. Read-only. Approval-gated."
    default_requires_approval = True

    def run(self, task: Task) -> dict:
        base = task.target or (task.params or {}).get("url", "")
        if not base:
            raise ValueError("favicon_hash needs a target URL")
        if "://" not in base:
            base = "https://" + base
        url = urljoin(base, "/favicon.ico")
        r = self.ctx.get(url)
        if r.get("error") or r.status != 200 or not r.body:
            return {"url": url, "found": False}
        raw = r.body.encode("utf-8", "surrogateescape")
        b64 = base64.encodebytes(raw)                 # Shodan hashes the base64 w/ newlines
        h = _murmur3_32(b64)
        f = Finding(title=f"Favicon hash: {h}", severity=Severity.INFO, target=base,
                    stage=PTESStage.INTELLIGENCE_GATHERING, agent=self.name,
                    task_id=task.id, status=FindingStatus.CONFIRMED,
                    description="Use this to find related/forgotten assets of the same org.",
                    reproduction=f"Shodan: http.favicon.hash:{h}  ·  Censys equivalent")
        f.evidence.append(Evidence(kind="note", task_id=task.id,
                                   content=f"favicon: {url}\nmmh3: {h}"))
        self.ctx.add_finding(f)
        return {"url": url, "found": True, "favicon_hash": h}
