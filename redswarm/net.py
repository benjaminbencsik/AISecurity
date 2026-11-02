"""Shared, rules-of-engagement-aware HTTP for agents.

Every request an agent makes should go through here so that:
  * scope is re-checked at the point of the call (and on any off-host redirect),
  * a per-host rate limit is enforced (politeness / program throttle rules),
  * the response body is size-capped,
  * the method is read-only by default.

This is passive-request plumbing, not an attack client. It performs no auth and
submits no forms.
"""
from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from .scope import ScopeGuard

_UA = "RedSwarm (authorized testing)"
_MAX_BODY = 256 * 1024


class RateLimiter:
    """Token bucket per host. Blocks the calling thread until a token is free."""
    def __init__(self, rps: float = 5.0, burst: int = 5):
        self.rps = max(0.1, rps)
        self.burst = max(1, burst)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def acquire(self, host: str) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                tokens, last = self._buckets.get(host, (float(self.burst), now))
                tokens = min(self.burst, tokens + (now - last) * self.rps)
                if tokens >= 1:
                    self._buckets[host] = (tokens - 1, now)
                    return
                wait = (1 - tokens) / self.rps
                self._buckets[host] = (tokens, now)
            time.sleep(min(wait, 2.0))


class HttpResult(dict):
    """Dict with convenience accessors: status, headers (lower-cased), body, set_cookies."""
    @property
    def status(self): return self.get("status")
    @property
    def headers(self): return self.get("headers", {})
    @property
    def body(self): return self.get("body", "")
    @property
    def set_cookies(self): return self.get("set_cookies", [])


def safe_get(scope: ScopeGuard, url: str, limiter: RateLimiter | None = None,
             headers: dict | None = None, timeout: int = 10,
             max_body: int = _MAX_BODY, method: str = "GET") -> HttpResult:
    """Scope-checked, rate-limited, read-only request. Raises on scope violation;
    network errors are returned as {'error': ...} so callers can report gracefully."""
    if "://" not in url:
        url = "https://" + url
    scope.assert_in_scope(url)
    host = urlparse(url).hostname or ""
    if limiter:
        limiter.acquire(host)
    req = urllib.request.Request(url, method=method,
                                 headers={"User-Agent": _UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final = urlparse(resp.geturl()).hostname
            if final and final != host:
                scope.assert_in_scope(resp.geturl())  # don't follow a redirect out of scope
            body = resp.read(max_body).decode("utf-8", "replace")
            try:
                cookies = resp.headers.get_all("Set-Cookie") or []
            except Exception:
                cookies = []
            return HttpResult(url=url, status=resp.status,
                              headers={k.lower(): v for k, v in resp.headers.items()},
                              set_cookies=cookies, body=body)
    except (urllib.error.HTTPError) as e:
        # HTTP errors still carry headers worth auditing
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()} if e.headers else {}
        return HttpResult(url=url, status=getattr(e, "code", 0), headers=hdrs,
                          set_cookies=[], body="", error=f"HTTP {getattr(e,'code','?')}")
    except Exception as e:  # noqa: BLE001
        return HttpResult(url=url, status=0, headers={}, set_cookies=[], body="",
                          error=str(e))
