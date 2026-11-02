"""ScopeGuard — the hard gate. If a target is not explicitly in scope, nothing
touches it. Out-of-scope entries always win over in-scope ones.

This is deliberately conservative:
  * No DNS resolution. We match the literal host/IP you were given, so a
    wildcard in scope can't be widened by a surprise CNAME.
  * Hostnames match by exact name or shell-style wildcard (*.example.com).
  * IPs match by exact address or CIDR membership.
  * A bare scheme-less target is treated as a host.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when an action is attempted against an out-of-scope target."""


@dataclass
class Scope:
    name: str = "unnamed engagement"
    # In scope:
    domains: list[str] = field(default_factory=list)      # "*.lab.local", "app.example.com"
    cidrs: list[str] = field(default_factory=list)         # "10.0.0.0/24", "127.0.0.1/32"
    url_prefixes: list[str] = field(default_factory=list)  # "https://app.example.com/api"
    # Out of scope (always wins):
    exclude_domains: list[str] = field(default_factory=list)
    exclude_cidrs: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        known = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in known})


def _host_of(target: str) -> str:
    """Pull the host out of a URL, or return the target unchanged if it's a bare host/IP."""
    t = target.strip()
    if "://" in t:
        return (urlparse(t).hostname or "").lower()
    # could be host:port or host/path
    t = t.split("/", 1)[0]
    t = t.rsplit(":", 1)[0] if t.count(":") == 1 and not t.startswith("[") else t
    return t.lower().strip("[]")


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


class ScopeGuard:
    def __init__(self, scope: Scope):
        self.scope = scope
        self._nets = [ipaddress.ip_network(c, strict=False) for c in scope.cidrs]
        self._ex_nets = [ipaddress.ip_network(c, strict=False) for c in scope.exclude_cidrs]

    # -- public API -------------------------------------------------------
    def check(self, target: str) -> tuple[bool, str]:
        """Return (allowed, reason). Never raises."""
        if not target:
            return False, "empty target"
        host = _host_of(target)
        if not host:
            return False, f"could not parse a host from {target!r}"
        ip = _as_ip(host)

        # 1. explicit exclusions win, no matter what.
        for dom in self.scope.exclude_domains:
            if fnmatch.fnmatch(host, dom.lower()):
                return False, f"host matches excluded domain {dom!r}"
        if ip is not None:
            for net in self._ex_nets:
                if ip in net:
                    return False, f"ip {ip} is in excluded range {net}"

        # 2. url-prefix allow (most specific).
        for pref in self.scope.url_prefixes:
            if target.startswith(pref):
                return True, f"matches url prefix {pref!r}"

        # 3. host / ip allow.
        for dom in self.scope.domains:
            if fnmatch.fnmatch(host, dom.lower()):
                return True, f"matches in-scope domain {dom!r}"
        if ip is not None:
            for net in self._nets:
                if ip in net:
                    return True, f"ip {ip} is in-scope range {net}"

        return False, f"{host!r} is not in scope for '{self.scope.name}'"

    def allowed(self, target: str) -> bool:
        return self.check(target)[0]

    def assert_in_scope(self, target: str) -> None:
        ok, reason = self.check(target)
        if not ok:
            raise ScopeViolation(f"BLOCKED: {reason} (target={target!r})")

    def summary(self) -> dict:
        return {
            "name": self.scope.name,
            "domains": self.scope.domains,
            "cidrs": self.scope.cidrs,
            "url_prefixes": self.scope.url_prefixes,
            "exclude_domains": self.scope.exclude_domains,
            "exclude_cidrs": self.scope.exclude_cidrs,
        }
