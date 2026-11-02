"""Minimal, zero-dependency DNS resolver over UDP.

Supports A, AAAA, CNAME, MX, NS, TXT. Used by the recon modules for DNS
enumeration, email-security (SPF/DMARC) and subdomain-takeover checks. These
are passive lookups against a resolver, not contact with the target.

Resolver is 1.1.1.1 by default, overridable via REDSWARM_DNS (host or host:port)
— handy for tests (point it at a local mock resolver).
"""
from __future__ import annotations

import os
import random
import socket
import struct

_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


def _encode_name(name: str) -> bytes:
    out = b""
    for part in name.rstrip(".").split("."):
        if not part:
            continue
        try:
            label = part.encode("idna")
        except Exception:
            label = part.encode("utf-8", "replace")
        out += bytes([len(label)]) + label
    return out + b"\x00"


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels, jumped, after = [], False, offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length & 0xC0 == 0xC0:                     # compression pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                after = offset + 2
            offset, jumped = ptr, True
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (after if jumped else offset)


def query(name: str, rtype: str = "A", server: str | None = None,
          timeout: float = 4.0) -> list[str]:
    """Return the record values for (name, rtype). Empty list on no-answer or error."""
    rtype = rtype.upper()
    if rtype not in _TYPES:
        raise ValueError(f"unsupported record type {rtype!r}")
    server = server or os.environ.get("REDSWARM_DNS", "1.1.1.1")
    host, port = (server.rsplit(":", 1) + ["53"])[:2] if ":" in server else (server, "53")
    port = int(port)

    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)   # RD=1
    packet = header + _encode_name(name) + struct.pack(">HH", _TYPES[rtype], 1)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (host, port))
        data, _ = s.recvfrom(8192)
    except (socket.timeout, OSError):
        return []
    finally:
        s.close()

    if len(data) < 12:
        return []
    _, _, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4

    out: list[str] = []
    for _ in range(an):
        _, off = _read_name(data, off)
        if off + 10 > len(data):
            break
        rt, _rc, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rd = data[off:off + rdlen]
        try:
            if rt == 1 and rdlen == 4:
                out.append(socket.inet_ntoa(rd))
            elif rt == 28 and rdlen == 16:
                out.append(socket.inet_ntop(socket.AF_INET6, rd))
            elif rt in (2, 5):                         # NS / CNAME
                nm, _ = _read_name(data, off)
                out.append(nm)
            elif rt == 15:                             # MX
                pref = struct.unpack(">H", rd[:2])[0]
                nm, _ = _read_name(data, off + 2)
                out.append(f"{pref} {nm}")
            elif rt == 16:                             # TXT (length-prefixed chunks)
                txt, i = "", 0
                while i < rdlen:
                    ln = rd[i]
                    txt += rd[i + 1:i + 1 + ln].decode("utf-8", "replace")
                    i += 1 + ln
                out.append(txt)
        except Exception:
            pass
        off += rdlen
    return out
