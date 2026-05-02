"""Caller-IP resolution that respects ``trusted_proxies``.

X-Forwarded-For is trivially spoofable when accepted unconditionally — a
single attacker can rotate IPs in the header to dodge any per-IP rate
limit. This module returns the immediate peer IP unless that peer is in
the configured trusted-proxies list, in which case the left-most XFF
entry is returned (after walking through any further trusted hops).
"""
from __future__ import annotations

from collections.abc import Iterable
from ipaddress import ip_address, ip_network

from fastapi import Request

from cyberscan_api.core.config import get_settings


def _parse_trusted(raw: str) -> list:
    nets: list = []
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            nets.append(ip_network(chunk, strict=False))
        except ValueError:
            continue
    return nets


def _is_trusted(ip: str, networks: Iterable) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def client_ip(request: Request) -> str:
    """Return the best-effort caller IP for ``request``.

    XFF is honored only if every hop between the peer and the claimed
    origin sits inside ``trusted_proxies``. Otherwise the immediate peer
    IP is returned.
    """
    peer = request.client.host if request.client else "unknown"
    trusted = _parse_trusted(get_settings().trusted_proxies)
    if not trusted:
        return peer

    if not _is_trusted(peer, trusted):
        return peer

    xff = request.headers.get("x-forwarded-for")
    if not xff:
        return peer

    # Walk the chain right-to-left, stripping trusted hops; the first
    # untrusted entry is the real client.
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    while hops:
        candidate = hops.pop()
        if not _is_trusted(candidate, trusted):
            return candidate
    # Every hop was trusted — fall back to the original left-most entry.
    return xff.split(",")[0].strip()
