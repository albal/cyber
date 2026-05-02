"""Target-ownership verification.

v0.1 ships HTTP file upload at /.well-known/cyberscan-<token>.txt.
DNS TXT and HTTP header methods are stubbed for v0.2.
"""
from __future__ import annotations

import secrets
import socket
from ipaddress import ip_address
from urllib.parse import urlparse

import dns.resolver
import httpx

from cyberscan_api.core.config import get_settings

WELL_KNOWN_PATH = "/.well-known/cyberscan-{token}.txt"
DNS_TXT_HOST = "_cyberscan-verify.{domain}"
HEADER_NAME = "X-Cyberscan-Verify"
HTTP_TIMEOUT = 8.0


class _PrivateAddressRefused(httpx.RequestError):
    pass


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False
    # Cloud-metadata addresses fall under is_link_local already (169.254/16,
    # fe80::/10), but block IPv6 ULA explicitly.
    return not (addr.version == 6 and addr.is_site_local)


def _resolve_public_ips(host: str) -> list[str]:
    """Return all public IPs ``host`` resolves to, raising if any are private.

    Refusing the *whole* hostname when any answer is private keeps DNS-rebinding
    style attacks honest: an attacker can't return one public + one private A
    record and gamble on which one httpx picks for the actual connect.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise _PrivateAddressRefused(f"DNS resolution failed for {host}: {exc}") from exc
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise _PrivateAddressRefused(f"DNS returned no addresses for {host}")
    for ip in ips:
        if not _is_public_ip(ip):
            raise _PrivateAddressRefused(
                f"refusing to fetch {host}: resolves to non-public address {ip}"
            )
    return ips


def _safe_get(url: str, **kwargs) -> httpx.Response:
    """`httpx.get` that refuses private/loopback/link-local destinations.

    Disabled when ``allow_private_targets`` is set in config (self-hosted
    intranet verification).
    """
    if get_settings().allow_private_targets:
        return httpx.get(url, **kwargs)
    parsed = urlparse(url)
    if parsed.hostname is None:
        raise _PrivateAddressRefused(f"URL has no hostname: {url}")
    # Pre-resolve and refuse if any answer is non-public. We then let httpx
    # do its own resolution; the small TOCTOU window is acceptable given
    # that follow_redirects is False on the verification path and the
    # response body itself is the only signal that flows back to the user.
    _resolve_public_ips(parsed.hostname)
    return httpx.get(url, **kwargs)


def new_token() -> str:
    return secrets.token_urlsafe(24)


def hostname_from_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError(f"URL has no hostname: {url}")
    return parsed.hostname


def instructions_for(method: str, hostname: str, token: str) -> str:
    if method == "http_file":
        path = WELL_KNOWN_PATH.format(token=token)
        return (
            f"Place a file at https://{hostname}{path} containing exactly: {token}\n"
            f"Then click 'Verify'."
        )
    if method == "dns_txt":
        host = DNS_TXT_HOST.format(domain=hostname)
        return f"Add a DNS TXT record at {host} with value: {token}\nThen click 'Verify'."
    if method == "http_header":
        return (
            f"Configure your web server to return the header "
            f"'{HEADER_NAME}: {token}' on https://{hostname}/\nThen click 'Verify'."
        )
    raise ValueError(f"Unknown verification method: {method}")


def verify(method: str, hostname: str, token: str) -> tuple[bool, str]:
    """Returns (verified, reason). Reason is empty on success, else explanatory."""
    try:
        if method == "http_file":
            return _verify_http_file(hostname, token)
        if method == "dns_txt":
            return _verify_dns_txt(hostname, token)
        if method == "http_header":
            return _verify_http_header(hostname, token)
    except Exception as exc:  # noqa: BLE001
        return False, f"verification error: {exc}"
    return False, f"unknown method: {method}"


def _verify_http_file(hostname: str, token: str) -> tuple[bool, str]:
    path = WELL_KNOWN_PATH.format(token=token)
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}{path}"
        try:
            r = _safe_get(url, timeout=HTTP_TIMEOUT, follow_redirects=False)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and r.text.strip() == token:
            return True, ""
    return False, f"token file not found or did not match at /.well-known/cyberscan-{token}.txt"


def _verify_dns_txt(hostname: str, token: str) -> tuple[bool, str]:
    host = DNS_TXT_HOST.format(domain=hostname)
    answers = dns.resolver.resolve(host, "TXT")
    for rdata in answers:
        for txt in rdata.strings:  # type: ignore[attr-defined]
            if txt.decode().strip() == token:
                return True, ""
    return False, f"TXT record at {host} did not contain token"


def _verify_http_header(hostname: str, token: str) -> tuple[bool, str]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            # follow_redirects=False to keep the SSRF guard meaningful — a
            # public host could otherwise 302 us at 169.254.169.254.
            r = _safe_get(url, timeout=HTTP_TIMEOUT, follow_redirects=False)
        except httpx.HTTPError:
            continue
        if r.headers.get(HEADER_NAME) == token:
            return True, ""
    return False, f"{HEADER_NAME} header missing or did not match"
