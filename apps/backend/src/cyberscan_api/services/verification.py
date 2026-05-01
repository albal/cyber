"""Target-ownership verification.

v0.1 ships HTTP file upload at /.well-known/cyberscan-<token>.txt.
DNS TXT and HTTP header methods are stubbed for v0.2.
"""
from __future__ import annotations

import secrets
from urllib.parse import urlparse

import dns.resolver
import httpx

WELL_KNOWN_PATH = "/.well-known/cyberscan-{token}.txt"
DNS_TXT_HOST = "_cyberscan-verify.{domain}"
HEADER_NAME = "X-Cyberscan-Verify"
HTTP_TIMEOUT = 8.0


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
            r = httpx.get(url, timeout=HTTP_TIMEOUT, follow_redirects=False)
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
            r = httpx.get(url, timeout=HTTP_TIMEOUT, follow_redirects=True)
        except httpx.HTTPError:
            continue
        if r.headers.get(HEADER_NAME) == token:
            return True, ""
    return False, f"{HEADER_NAME} header missing or did not match"
