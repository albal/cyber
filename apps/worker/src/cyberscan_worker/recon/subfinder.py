"""Subfinder adapter — passive subdomain enumeration.

ProjectDiscovery's `subfinder` uses public sources (cert-stream, crt.sh,
DNS providers, etc.) to find subdomains for a given root. We use it
opt-in per asset: scanning everyone's subdomains by default would explode
the surface and the legal posture.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess

log = logging.getLogger(__name__)


def run(domain: str, *, timeout_s: int = 60, max_results: int = 200) -> list[str]:
    """Return a deduplicated list of subdomains discovered for `domain`.

    Always includes the original domain as the first entry so callers can
    use the result as a single seed list."""
    if not domain:
        return []
    if not shutil.which("subfinder"):
        log.info("subfinder not on PATH — skipping enumeration, returning input domain only")
        return [domain]

    cmd = [
        "subfinder",
        "-silent",
        "-d", domain,
        "-json",
        "-timeout", "10",
        "-max-time", "1",  # max minutes
        "-no-color",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except subprocess.TimeoutExpired:
        log.warning("subfinder timed out for %s", domain)
        return [domain]

    found = parse(proc.stdout)
    if domain not in found:
        found.insert(0, domain)
    if max_results and len(found) > max_results:
        found = found[:max_results]
    return found


def parse(jsonl: str) -> list[str]:
    """Parse subfinder's JSONL output (`-json` flag). Public for testing."""
    seen: set[str] = set()
    out: list[str] = []
    for line in jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            # subfinder also has a -oJ alternate that emits raw lines; tolerate.
            host = line
            row = None  # noqa: F841
        else:
            host = row.get("host") or row.get("subdomain") or ""
        host = host.strip().lower()
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out
