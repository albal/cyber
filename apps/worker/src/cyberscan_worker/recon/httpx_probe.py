"""httpx adapter — service & tech fingerprinting."""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass(slots=True)
class HttpService:
    url: str
    status: int
    title: str | None = None
    tech: list[str] = field(default_factory=list)
    webserver: str | None = None
    tls: bool = False


def run(targets: list[str], timeout_s: int = 120) -> list[HttpService]:
    """Probe a list of host:port targets with httpx."""
    if not targets:
        return []
    if not shutil.which("httpx"):
        log.warning("httpx not on PATH — returning empty result")
        return []

    cmd = [
        "httpx",
        "-silent",
        "-json",
        "-tech-detect",
        "-title",
        "-status-code",
        "-no-color",
        "-timeout", "8",
    ]
    log.info("running httpx on %d targets", len(targets))
    try:
        proc = subprocess.run(
            cmd,
            input="\n".join(targets),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning("httpx timed out")
        return []

    return parse(proc.stdout)


def parse(jsonl: str) -> list[HttpService]:
    """Parse httpx's JSONL output. Public entry point for tests."""
    out: list[HttpService] = []
    for line in jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = row.get("url") or row.get("input")
        if not url:
            continue
        out.append(
            HttpService(
                url=url,
                status=int(row.get("status_code") or row.get("status-code") or 0),
                title=row.get("title"),
                tech=list(row.get("tech") or row.get("technologies") or []),
                webserver=row.get("webserver"),
                tls=str(url).startswith("https://"),
            )
        )
    return out
