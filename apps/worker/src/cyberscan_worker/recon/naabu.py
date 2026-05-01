"""Naabu adapter — fast TCP port discovery."""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass

from cyberscan_worker.config import get_settings

log = logging.getLogger(__name__)


@dataclass(slots=True)
class OpenPort:
    host: str
    port: int


def run(host: str, top_ports: str = "1000", timeout_s: int = 120) -> list[OpenPort]:
    """Run naabu against a single host. Returns list of open ports."""
    s = get_settings()
    if not shutil.which("naabu"):
        log.warning("naabu not on PATH — returning empty result")
        return []

    cmd = [
        "naabu",
        "-host", host,
        "-top-ports", top_ports,
        "-rate", str(s.naabu_rate),
        "-c", str(s.naabu_concurrency),
        "-silent",
        "-json",
    ]
    log.info("running naabu: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning("naabu timed out for %s", host)
        return []

    return parse(proc.stdout, fallback_host=host)


def parse(jsonl: str, *, fallback_host: str = "") -> list[OpenPort]:
    """Parse Naabu's JSONL output. Public entry point for tests."""
    out: list[OpenPort] = []
    for line in jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        h = row.get("host") or row.get("ip") or fallback_host
        port = row.get("port")
        if isinstance(port, int):
            out.append(OpenPort(host=h, port=port))
    return out
