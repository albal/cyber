"""Nuclei adapter — template-based web vulnerability scanner.

Output is parsed from Nuclei's JSONL (-jsonl) format.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass(slots=True)
class NucleiHit:
    template_id: str
    name: str
    severity: str
    matched_at: str
    description: str | None = None
    remediation: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    request: str | None = None
    response_excerpt: str | None = None
    matcher_name: str | None = None
    cvss_score: float | None = None


def run(
    targets: list[str],
    severities: tuple[str, ...] = ("critical", "high", "medium", "low"),
    timeout_s: int = 600,
    extra_args: list[str] | None = None,
) -> list[NucleiHit]:
    if not targets:
        return []
    if not shutil.which("nuclei"):
        log.warning("nuclei not on PATH — returning empty result")
        return []

    cmd = [
        "nuclei",
        "-silent",
        "-jsonl",
        "-severity", ",".join(severities),
        "-no-color",
        "-disable-update-check",
        "-rate-limit", "150",
        "-c", "25",
        "-timeout", "10",
    ]
    if extra_args:
        cmd.extend(extra_args)

    log.info("running nuclei on %d target(s)", len(targets))
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
        log.warning("nuclei timed out")
        return []

    out: list[NucleiHit] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = row.get("info") or {}
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or info.get("reference-cve-id") or []
        cwe_ids = classification.get("cwe-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        if isinstance(cwe_ids, str):
            cwe_ids = [cwe_ids]

        cvss_score: float | None = None
        cvss_metrics = classification.get("cvss-score")
        if isinstance(cvss_metrics, (int, float)):
            cvss_score = float(cvss_metrics)

        out.append(
            NucleiHit(
                template_id=str(row.get("template-id") or row.get("templateID") or "unknown"),
                name=str(info.get("name") or row.get("template-id") or "finding"),
                severity=str(info.get("severity") or "info").lower(),
                matched_at=str(row.get("matched-at") or row.get("host") or ""),
                description=info.get("description"),
                remediation=info.get("remediation"),
                cve_ids=[str(c).upper() for c in cve_ids],
                cwe_ids=[str(c).upper() for c in cwe_ids],
                references=list(info.get("reference") or []),
                request=row.get("request"),
                response_excerpt=(row.get("response") or "")[:2000] or None,
                matcher_name=row.get("matcher-name"),
                cvss_score=cvss_score,
            )
        )
    return out


def shard(targets: list[str], shards: int) -> list[list[str]]:
    if shards <= 1 or len(targets) <= shards:
        return [targets]
    buckets: list[list[str]] = [[] for _ in range(shards)]
    for i, t in enumerate(targets):
        buckets[i % shards].append(t)
    return [b for b in buckets if b]
