"""Katana adapter — recursive web crawler.

Katana is the ProjectDiscovery crawler. It walks the target, follows links,
parses JavaScript and source maps, and emits one JSON document per
discovered URL. We feed the resulting URL list into Nuclei so it doesn't
just hammer the homepage on a single-page app.

Ships in headless=false mode by default (HTTP-only crawl: fast, no
Chromium needed). Set KATANA_HEADLESS=1 in the worker env to render JS;
that requires Chromium installed in the image.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(slots=True)
class CrawledUrl:
    url: str
    method: str = "GET"
    status: int | None = None


def run(
    seeds: list[str],
    *,
    depth: int = 3,
    max_urls: int = 500,
    timeout_s: int = 180,
    headless: bool | None = None,
) -> list[CrawledUrl]:
    """Crawl `seeds` and return a deduplicated list of discovered URLs."""
    if not seeds:
        return []
    if not shutil.which("katana"):
        log.info("katana not on PATH — skipping crawl, returning seeds only")
        return [CrawledUrl(url=s) for s in seeds]

    if headless is None:
        headless = bool(int(os.environ.get("KATANA_HEADLESS", "0")))

    cmd = [
        "katana",
        "-silent",
        "-jsonl",
        "-d", str(depth),
        "-c", "10",
        "-rl", "150",
        "-jc",  # parse JavaScript files
        "-kf", "all",  # known files (robots, sitemap, ...)
        "-fs", "rdn",  # field-scope: same root domain
    ]
    if headless:
        cmd += ["-headless", "-no-sandbox"]

    log.info("katana: crawling %d seed(s) depth=%d headless=%s", len(seeds), depth, headless)
    try:
        proc = subprocess.run(
            cmd,
            input="\n".join(seeds),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning("katana timed out (after %ds)", timeout_s)
        return [CrawledUrl(url=s) for s in seeds]

    found = parse(proc.stdout, seeds=seeds)
    if max_urls and len(found) > max_urls:
        log.info("katana: capping crawl from %d to %d urls", len(found), max_urls)
        found = found[:max_urls]
    return found


def parse(jsonl: str, *, seeds: list[str] | None = None) -> list[CrawledUrl]:
    """Parse Katana's JSONL output into deduplicated CrawledUrl entries.

    Always includes the seeds (so callers don't have to merge them back in).
    """
    seen: set[str] = set()
    out: list[CrawledUrl] = []

    for s in seeds or []:
        if s and s not in seen:
            seen.add(s)
            out.append(CrawledUrl(url=s))

    for line in jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Katana emits {"timestamp":"...","request":{"endpoint":"...","method":"GET",...},
        #               "response":{"status_code":200, ...}}
        req = row.get("request") or {}
        url = req.get("endpoint") or row.get("endpoint") or row.get("url") or ""
        if not url or url in seen:
            continue
        seen.add(url)
        method = (req.get("method") or "GET").upper()
        status = (row.get("response") or {}).get("status_code")
        out.append(
            CrawledUrl(
                url=url,
                method=method,
                status=int(status) if isinstance(status, (int, str)) and str(status).isdigit() else None,
            )
        )
    return out
