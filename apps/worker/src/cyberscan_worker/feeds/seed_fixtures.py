"""Seed CVE/KEV tables from bundled fixtures. Run once on `make seed`."""
from __future__ import annotations

import logging

from cyberscan_worker.config import get_settings
from cyberscan_worker.db import SessionLocal
from cyberscan_worker.feeds import kev, nvd

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def main() -> None:
    s = get_settings()
    use_fixture = s.feeds_use_fixtures or not s.nvd_api_key
    with SessionLocal() as db:
        nvd_count = nvd.ingest(db, use_fixture=use_fixture, api_key=s.nvd_api_key)
        kev_count = kev.ingest(db, use_fixture=use_fixture)
    print(f"seeded NVD={nvd_count} KEV={kev_count}")


if __name__ == "__main__":
    main()
