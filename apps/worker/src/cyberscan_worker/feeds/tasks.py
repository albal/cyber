"""Periodic feed-refresh tasks (used by Celery Beat or Kubernetes CronJob)."""
from __future__ import annotations

import logging

from cyberscan_worker.celery_app import celery_app
from cyberscan_worker.config import get_settings
from cyberscan_worker.db import SessionLocal
from cyberscan_worker.feeds import epss, kev, nvd

log = logging.getLogger(__name__)


@celery_app.task(name="cyberscan_worker.feeds.refresh_nvd", queue="feeds")
def refresh_nvd() -> int:
    s = get_settings()
    with SessionLocal() as db:
        return nvd.ingest(db, use_fixture=s.feeds_use_fixtures, api_key=s.nvd_api_key)


@celery_app.task(name="cyberscan_worker.feeds.refresh_kev", queue="feeds")
def refresh_kev() -> int:
    s = get_settings()
    with SessionLocal() as db:
        return kev.ingest(db, use_fixture=s.feeds_use_fixtures)


@celery_app.task(name="cyberscan_worker.feeds.refresh_epss", queue="feeds")
def refresh_epss() -> int:
    s = get_settings()
    with SessionLocal() as db:
        return epss.ingest(db, use_fixture=s.feeds_use_fixtures)
