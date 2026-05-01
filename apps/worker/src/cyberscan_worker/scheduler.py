"""Per-asset scheduled scans.

A single Celery Beat schedule fires this dispatcher task every minute. The
dispatcher reads `assets.schedule_cron` for every enabled asset and enqueues
a `pipeline.run_scan` if the cron expression matches and we haven't fired
already in this minute (deduped via `last_scheduled_at`).

Using a coarse (per-minute) tick instead of one Celery Beat schedule per
asset keeps the scheduler stateless: assets can be added/removed/edited at
runtime without restarting Beat.
"""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from croniter import croniter
from sqlalchemy import text

from cyberscan_worker.celery_app import celery_app
from cyberscan_worker.db import SessionLocal

log = logging.getLogger(__name__)

# Configure Celery Beat to fire the dispatcher once a minute.
celery_app.conf.beat_schedule = {
    **(celery_app.conf.beat_schedule or {}),
    "scheduled-scans-tick": {
        "task": "cyberscan_worker.scheduler.dispatch_due_scans",
        "schedule": 60.0,
    },
}


@celery_app.task(name="cyberscan_worker.scheduler.dispatch_due_scans", queue="recon")
def dispatch_due_scans() -> int:
    """Find assets whose cron matches the previous minute and enqueue scans."""
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    enqueued = 0

    with SessionLocal() as db:
        # No GUC pin — beat runs system-wide, RLS owner bypass applies.
        rows = db.execute(
            text(
                """
                SELECT id::text, tenant_id::text, name, schedule_cron,
                       last_scheduled_at, verification_status::text AS verification_status
                  FROM assets
                 WHERE schedule_enabled = TRUE AND schedule_cron IS NOT NULL
                """
            )
        ).all()

        for row in rows:
            if row.verification_status != "verified":
                log.debug("skipping unverified asset %s for scheduled scan", row.id)
                continue
            if not _is_due(row.schedule_cron, now, row.last_scheduled_at):
                continue

            scan_id = str(uuid.uuid4())
            db.execute(
                text(
                    """
                    INSERT INTO scans (id, tenant_id, asset_id, status, progress, created_by)
                    VALUES (:id, :tid, :aid, 'queued', 0,
                            (SELECT id FROM users WHERE tenant_id = :tid ORDER BY created_at LIMIT 1))
                    """
                ),
                {"id": scan_id, "tid": row.tenant_id, "aid": row.id},
            )
            db.execute(
                text("UPDATE assets SET last_scheduled_at = :now WHERE id = :id"),
                {"now": now, "id": row.id},
            )
            db.commit()

            celery_app.send_task(
                "cyberscan_worker.pipeline.run_scan",
                kwargs={"scan_id": scan_id, "tenant_id": row.tenant_id},
                queue="recon",
            )
            enqueued += 1
            log.info("scheduled scan enqueued asset=%s scan=%s", row.id, scan_id)

    return enqueued


def _is_due(cron_expr: str, now: datetime, last_at: datetime | None) -> bool:
    """True when the previous minute matches the cron expression and we
    haven't already fired for that minute."""
    try:
        # Step BACK from now to the most recent matching minute. If that
        # equals `now` (we're inside that minute), we should fire — unless
        # we've already fired in this minute.
        prev = croniter(cron_expr, now + _ONE_MINUTE).get_prev(datetime)
    except (ValueError, KeyError):
        log.warning("invalid cron expression: %s", cron_expr)
        return False

    if prev != now:
        return False
    if last_at is None:
        return True
    last = last_at.replace(second=0, microsecond=0)
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return last < now


from datetime import timedelta as _td  # noqa: E402

_ONE_MINUTE = _td(seconds=1)
