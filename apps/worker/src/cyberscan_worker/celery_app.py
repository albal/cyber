from celery import Celery

from cyberscan_worker.config import get_settings

_settings = get_settings()

celery_app = Celery(
    "cyberscan",
    broker=_settings.celery_broker_url,
    backend=_settings.celery_result_backend,
    include=["cyberscan_worker.pipeline", "cyberscan_worker.feeds.tasks"],
)

celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
)
