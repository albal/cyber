from celery import Celery

from cyberscan_api.core.config import get_settings

_settings = get_settings()

celery_app = Celery(
    "cyberscan",
    broker=_settings.celery_broker_url,
    backend=_settings.celery_result_backend,
)
celery_app.conf.task_routes = {
    "cyberscan_worker.pipeline.run_scan": {"queue": "recon"},
}
