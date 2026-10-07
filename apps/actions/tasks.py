"""
Celery tasks for the scheduled jobs.

Each task runs the existing management command, so an external scheduler and the
in-container scheduler share one code path: the command records the run (``trigger=celery``
here, ``command`` from an external scheduler). A Redis lock (config.task_lock) makes sure
only one run of each job is active across all containers. See docs/maintenance-jobs.md.
"""

import io
import logging

from celery import shared_task
from django.core.management import call_command

from apps.actions.scheduled_jobs import (
    TRIGGER_CELERY,
    ScheduledJobFailed,
    record_failure_before_start,
    record_skipped,
)
from config.task_lock import task_lock

logger = logging.getLogger(__name__)

# retry_webhooks stops after --max-seconds 50 (its default); the lock covers that plus
# in-flight HTTP calls. If a worker dies, retries resume after at most 2 minutes.
RETRY_WEBHOOKS_LOCK_TTL = 120

PURGE_EXPIRED_DATA_MAX_SECONDS = 300
# Purge stops after 300 seconds plus the batch in progress.
PURGE_EXPIRED_DATA_LOCK_TTL = 900


def _run_command(name: str, **options) -> str:
    out = io.StringIO()
    call_command(name, stdout=out, no_color=True, trigger=TRIGGER_CELERY, **options)
    summary = out.getvalue().strip()
    if summary:
        logger.info(summary)
    return summary


def _run_locked(name: str, ttl: int, **options) -> str:
    """
    ``skipped`` when another run holds the lock, ``failed`` when the run failed (already
    recorded, logged at ERROR and sent to Sentry by the command), else the command summary.
    """
    try:
        with task_lock(name, ttl=ttl) as acquired:
            if not acquired:
                logger.info('%s: skipped, another run is in progress', name)
                record_skipped(name, TRIGGER_CELERY)
                return 'skipped'
            return _run_command(name, **options)
    except ScheduledJobFailed:
        return 'failed'
    except Exception as exc:  # noqa: BLE001
        # Failed before the command could record it (Redis down while taking the lock).
        record_failure_before_start(name, TRIGGER_CELERY, exc)
        return 'failed'


@shared_task(name='actions.retry_webhooks', ignore_result=True)
def retry_webhooks() -> str:
    """Retry failed webhook deliveries."""
    return _run_locked('retry_webhooks', ttl=RETRY_WEBHOOKS_LOCK_TTL)


@shared_task(name='actions.purge_expired_data', ignore_result=True)
def purge_expired_data() -> str:
    """Delete event log rows and finished deliveries past retention."""
    return _run_locked(
        'purge_expired_data',
        ttl=PURGE_EXPIRED_DATA_LOCK_TTL,
        max_seconds=PURGE_EXPIRED_DATA_MAX_SECONDS,
    )
