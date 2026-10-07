"""Data retention: purge rows older than ``EVENT_LOG_RETENTION_DAYS`` and detect a missing purge job."""

from __future__ import annotations

import time
from datetime import datetime, timedelta

from django.conf import settings
from django.db.models import Model, Q, QuerySet
from django.utils import timezone

from apps.actions.models import ActionOutbox, EventLog

# Grace period before stale rows are reported: a purge job running at least daily never trips it.
STALE_GRACE = timedelta(days=1)

# Pending and failed deliveries are still retried, so only finished ones expire.
_FINISHED_DELIVERY = Q(status__in=(ActionOutbox.STATUS_DELIVERED, ActionOutbox.STATUS_DEAD))

_PURGE_TARGETS: tuple[tuple[str, type[Model], Q], ...] = (
    ('events', EventLog, Q()),
    ('webhook_deliveries', ActionOutbox, _FINISHED_DELIVERY & Q(delivery_kind=ActionOutbox.KIND_WEBHOOK)),
    ('email_events', ActionOutbox, _FINISHED_DELIVERY & Q(delivery_kind=ActionOutbox.KIND_EMAIL)),
)


def retention_days() -> int:
    return max(1, int(settings.EVENT_LOG_RETENTION_DAYS))


def retention_status(company_id: int, *, now: datetime | None = None) -> dict:
    """
    Retention setting and health for ``company_id`` (one indexed query).

    ``stale_events`` is true when the oldest event is older than retention plus ``STALE_GRACE``,
    which means ``purge_expired_data`` is not scheduled or keeps failing.
    """
    now = now or timezone.now()
    days = retention_days()
    oldest = (
        EventLog.objects.filter(company_id=company_id)
        .order_by('created_at')
        .values_list('created_at', flat=True)
        .first()
    )
    return {
        'data_retention_days': days,
        'oldest_event_at': oldest.isoformat() if oldest else None,
        'stale_events': bool(oldest and oldest < now - timedelta(days=days) - STALE_GRACE),
    }


def _delete_in_batches(qs: QuerySet, *, batch_size: int, deadline: float | None) -> tuple[int, bool]:
    """Delete ``qs`` in primary-key batches so each statement and lock stays short."""
    model = qs.model
    ids_qs = qs.order_by().values_list('pk', flat=True)
    deleted = 0
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            return deleted, False
        ids = list(ids_qs[:batch_size])
        if not ids:
            return deleted, True
        model.objects.filter(pk__in=ids).delete()
        deleted += len(ids)


def purge_expired_data(
    *,
    batch_size: int = 2000,
    max_seconds: float | None = None,
    dry_run: bool = False,
    now: datetime | None = None,
) -> dict:
    """
    Delete event log rows and finished webhook and email deliveries older than ``EVENT_LOG_RETENTION_DAYS``.

    Returns per-target counts and ``complete=False`` when ``max_seconds`` ran out first
    (the next run picks up where this one stopped).
    """
    now = now or timezone.now()
    cutoff = now - timedelta(days=retention_days())
    deadline = time.monotonic() + max_seconds if max_seconds else None
    stats: dict = {label: 0 for label, *_ in _PURGE_TARGETS}
    stats['scheduled_job_runs'] = 0
    stats['complete'] = True
    for label, model, extra in _PURGE_TARGETS:
        qs = model.objects.filter(extra, created_at__lt=cutoff)
        if dry_run:
            stats[label] = qs.count()
            continue
        deleted, finished = _delete_in_batches(qs, batch_size=batch_size, deadline=deadline)
        stats[label] = deleted
        if not finished:
            stats['complete'] = False
            return stats
    from apps.actions.scheduled_jobs import count_old_runs, purge_old_runs

    if dry_run:
        stats['scheduled_job_runs'] = count_old_runs(now=now)
        return stats
    deleted, finished = purge_old_runs(now=now, batch_size=batch_size, deadline=deadline)
    stats['scheduled_job_runs'] = deleted
    if not finished:
        stats['complete'] = False
    return stats
