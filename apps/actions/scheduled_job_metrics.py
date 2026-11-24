"""OpenTelemetry instruments for the scheduled jobs.

Runs happen in the Celery worker or an external scheduler, so values are read
from ``ScheduledJobCounter`` and ``ScheduledJobState`` when the meter collects.
Labels stay ``job``, ``status``, and ``kind``.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from django.utils import timezone

from apps.actions.models import ScheduledJobCounter
from apps.actions.scheduled_jobs import (
    JOBS,
    RUN_STATUSES,
    beat_last_seen,
    ensure_states,
    is_overdue,
    redis_reachable,
    scheduler_enabled,
)

logger = logging.getLogger(__name__)

# Prometheus name, instrument kind, unit, description.
# ``counter`` is an observable counter (the database stores the cumulative total).
SCHEDULED_METRICS: tuple[tuple[str, str, str, str], ...] = (
    (
        'shellui_storage_scheduled_job_runs_total',
        'counter',
        '1',
        'Finished scheduled job runs by status (succeeded, failed, skipped_locked).',
    ),
    (
        'shellui_storage_scheduled_job_items_total',
        'counter',
        '1',
        'Items processed by scheduled job runs, by kind.',
    ),
    (
        'shellui_storage_scheduled_job_last_success_timestamp_seconds',
        'gauge',
        's',
        'Unix time when the last successful run finished (0 before the first one).',
    ),
    (
        'shellui_storage_scheduled_job_last_run_timestamp_seconds',
        'gauge',
        's',
        'Unix time when the last run started (0 before the first one).',
    ),
    (
        'shellui_storage_scheduled_job_last_run_duration_seconds',
        'gauge',
        's',
        'Duration of the last finished run.',
    ),
    (
        'shellui_storage_scheduled_job_overdue',
        'gauge',
        '1',
        '1 when the last successful run is older than 3 times the job interval.',
    ),
    (
        'shellui_storage_scheduler_enabled',
        'gauge',
        '1',
        '1 when the in-container Celery worker and beat run (SCHEDULER_ENABLED).',
    ),
    (
        'shellui_storage_scheduler_redis_up',
        'gauge',
        '1',
        '1 when the scheduler broker (Redis) answers PING.',
    ),
    (
        'shellui_storage_scheduler_beat_last_seen_timestamp_seconds',
        'gauge',
        's',
        'Unix time when Celery beat last published a scheduled job.',
    ),
)

_cache_lock = threading.Lock()
_cache_at = 0.0
_cache_value: dict[str, list] | None = None
_CACHE_TTL = 5.0
_registered: Any = None


def clear_scheduled_job_metric_cache() -> None:
    global _cache_at, _cache_value
    with _cache_lock:
        _cache_at = 0.0
        _cache_value = None


def _load(observation) -> dict[str, list]:
    now = timezone.now()
    states = ensure_states()
    counters = {(row.job, row.name): row.value for row in ScheduledJobCounter.objects.filter(job__in=list(JOBS))}
    points: dict[str, list] = {name: [] for name, *_rest in SCHEDULED_METRICS}

    for name, spec in JOBS.items():
        state = states[name]
        for status in RUN_STATUSES:
            points['shellui_storage_scheduled_job_runs_total'].append(
                observation(counters.get((name, f'runs.{status}'), 0), {'job': name, 'status': status})
            )
        for kind in spec.item_kinds:
            points['shellui_storage_scheduled_job_items_total'].append(
                observation(counters.get((name, f'items.{kind}'), 0), {'job': name, 'kind': kind})
            )
        points['shellui_storage_scheduled_job_last_success_timestamp_seconds'].append(
            observation(state.last_success_at.timestamp() if state.last_success_at else 0, {'job': name})
        )
        points['shellui_storage_scheduled_job_last_run_timestamp_seconds'].append(
            observation(state.last_started_at.timestamp() if state.last_started_at else 0, {'job': name})
        )
        if state.last_duration_ms is not None:
            points['shellui_storage_scheduled_job_last_run_duration_seconds'].append(
                observation(state.last_duration_ms / 1000.0, {'job': name})
            )
        points['shellui_storage_scheduled_job_overdue'].append(
            observation(1 if is_overdue(spec, state, now) else 0, {'job': name})
        )

    points['shellui_storage_scheduler_enabled'].append(observation(1 if scheduler_enabled() else 0, {}))
    reachable = redis_reachable()
    if reachable is not None:
        points['shellui_storage_scheduler_redis_up'].append(observation(1 if reachable else 0, {}))
    beat = beat_last_seen() if reachable else None
    if beat is not None:
        points['shellui_storage_scheduler_beat_last_seen_timestamp_seconds'].append(observation(beat.timestamp(), {}))
    return points


def _points(observation) -> dict[str, list]:
    global _cache_at, _cache_value
    now = time.monotonic()
    with _cache_lock:
        if _cache_value is not None and now - _cache_at < _CACHE_TTL:
            return _cache_value
    try:
        loaded = _load(observation)
    except Exception:
        logger.exception('storage telemetry: failed to read scheduled job metrics')
        return {name: [] for name, *_rest in SCHEDULED_METRICS}
    with _cache_lock:
        _cache_at = time.monotonic()
        _cache_value = loaded
    return loaded


def register_scheduled_job_metrics(meter) -> None:
    global _registered
    if _registered == id(meter):
        return
    from opentelemetry.metrics import Observation
    from shellui_django.telemetry import canonical_metric_name

    def _callback(prometheus_name: str):
        def callback(_options):
            return list(_points(Observation).get(prometheus_name, ()))

        return callback

    for prometheus_name, kind, unit, description in SCHEDULED_METRICS:
        name = canonical_metric_name(prometheus_name)
        callbacks = [_callback(prometheus_name)]
        if kind == 'counter':
            meter.create_observable_counter(name, callbacks=callbacks, unit=unit, description=description)
        else:
            meter.create_observable_gauge(name, callbacks=callbacks, unit=unit, description=description)
    _registered = id(meter)
