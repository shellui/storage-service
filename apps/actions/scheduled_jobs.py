"""
Run recording and health for the scheduled jobs (``retry_webhooks``, ``purge_expired_data``).

The management commands record their own runs (``record_run``), so runs started by the
in-container Celery beat (``trigger=celery``) and by an external scheduler (``trigger=command``)
are both recorded. Each finished run writes:

- one ``ScheduledJobRun`` row (kept ``RUN_RETENTION_DAYS``)
- the latest timestamps in ``ScheduledJobState``
- monotonic counters in ``ScheduledJobCounter`` for Prometheus
- one staff-only platform event (``storage.scheduled_job.succeeded`` / ``.failed``)

A failed run logs at ERROR with the run id as request id (``[req=sjr-<id>]``), which also
reports it to Sentry when ``SENTRY_DSN`` is set. See docs/maintenance-jobs.md.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.conf import settings
from django.core.management.base import CommandError
from django.db import DatabaseError
from django.db.models import F
from django.utils import timezone

from apps.actions.models import ScheduledJobCounter, ScheduledJobRun, ScheduledJobState
from config.request_context import request_id_var

logger = logging.getLogger(__name__)

RUN_RETENTION_DAYS = 7

TRIGGER_CELERY = ScheduledJobRun.TRIGGER_CELERY
TRIGGER_COMMAND = ScheduledJobRun.TRIGGER_COMMAND
TRIGGERS = (TRIGGER_CELERY, TRIGGER_COMMAND)

HEALTH_HEALTHY = 'healthy'
HEALTH_OVERDUE = 'overdue'
HEALTH_FAILING = 'failing'
HEALTH_DISABLED = 'disabled'
HEALTH_VALUES = (HEALTH_HEALTHY, HEALTH_OVERDUE, HEALTH_FAILING, HEALTH_DISABLED)

# Stable error keys, translated by the admin panel.
ERROR_DATABASE = 'database_error'
ERROR_REDIS = 'redis_error'
ERROR_TIMEOUT = 'timeout'
ERROR_NETWORK = 'network_error'
ERROR_INTERRUPTED = 'interrupted'
ERROR_UNEXPECTED = 'unexpected_error'
ERROR_KEYS = (ERROR_DATABASE, ERROR_REDIS, ERROR_TIMEOUT, ERROR_NETWORK, ERROR_INTERRUPTED, ERROR_UNEXPECTED)

RUN_STATUSES = (
    ScheduledJobRun.STATUS_SUCCEEDED,
    ScheduledJobRun.STATUS_FAILED,
    ScheduledJobRun.STATUS_SKIPPED_LOCKED,
)

EVENT_SUCCEEDED = 'storage.scheduled_job.succeeded'
EVENT_FAILED = 'storage.scheduled_job.failed'

BEAT_STALE_AFTER = timedelta(minutes=3)


@dataclass(frozen=True)
class JobSpec:
    name: str
    interval_seconds: int
    overdue_after_seconds: int
    # Seconds after which a ``running`` row can only be a crashed run (the lock TTL).
    max_runtime_seconds: int
    item_kinds: tuple[str, ...] = field(default=())
    # Hourly jobs run at this minute (crontab); None for fixed intervals.
    cron_minute: int | None = None

    def next_after(self, moment: datetime) -> datetime:
        if self.cron_minute is None:
            return moment + timedelta(seconds=self.interval_seconds)
        candidate = moment.replace(minute=self.cron_minute, second=0, microsecond=0)
        if candidate <= moment:
            candidate += timedelta(hours=1)
        return candidate


RETRY_WEBHOOKS = JobSpec(
    name='retry_webhooks',
    interval_seconds=60,
    overdue_after_seconds=180,
    max_runtime_seconds=120,
    item_kinds=(
        'webhook_deliveries_attempted',
        'webhook_deliveries_succeeded',
        'webhook_deliveries_failed',
        'webhook_deliveries_given_up',
    ),
)

PURGE_EXPIRED_DATA = JobSpec(
    name='purge_expired_data',
    interval_seconds=3600,
    overdue_after_seconds=8100,
    max_runtime_seconds=900,
    item_kinds=(
        'events',
        'webhook_deliveries',
        'scheduled_job_runs',
    ),
    cron_minute=17,
)

JOBS: dict[str, JobSpec] = {spec.name: spec for spec in (RETRY_WEBHOOKS, PURGE_EXPIRED_DATA)}


def get_job(name: str) -> JobSpec:
    try:
        return JOBS[name]
    except KeyError as exc:
        raise ValueError(f'Unknown scheduled job: {name!r}') from exc


def host_id() -> str:
    return f'{socket.gethostname()}:{os.getpid()}'[:128]


# --- error sanitizing -------------------------------------------------------------------

_URL_QUERY_RE = re.compile(r'(\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s?#\'"<>]*)[?#][^\s\'"<>]*')
_URL_USERINFO_RE = re.compile(r'(\b[a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@\'"<>]+@')
_SECRET_PAIR_RE = re.compile(
    r'(?i)\b(token|access_token|refresh_token|api[_-]?key|key|secret|password|passwd|pwd|'
    r'authorization|code|state|signature|sig)(\s*[=:]\s*)("[^"]*"|\'[^\']*\'|[^\s,;&]+)'
)
_BEARER_RE = re.compile(r'(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}')
_JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b')
_LONG_HEX_RE = re.compile(r'\b[A-Fa-f0-9]{32,}\b')
ERROR_MESSAGE_MAX = 300


def sanitize_error_message(text: str) -> str:
    """
    One line, at most 300 characters, with URL query strings, URL credentials, ``key=value``
    secrets, bearer tokens, JWTs and long hex tokens removed.
    """
    value = ' '.join(str(text or '').split())
    value = _URL_QUERY_RE.sub(r'\1', value)
    value = _URL_USERINFO_RE.sub(r'\1', value)
    value = _BEARER_RE.sub(r'\1 [Filtered]', value)
    value = _JWT_RE.sub('[Filtered]', value)
    value = _SECRET_PAIR_RE.sub(r'\1\2[Filtered]', value)
    value = _LONG_HEX_RE.sub('[Filtered]', value)
    if len(value) > ERROR_MESSAGE_MAX:
        value = value[: ERROR_MESSAGE_MAX - 1] + '…'
    return value


def error_key_for(exc: BaseException) -> str:
    try:
        import redis
    except ImportError:  # pragma: no cover
        redis = None
    if redis is not None and isinstance(exc, redis.TimeoutError):
        return ERROR_TIMEOUT
    if redis is not None and isinstance(exc, redis.RedisError):
        return ERROR_REDIS
    if isinstance(exc, DatabaseError):
        return ERROR_DATABASE
    if isinstance(exc, TimeoutError):
        return ERROR_TIMEOUT
    if isinstance(exc, (ConnectionError, socket.gaierror)):
        return ERROR_NETWORK
    try:
        import requests

        if isinstance(exc, requests.Timeout):
            return ERROR_TIMEOUT
        if isinstance(exc, requests.RequestException):
            return ERROR_NETWORK
    except ImportError:  # pragma: no cover
        pass
    return ERROR_UNEXPECTED


def describe_error(exc: BaseException) -> tuple[str, str, str]:
    """``(error_key, error_class, error_message)`` safe to store, show to staff and log."""
    return (
        error_key_for(exc),
        exc.__class__.__name__[:128],
        sanitize_error_message(str(exc) or exc.__class__.__name__),
    )


# --- counters and state -------------------------------------------------------------------


def _increment(job: str, name: str, amount: int = 1) -> None:
    if amount <= 0:
        return
    updated = ScheduledJobCounter.objects.filter(job=job, name=name).update(value=F('value') + amount)
    if updated:
        return
    counter, created = ScheduledJobCounter.objects.get_or_create(job=job, name=name, defaults={'value': amount})
    if not created:
        ScheduledJobCounter.objects.filter(pk=counter.pk).update(value=F('value') + amount)


def _ensure_state(job: str) -> None:
    ScheduledJobState.objects.get_or_create(job=job)


def ensure_states() -> dict[str, ScheduledJobState]:
    states = {s.job: s for s in ScheduledJobState.objects.filter(job__in=list(JOBS))}
    for name in JOBS:
        if name not in states:
            states[name], _ = ScheduledJobState.objects.get_or_create(job=name)
    return states


def _int_counts(spec: JobSpec, counts: dict) -> dict[str, int]:
    return {
        kind: int(counts.get(kind) or 0)
        for kind in spec.item_kinds
        if isinstance(counts.get(kind), int) and not isinstance(counts.get(kind), bool)
    }


# --- recording ------------------------------------------------------------------------------


class ScheduledJobFailed(CommandError):
    """
    Raised by the commands after a failed run was recorded and reported.

    A ``CommandError``, so ``manage.py`` prints one line and exits with status 1 (cron
    alerting works) without a second Sentry report from the uncaught-exception hook.
    """

    def __init__(self, run: ScheduledJobRun | None, message: str):
        super().__init__(message)
        self.run = run


@dataclass
class RunRecorder:
    run: ScheduledJobRun
    counts: dict = field(default_factory=dict)

    def set_counts(self, counts: dict) -> None:
        self.counts = dict(counts)


def _mark_interrupted(spec: JobSpec, current: ScheduledJobRun) -> None:
    """Close ``running`` rows that outlived the lock TTL: their worker died mid-run."""
    cutoff = current.started_at - timedelta(seconds=spec.max_runtime_seconds)
    stale = ScheduledJobRun.objects.filter(
        job=spec.name,
        status=ScheduledJobRun.STATUS_RUNNING,
        started_at__lt=cutoff,
    ).exclude(pk=current.pk)
    count = stale.update(
        status=ScheduledJobRun.STATUS_FAILED,
        finished_at=current.started_at,
        error_key=ERROR_INTERRUPTED,
        error_class='',
        error_message='',
    )
    if count:
        _increment(spec.name, f'runs.{ScheduledJobRun.STATUS_FAILED}', count)
        logger.warning('scheduled_job_interrupted job=%s runs=%s', spec.name, count)


def _record_platform_event(run: ScheduledJobRun) -> int | None:
    from apps.actions.models import EventLog

    event_id = EVENT_SUCCEEDED if run.status == ScheduledJobRun.STATUS_SUCCEEDED else EVENT_FAILED
    payload = {
        'run_id': run.pk,
        'job': run.job,
        'trigger': run.trigger,
        'duration_ms': run.duration_ms,
        'counts': run.counts,
        'host': run.host,
        'error_key': run.error_key,
        'error_class': run.error_class,
    }
    # No company: staff-only platform event, never offered as a webhook rule.
    return EventLog.objects.create(company_id=None, event_type=event_id, data=payload).pk


def _finish(
    run: ScheduledJobRun,
    spec: JobSpec,
    *,
    started: float,
    counts: dict,
    exc: BaseException | None,
) -> None:
    now = timezone.now()
    run.finished_at = now
    run.duration_ms = max(0, int((time.monotonic() - started) * 1000))
    run.counts = counts
    if exc is None:
        run.status = ScheduledJobRun.STATUS_SUCCEEDED
    else:
        run.status = ScheduledJobRun.STATUS_FAILED
        run.error_key, run.error_class, run.error_message = describe_error(exc)
    run.event_log_id = _record_platform_event(run)
    run.save(
        update_fields=[
            'status',
            'finished_at',
            'duration_ms',
            'counts',
            'error_key',
            'error_class',
            'error_message',
            'event_log_id',
        ]
    )
    state_update = {'last_duration_ms': run.duration_ms}
    if exc is None:
        state_update['last_success_at'] = now
    else:
        state_update['last_failure_at'] = now
    ScheduledJobState.objects.filter(job=spec.name).update(**state_update)
    _increment(spec.name, f'runs.{run.status}')
    for kind, amount in _int_counts(spec, counts).items():
        _increment(spec.name, f'items.{kind}', amount)


@contextlib.contextmanager
def _sentry_scope(run: ScheduledJobRun):
    if not getattr(settings, 'SENTRY_DSN', ''):
        yield
        return
    try:
        import sentry_sdk
    except ImportError:  # pragma: no cover
        yield
        return
    with sentry_sdk.new_scope() as scope:
        scope.set_tag('scheduled_job', run.job)
        scope.set_tag('scheduled_job_trigger', run.trigger)
        scope.set_tag('scheduled_job_run_id', str(run.pk))
        yield


class ScheduledJobError(Exception):
    """
    Stand-in for the original exception in logs and Sentry: same traceback, sanitized message.

    The original message (and its chained causes) can hold a URL with a query string or a
    credential, so it never reaches stdout or Sentry as is.
    """


def sanitized_exc_info(exc: BaseException):
    _key, error_class, message = describe_error(exc)
    safe = ScheduledJobError(f'{error_class}: {message}')
    safe.__suppress_context__ = True
    return (ScheduledJobError, safe.with_traceback(exc.__traceback__), exc.__traceback__)


def _report_failure(run: ScheduledJobRun, exc: BaseException) -> None:
    with _sentry_scope(run):
        logger.error(
            'scheduled_job_failed job=%s run_id=%s trigger=%s error_key=%s error_class=%s error=%s',
            run.job,
            run.pk,
            run.trigger,
            run.error_key,
            run.error_class,
            run.error_message,
            exc_info=sanitized_exc_info(exc),
        )


@contextlib.contextmanager
def record_run(job: str, trigger: str):
    """
    Record one run of ``job``. Yields a ``RunRecorder``; call ``set_counts`` before leaving.

    On error the run is stored as ``failed``, logged at ERROR (Sentry) and the exception is
    re-raised. While the block runs, log lines carry ``[req=sjr-<run id>]``.
    """
    spec = get_job(job)
    if trigger not in TRIGGERS:
        raise ValueError(f'Unknown trigger: {trigger!r}')
    run = ScheduledJobRun.objects.create(
        job=spec.name,
        trigger=trigger,
        status=ScheduledJobRun.STATUS_RUNNING,
        started_at=timezone.now(),
        host=host_id(),
    )
    _ensure_state(spec.name)
    ScheduledJobState.objects.filter(job=spec.name).update(last_started_at=run.started_at)
    _mark_interrupted(spec, run)
    token = request_id_var.set(run.request_id)
    recorder = RunRecorder(run=run)
    started = time.monotonic()
    try:
        try:
            yield recorder
        except Exception as exc:
            try:
                _finish(run, spec, started=started, counts=recorder.counts, exc=exc)
            except Exception:  # noqa: BLE001
                logger.exception('scheduled_job_record_failed job=%s run_id=%s', spec.name, run.pk)
            _report_failure(run, exc)
            raise
        try:
            _finish(run, spec, started=started, counts=recorder.counts, exc=None)
        except Exception:  # noqa: BLE001
            # The job did its work; a later run marks this row as interrupted.
            logger.exception('scheduled_job_record_failed job=%s run_id=%s', spec.name, run.pk)
    finally:
        request_id_var.reset(token)


def run_recorded(job: str, trigger: str, work):
    """
    Run ``work(run_id) -> (result, counts)`` inside ``record_run``. Returns ``(result, run_id)``.

    Raises ``ScheduledJobFailed`` (sanitized message with the run id) when ``work`` fails.
    """
    recorder = None
    try:
        with record_run(job, trigger) as recorder:
            result, counts = work(recorder.run.pk)
            recorder.set_counts(counts)
            return result, recorder.run.pk
    except Exception as exc:
        run = recorder.run if recorder is not None else None
        _key, error_class, message = describe_error(exc)
        if run is None:
            # The run row could not be written (database down): log it here instead.
            logger.error(
                'scheduled_job_failed job=%s run_id=- trigger=%s error_class=%s error=%s',
                job,
                trigger,
                error_class,
                message,
                exc_info=sanitized_exc_info(exc),
            )
        raise ScheduledJobFailed(
            run,
            f'{job} failed: {error_class}: {message} (run_id={run.pk if run else "-"})',
        ) from exc


def record_skipped(job: str, trigger: str = TRIGGER_CELERY) -> None:
    """Another run holds the lock. Counted for metrics, no run row (see module docstring)."""
    spec = get_job(job)
    _ensure_state(spec.name)
    ScheduledJobState.objects.filter(job=spec.name).update(last_skipped_at=timezone.now())
    _increment(spec.name, f'runs.{ScheduledJobRun.STATUS_SKIPPED_LOCKED}')


def record_failure_before_start(job: str, trigger: str, exc: BaseException) -> ScheduledJobRun | None:
    """
    Record a run that failed before the command started (for example Redis down while
    taking the lock). Never raises.
    """
    try:
        with record_run(job, trigger) as recorder:
            raise exc
    except Exception as raised:  # noqa: BLE001
        if raised is not exc:
            logger.exception('scheduled_job_record_failed job=%s', job)
            return None
        return recorder.run
    return None  # pragma: no cover


# --- health -----------------------------------------------------------------------------------


def scheduler_enabled() -> bool:
    return bool(getattr(settings, 'SCHEDULER_ENABLED', True))


def redis_reachable() -> bool | None:
    """True or False after a PING on the broker, None when no broker is configured."""
    if not getattr(settings, 'CELERY_BROKER_URL', ''):
        return None
    from config.task_lock import get_lock_client

    try:
        return bool(get_lock_client().ping())
    except Exception:  # noqa: BLE001
        return False


def beat_last_seen() -> datetime | None:
    if not getattr(settings, 'CELERY_BROKER_URL', ''):
        return None
    from config.task_lock import read_beat_heartbeat

    try:
        ts = read_beat_heartbeat()
    except Exception:  # noqa: BLE001
        return None
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=dt_timezone.utc)


def _last_runs(job_names) -> dict[str, ScheduledJobRun]:
    result = {}
    for name in job_names:
        run = ScheduledJobRun.objects.filter(job=name).order_by('-started_at', '-id').first()
        if run is not None:
            result[name] = run
    return result


def _last_finished_runs(job_names) -> dict[str, ScheduledJobRun]:
    result = {}
    for name in job_names:
        run = (
            ScheduledJobRun.objects.filter(job=name)
            .exclude(status=ScheduledJobRun.STATUS_RUNNING)
            .order_by('-started_at', '-id')
            .first()
        )
        if run is not None:
            result[name] = run
    return result


def is_overdue(spec: JobSpec, state: ScheduledJobState, now: datetime) -> bool:
    """Last success (or, before the first one, when monitoring started) older than the limit."""
    reference = state.last_success_at or state.created_at
    return now - reference > timedelta(seconds=spec.overdue_after_seconds)


def compute_health(
    spec: JobSpec,
    state: ScheduledJobState,
    last_finished: ScheduledJobRun | None,
    now: datetime,
    *,
    enabled: bool,
) -> str:
    """
    ``disabled``: scheduler off and no run ever recorded (no cron set up yet).
    ``failing``: the last finished run failed. ``overdue``: no success within the limit.
    """
    ever_ran = state.last_started_at is not None or last_finished is not None
    if not enabled and not ever_ran:
        return HEALTH_DISABLED
    if last_finished is not None and last_finished.status == ScheduledJobRun.STATUS_FAILED:
        return HEALTH_FAILING
    if is_overdue(spec, state, now):
        return HEALTH_OVERDUE
    return HEALTH_HEALTHY


def next_expected_at(spec: JobSpec, state: ScheduledJobState, now: datetime) -> datetime:
    """When the next run should start, from the last start (or now before the first run)."""
    return spec.next_after(state.last_started_at or now)


def run_payload(run: ScheduledJobRun) -> dict:
    return {
        'id': run.pk,
        'job': run.job,
        'trigger': run.trigger,
        'status': run.status,
        'started_at': run.started_at.isoformat() if run.started_at else None,
        'finished_at': run.finished_at.isoformat() if run.finished_at else None,
        'duration_ms': run.duration_ms,
        'counts': run.counts or {},
        'error_key': run.error_key or None,
        'error_class': run.error_class or None,
        'error_message': run.error_message or None,
        'host': run.host,
        'request_id': run.request_id,
        'event_log_id': run.event_log_id,
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def jobs_overview(*, now: datetime | None = None, check_redis: bool = True) -> dict:
    """Payload of ``GET /api/v1/scheduled-jobs`` (also used by the metrics collector)."""
    now = now or timezone.now()
    enabled = scheduler_enabled()
    states = ensure_states()
    names = list(JOBS)
    last_runs = _last_runs(names)
    last_finished = _last_finished_runs(names)
    since = now - timedelta(hours=24)
    # Count in Python: a conditional aggregate named after a CSS utility would be
    # picked up by the landing-page Tailwind scan.
    window: dict[str, dict[str, int]] = {}
    for job_name, status in ScheduledJobRun.objects.filter(job__in=names, started_at__gte=since).values_list(
        'job', 'status'
    ):
        bucket = window.setdefault(job_name, {'succeeded': 0, 'failed': 0})
        if status == ScheduledJobRun.STATUS_SUCCEEDED:
            bucket['succeeded'] += 1
        elif status == ScheduledJobRun.STATUS_FAILED:
            bucket['failed'] += 1
    skipped = {
        c.job: c.value
        for c in ScheduledJobCounter.objects.filter(
            job__in=names, name=f'runs.{ScheduledJobRun.STATUS_SKIPPED_LOCKED}'
        )
    }
    jobs = []
    for name in names:
        spec = JOBS[name]
        state = states[name]
        finished = last_finished.get(name)
        last_success_run = (
            finished
            if finished is not None and finished.status == ScheduledJobRun.STATUS_SUCCEEDED
            else ScheduledJobRun.objects.filter(job=name, status=ScheduledJobRun.STATUS_SUCCEEDED)
            .order_by('-started_at', '-id')
            .first()
        )
        win = window.get(name, {})
        jobs.append(
            {
                'job': name,
                'health': compute_health(spec, state, finished, now, enabled=enabled),
                'overdue': is_overdue(spec, state, now),
                'interval_seconds': spec.interval_seconds,
                'overdue_after_seconds': spec.overdue_after_seconds,
                'last_run': run_payload(last_runs[name]) if name in last_runs else None,
                'last_success_at': _iso(state.last_success_at),
                'last_failure_at': _iso(state.last_failure_at),
                'last_skipped_at': _iso(state.last_skipped_at),
                'last_duration_ms': state.last_duration_ms,
                'last_counts': (last_success_run.counts or {}) if last_success_run else {},
                'next_expected_at': _iso(next_expected_at(spec, state, now)),
                'last_24h': {
                    'succeeded': int(win.get('succeeded') or 0),
                    'failed': int(win.get('failed') or 0),
                },
                'skipped_locked_total': int(skipped.get(name) or 0),
            }
        )
    beat_seen = beat_last_seen() if check_redis else None
    return {
        'generated_at': now.isoformat(),
        'scheduler_enabled': enabled,
        'redis_reachable': redis_reachable() if check_redis else None,
        'beat_last_seen_at': _iso(beat_seen),
        'beat_stale': bool(enabled and (beat_seen is None or now - beat_seen > BEAT_STALE_AFTER)),
        'jobs': jobs,
    }


def purge_old_runs(*, now: datetime, batch_size: int, deadline: float | None) -> tuple[int, bool]:
    """Delete runs older than ``RUN_RETENTION_DAYS`` in batches. Returns (deleted, finished)."""
    cutoff = now - timedelta(days=RUN_RETENTION_DAYS)
    ids_qs = ScheduledJobRun.objects.filter(started_at__lt=cutoff).order_by().values_list('pk', flat=True)
    deleted = 0
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            return deleted, False
        ids = list(ids_qs[:batch_size])
        if not ids:
            return deleted, True
        ScheduledJobRun.objects.filter(pk__in=ids).delete()
        deleted += len(ids)


def count_old_runs(*, now: datetime) -> int:
    return ScheduledJobRun.objects.filter(started_at__lt=now - timedelta(days=RUN_RETENTION_DAYS)).count()
