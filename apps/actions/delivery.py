"""Outbox delivery, retries, and post-commit dispatch."""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone

from apps.actions.email_service import deliver_email_event, email_event_body, email_service_configured, is_email_outbox
from apps.actions.handlers.webhook import WebhookDeliveryError, deliver_webhook_action
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt
from apps.actions.webhook_retry import compute_retry_delay_seconds

logger = logging.getLogger(__name__)

_DISPATCH_EXECUTOR: ThreadPoolExecutor | None = None


def _max_attempts() -> int:
    return int(getattr(settings, 'ACTIONS_OUTBOX_MAX_ATTEMPTS', 8))


def _backoff_seconds(attempt_number: int) -> int:
    return min(3600, 30 * (2 ** max(0, attempt_number - 1)))


def backoff_seconds(attempt_number: int) -> int:
    """Public helper for tests and docs."""
    return _backoff_seconds(attempt_number)


def _lease_seconds() -> int:
    return int(getattr(settings, 'ACTIONS_WEBHOOK_RETRY_LEASE_SECONDS', 120))


def _dispatch_executor() -> ThreadPoolExecutor:
    global _DISPATCH_EXECUTOR
    if _DISPATCH_EXECUTOR is None:
        workers = int(getattr(settings, 'ACTIONS_WEBHOOK_DISPATCH_WORKERS', 4))
        _DISPATCH_EXECUTOR = ThreadPoolExecutor(
            max_workers=max(1, workers),
            thread_name_prefix='webhook-dispatch',
        )
    return _DISPATCH_EXECUTOR


def _format_attempt_error(
    *,
    error_message: str,
    http_status: int | None,
    response_excerpt: str,
) -> str:
    parts = [error_message.strip() or 'Delivery failed.']
    if http_status is not None:
        parts.append(f'HTTP {http_status}')
    if response_excerpt:
        parts.append(f'body: {response_excerpt[:512]}')
    return ' | '.join(parts)


def _load_rule_for_delivery(row: ActionOutbox) -> tuple[ActionRule | None, str | None]:
    if row.action_rule_id is None:
        return None, 'Action rule deleted.'
    try:
        rule = row.action_rule
    except ActionRule.DoesNotExist:
        return None, 'Action rule deleted.'
    if not rule.enabled:
        return None, 'Action rule disabled.'
    if rule.action_kind != ActionRule.ACTION_WEBHOOK:
        return None, 'Unsupported action kind (webhook only).'
    return rule, None


def _perform_http_delivery(*, rule: ActionRule, envelope: dict, attempt_number: int) -> tuple[bool, dict]:
    started = time.monotonic()
    http_status = None
    response_excerpt = ''
    error_message = ''
    success = False
    permanent = False
    retry_after_seconds = None
    try:
        deliver_webhook_action(
            config=rule.config or {},
            envelope=envelope,
            attempt_number=attempt_number,
        )
        success = True
    except WebhookDeliveryError as exc:
        error_message = str(exc)
        http_status = exc.http_status
        response_excerpt = exc.response_excerpt or ''
        permanent = exc.permanent
        retry_after_seconds = exc.retry_after_seconds
    except Exception as exc:  # noqa: BLE001
        error_message = str(exc) or exc.__class__.__name__
        logger.exception('Webhook delivery failed')
    duration_ms = int((time.monotonic() - started) * 1000)
    return success, {
        'http_status': http_status,
        'response_excerpt': response_excerpt,
        'error_message': error_message,
        'permanent': permanent,
        'retry_after_seconds': retry_after_seconds,
        'duration_ms': duration_ms,
    }


def _apply_delivery_result(
    row: ActionOutbox,
    *,
    rule: ActionRule | None,
    terminal_error: str | None,
    success: bool,
    attempt_meta: dict,
) -> ActionOutbox:
    attempt_number = row.attempt_count + 1
    if terminal_error:
        attempt_error = terminal_error
        success = False
        permanent = True
        http_status = None
        duration_ms = None
    else:
        http_status = attempt_meta.get('http_status')
        duration_ms = attempt_meta.get('duration_ms')
        attempt_error = _format_attempt_error(
            error_message=attempt_meta.get('error_message') or '',
            http_status=http_status,
            response_excerpt=attempt_meta.get('response_excerpt') or '',
        )
        permanent = bool(attempt_meta.get('permanent'))

    DeliveryAttempt.objects.create(
        outbox=row,
        status=DeliveryAttempt.STATUS_SUCCESS if success else DeliveryAttempt.STATUS_FAILURE,
        http_status=http_status,
        error_message='' if success else attempt_error,
        attempt_number=attempt_number,
        duration_ms=duration_ms,
    )
    channel = 'email_event' if is_email_outbox(row) else 'webhook_delivery'
    logger.info(
        '%s outbox_id=%s attempt=%s success=%s http_status=%s duration_ms=%s',
        channel,
        row.pk,
        attempt_number,
        success,
        http_status,
        duration_ms,
    )

    row.attempt_count = attempt_number
    row.locked_until = None
    if success:
        row.status = ActionOutbox.STATUS_DELIVERED
        row.delivered_at = timezone.now()
        row.last_error = ''
        row.next_attempt_at = None
    elif permanent or attempt_number >= _max_attempts():
        row.status = ActionOutbox.STATUS_DEAD
        row.last_error = attempt_error
        row.next_attempt_at = None
    else:
        row.status = ActionOutbox.STATUS_FAILED
        row.last_error = attempt_error
        delay = compute_retry_delay_seconds(
            attempt_number=attempt_number,
            http_status=http_status,
            retry_after_seconds=attempt_meta.get('retry_after_seconds'),
            base_backoff_seconds=_backoff_seconds(attempt_number),
        )
        row.next_attempt_at = timezone.now() + timedelta(seconds=delay)
    row.save(
        update_fields=[
            'status',
            'attempt_count',
            'last_error',
            'next_attempt_at',
            'delivered_at',
            'locked_until',
            'updated_at',
        ]
    )
    return row


def deliver_outbox_row(outbox_id) -> ActionOutbox | None:
    with transaction.atomic():
        row = (
            ActionOutbox.objects.select_for_update()
            .select_related('action_rule')
            .filter(pk=outbox_id)
            .first()
        )
        if row is None:
            return None
        if row.status == ActionOutbox.STATUS_DELIVERED:
            return row
        if row.status == ActionOutbox.STATUS_DEAD:
            return row
        email_body = email_event_body(row)
        if email_body is not None:
            rule = None
            terminal_error = None if email_service_configured() else 'Email service is not configured.'
        else:
            rule, terminal_error = _load_rule_for_delivery(row)
        envelope = row.envelope
        snapshot_attempt = row.attempt_count

    if row.status == ActionOutbox.STATUS_DELIVERED or row.status == ActionOutbox.STATUS_DEAD:
        return row

    if terminal_error:
        with transaction.atomic():
            row = ActionOutbox.objects.select_for_update().get(pk=outbox_id)
            if row.attempt_count != snapshot_attempt:
                return row
            return _apply_delivery_result(
                row,
                rule=rule,
                terminal_error=terminal_error,
                success=False,
                attempt_meta={},
            )

    if email_body is not None:
        success, attempt_meta = deliver_email_event(email_body)
    else:
        success, attempt_meta = _perform_http_delivery(
            rule=rule,
            envelope=envelope,
            attempt_number=snapshot_attempt + 1,
        )

    with transaction.atomic():
        row = ActionOutbox.objects.select_for_update().get(pk=outbox_id)
        if row.attempt_count != snapshot_attempt:
            return row
        return _apply_delivery_result(
            row,
            rule=rule,
            terminal_error=None,
            success=success,
            attempt_meta=attempt_meta,
        )


def _safe_deliver_outbox_row(outbox_id) -> None:
    connection.close()
    try:
        deliver_outbox_row(outbox_id)
    except Exception:  # noqa: BLE001
        logger.exception('Post-commit outbox delivery error outbox_id=%s', outbox_id)


def schedule_outbox_delivery(outbox_ids: list) -> None:
    if not outbox_ids:
        return

    def _run() -> None:
        if getattr(settings, 'ACTIONS_WEBHOOK_SYNC_DELIVERY', False):
            for oid in outbox_ids:
                _safe_deliver_outbox_row(oid)
            return
        executor = _dispatch_executor()
        for oid in outbox_ids:
            executor.submit(_safe_deliver_outbox_row, oid)

    transaction.on_commit(_run)


def _pending_outbox_filter(now):
    return (
        ActionOutbox.objects.filter(
            status__in=[ActionOutbox.STATUS_PENDING, ActionOutbox.STATUS_FAILED],
        )
        .filter(Q(next_attempt_at__isnull=True) | Q(next_attempt_at__lte=now))
        .filter(Q(locked_until__isnull=True) | Q(locked_until__lte=now))
    )


def claim_next_pending_outbox(*, now=None) -> ActionOutbox | None:
    """Claim one retryable row with skip-locked and a short lease."""
    now = now or timezone.now()
    lease_until = now + timedelta(seconds=_lease_seconds())
    with transaction.atomic():
        row = (
            _pending_outbox_filter(now)
            .select_for_update(skip_locked=True)
            .select_related('action_rule')
            .order_by('next_attempt_at', 'created_at')
            .first()
        )
        if row is None:
            return None
        row.locked_until = lease_until
        row.save(update_fields=['locked_until', 'updated_at'])
        return row


def _summarize_delivery_result(before_status: str, after: ActionOutbox | None) -> dict[str, int]:
    delta = {'processed': 0, 'delivered': 0, 'retried': 0, 'dead': 0}
    if after is None:
        return delta
    delta['processed'] = 1
    if after.status == ActionOutbox.STATUS_DELIVERED:
        delta['delivered'] = 1
    elif after.status == ActionOutbox.STATUS_DEAD:
        delta['dead'] = 1
    elif after.status == ActionOutbox.STATUS_FAILED:
        delta['retried'] = 1
    elif before_status in (ActionOutbox.STATUS_PENDING, ActionOutbox.STATUS_FAILED):
        delta['retried'] = 1
    return delta


def retry_pending_webhooks(
    *,
    batch_size: int = 50,
    max_seconds: float = 50.0,
    concurrency: int = 4,
    dry_run: bool = False,
    now=None,
) -> dict[str, int]:
    """
    Process a bounded batch of pending/failed webhook deliveries.

    HTTP runs outside DB transactions. Safe for overlapping cron runs via skip-locked + lease.
    """
    from concurrent.futures import FIRST_COMPLETED, wait

    now = now or timezone.now()
    stats = {'processed': 0, 'delivered': 0, 'retried': 0, 'dead': 0}
    deadline = time.monotonic() + max(0.1, float(max_seconds))
    workers = max(1, int(concurrency))
    in_flight: set = set()

    def _worker(row_id, before_status: str) -> dict[str, int]:
        connection.close()
        after = deliver_outbox_row(row_id)
        return _summarize_delivery_result(before_status, after)

    def _merge(delta: dict[str, int]) -> None:
        for key in stats:
            stats[key] += delta.get(key, 0)

    use_pool = workers > 1
    executor = (
        ThreadPoolExecutor(max_workers=workers, thread_name_prefix='webhook-retry')
        if use_pool
        else None
    )

    try:
        while stats['processed'] < batch_size and time.monotonic() < deadline:
            if len(in_flight) >= workers:
                done, in_flight = wait(in_flight, timeout=0.05, return_when=FIRST_COMPLETED)
                for fut in done:
                    _merge(fut.result())
                continue

            row = claim_next_pending_outbox(now=now)
            if row is None:
                if in_flight:
                    done, in_flight = wait(
                        in_flight,
                        timeout=max(0.0, deadline - time.monotonic()),
                        return_when=FIRST_COMPLETED,
                    )
                    for fut in done:
                        _merge(fut.result())
                    continue
                break

            before_status = row.status
            if dry_run:
                stats['processed'] += 1
                ActionOutbox.objects.filter(pk=row.pk).update(locked_until=None)
                continue

            if not use_pool:
                _merge(_worker(row.pk, before_status))
                continue

            fut = executor.submit(_worker, row.pk, before_status)
            in_flight.add(fut)

        while in_flight and time.monotonic() < deadline + 1.0:
            done, in_flight = wait(in_flight, timeout=max(0.0, deadline - time.monotonic()))
            for fut in done:
                _merge(fut.result())
            if not done and in_flight:
                break
    finally:
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=False)
        connection.close()

    return stats
