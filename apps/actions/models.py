from __future__ import annotations

import uuid

from django.db import models
from django.utils import timezone

from apps.actions.registry import event_choices


def _event_type_field_choices():
    from apps.actions import storage_events  # noqa: F401

    return event_choices()


class ActionRule(models.Model):
    ACTION_WEBHOOK = 'webhook'
    ACTION_KIND_CHOICES = [
        (ACTION_WEBHOOK, 'Webhook'),
    ]

    company_id = models.PositiveIntegerField(db_index=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    event_type = models.CharField(max_length=128, choices=_event_type_field_choices)
    enabled = models.BooleanField(default=True)
    action_kind = models.CharField(
        max_length=16,
        choices=ACTION_KIND_CHOICES,
        default=ACTION_WEBHOOK,
    )
    config = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['company_id', 'event_type', 'name']
        indexes = [
            models.Index(fields=['company_id', 'event_type', 'enabled']),
        ]

    def __str__(self) -> str:
        return f'{self.company_id}:{self.event_type}:{self.name}'


class ActionOutbox(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_DELIVERED = 'delivered'
    STATUS_FAILED = 'failed'
    STATUS_DEAD = 'dead'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_DELIVERED, 'Delivered'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_DEAD, 'Dead'),
    ]

    KIND_WEBHOOK = 'webhook'
    KIND_EMAIL = 'email'
    KIND_CHOICES = [
        (KIND_WEBHOOK, 'Webhook'),
        (KIND_EMAIL, 'Email'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company_id = models.PositiveIntegerField(db_index=True)
    action_rule = models.ForeignKey(
        ActionRule,
        on_delete=models.CASCADE,
        related_name='outbox_rows',
        null=True,
        blank=True,
    )
    delivery_kind = models.CharField(
        max_length=16,
        choices=KIND_CHOICES,
        default=KIND_WEBHOOK,
        db_index=True,
    )
    event_type = models.CharField(max_length=128)
    envelope = models.JSONField()
    status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
        db_index=True,
    )
    attempt_count = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True, db_index=True)
    locked_until = models.DateTimeField(null=True, blank=True, db_index=True)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = 'Action delivery'
        verbose_name_plural = 'Action deliveries'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'next_attempt_at']),
        ]

    def __str__(self) -> str:
        target = self.action_rule_id if self.action_rule_id else self.delivery_kind
        return f'{self.event_type} → {target} ({self.status})'


class DeliveryAttempt(models.Model):
    STATUS_SUCCESS = 'success'
    STATUS_FAILURE = 'failure'
    STATUS_CHOICES = [
        (STATUS_SUCCESS, 'Success'),
        (STATUS_FAILURE, 'Failure'),
    ]

    outbox = models.ForeignKey(
        ActionOutbox,
        on_delete=models.CASCADE,
        related_name='delivery_attempts',
    )
    status = models.CharField(max_length=16, choices=STATUS_CHOICES)
    http_status = models.PositiveIntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    attempt_number = models.PositiveIntegerField()
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    # ``dispatch``: first try right after the event. ``automatic_retry``: retry_webhooks job.
    trigger = models.CharField(
        max_length=16,
        choices=[
            ('dispatch', 'Dispatch'),
            ('automatic_retry', 'Automatic retry'),
        ],
        blank=True,
    )
    # ``ScheduledJobRun`` that made this attempt (staff only in the API; no FK, runs are purged first).
    scheduled_job_run_id = models.BigIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    TRIGGER_DISPATCH = 'dispatch'
    TRIGGER_AUTOMATIC_RETRY = 'automatic_retry'

    class Meta:
        verbose_name = 'Delivery attempt'
        verbose_name_plural = 'Delivery attempts'
        ordering = ['-created_at']
        indexes = [
            models.Index(
                fields=['scheduled_job_run_id'],
                name='actions_attempt_sjrun_idx',
                condition=models.Q(scheduled_job_run_id__isnull=False),
            ),
        ]

    def __str__(self) -> str:
        return f'attempt {self.attempt_number} ({self.status})'


class EventLog(models.Model):
    """
    One row per catalog event, written whether or not a webhook rule matches.

    Kept small on purpose: ids instead of foreign keys (users and companies live in identity-service),
    a compact JSON payload, and only the two indexes the admin list needs.
    """

    id = models.BigAutoField(primary_key=True)
    # Null for staff-only platform events (``storage.scheduled_job.*``).
    company_id = models.PositiveIntegerField(null=True, blank=True)
    user_id = models.PositiveIntegerField(null=True, blank=True)
    event_type = models.CharField(max_length=64)
    data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = 'Event log entry'
        verbose_name_plural = 'Event log'
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['company_id', '-created_at'], name='actions_eventlog_company_idx'),
            models.Index(fields=['company_id', 'user_id', '-created_at'], name='actions_eventlog_user_idx'),
        ]

    def __str__(self) -> str:
        return f'{self.event_type} @ {self.created_at:%Y-%m-%d %H:%M:%S}'


class ScheduledJobRun(models.Model):
    """
    One run of a scheduled job (``retry_webhooks``, ``purge_expired_data``).

    Written by the management command itself, so runs started by the in-container Celery
    beat and by an external scheduler are both recorded. Skipped runs (another run held the
    lock) are not stored: they only increment a counter (see ``ScheduledJobCounter``).
    ``purge_expired_data`` deletes rows older than ``scheduled_jobs.RUN_RETENTION_DAYS``.
    """

    TRIGGER_CELERY = 'celery'
    TRIGGER_COMMAND = 'command'
    TRIGGER_CHOICES = [
        (TRIGGER_CELERY, 'Celery beat'),
        (TRIGGER_COMMAND, 'Management command'),
    ]

    STATUS_RUNNING = 'running'
    STATUS_SUCCEEDED = 'succeeded'
    STATUS_FAILED = 'failed'
    STATUS_SKIPPED_LOCKED = 'skipped_locked'
    STATUS_CHOICES = [
        (STATUS_RUNNING, 'Running'),
        (STATUS_SUCCEEDED, 'Succeeded'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_SKIPPED_LOCKED, 'Skipped (lock held)'),
    ]

    id = models.BigAutoField(primary_key=True)
    job = models.CharField(max_length=64)
    trigger = models.CharField(max_length=16, choices=TRIGGER_CHOICES)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_RUNNING)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    counts = models.JSONField(default=dict, blank=True)
    error_key = models.CharField(max_length=32, blank=True)
    error_class = models.CharField(max_length=128, blank=True)
    error_message = models.CharField(max_length=300, blank=True)
    host = models.CharField(max_length=128, blank=True)
    event_log_id = models.BigIntegerField(null=True, blank=True)

    class Meta:
        verbose_name = 'Scheduled job run'
        verbose_name_plural = 'Scheduled job runs'
        ordering = ['-started_at', '-id']
        indexes = [
            models.Index(fields=['job', '-started_at'], name='actions_sjrun_job_idx'),
            models.Index(fields=['started_at'], name='actions_sjrun_started_idx'),
        ]

    def __str__(self) -> str:
        return f'{self.job} #{self.pk} ({self.status})'

    @property
    def request_id(self) -> str:
        """Log correlation id used while the run executes (``[req=…]`` in log lines)."""
        return f'sjr-{self.pk}'


class ScheduledJobState(models.Model):
    """Latest timestamps per job. Survives run retention, so ``last_success_at`` is never lost."""

    job = models.CharField(max_length=64, primary_key=True)
    created_at = models.DateTimeField(default=timezone.now)
    last_started_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    last_failure_at = models.DateTimeField(null=True, blank=True)
    last_skipped_at = models.DateTimeField(null=True, blank=True)
    last_duration_ms = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        verbose_name = 'Scheduled job state'
        verbose_name_plural = 'Scheduled job states'

    def __str__(self) -> str:
        return self.job


class ScheduledJobCounter(models.Model):
    """
    Monotonic counters for Prometheus (``runs.<status>``, ``items.<kind>``).

    Stored in the database because runs happen in the Celery worker or an external scheduler,
    while ``/storage/v1/metrics/all`` is served by gunicorn workers.
    """

    job = models.CharField(max_length=64)
    name = models.CharField(max_length=64)
    value = models.BigIntegerField(default=0)

    class Meta:
        verbose_name = 'Scheduled job counter'
        verbose_name_plural = 'Scheduled job counters'
        constraints = [
            models.UniqueConstraint(fields=['job', 'name'], name='actions_sjcounter_job_name_uniq'),
        ]

    def __str__(self) -> str:
        return f'{self.job}:{self.name}={self.value}'
