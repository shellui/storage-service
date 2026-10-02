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

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company_id = models.PositiveIntegerField(db_index=True)
    action_rule = models.ForeignKey(
        ActionRule,
        on_delete=models.CASCADE,
        related_name='outbox_rows',
        null=True,
        blank=True,
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
        if self.action_rule_id:
            return f'{self.event_type} → rule {self.action_rule_id} ({self.status})'
        return f'{self.event_type} → email-service ({self.status})'


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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Delivery attempt'
        verbose_name_plural = 'Delivery attempts'
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f'attempt {self.attempt_number} ({self.status})'


class EventLog(models.Model):
    """
    One row per catalog event, written whether or not a webhook rule matches.

    Kept small on purpose: ids instead of foreign keys (users and companies live in identity-service),
    a compact JSON payload, and only the two indexes the admin list needs.
    """

    id = models.BigAutoField(primary_key=True)
    company_id = models.PositiveIntegerField()
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
