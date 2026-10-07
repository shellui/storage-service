"""Single entry point for domain event emission."""

from __future__ import annotations

from typing import Any

from apps.actions.company import CompanyContext, company_context_from_id
from apps.actions.delivery import schedule_outbox_delivery
from apps.actions.email_service import enqueue_email_event
from apps.actions.envelope import build_envelope
from apps.actions.event_log import record_event
from apps.actions.models import ActionOutbox, ActionRule
from apps.actions.registry import get_event_type


def emit_event(
    event_type: str,
    company_id: int,
    payload: dict[str, Any],
    *,
    company: CompanyContext | None = None,
    actor: dict[str, Any] | None = None,
    force: bool = False,
) -> list[ActionOutbox]:
    """
    Validate ``event_type``, record it in the event log, then write outbox rows for enabled
    webhook ``ActionRule`` rows of ``company_id``.

    When ``EMAIL_SERVICE_API_KEY`` is set, also enqueue one email-service row on the same
    outbox. Staff-only platform events are not forwarded. No key means no email row.

    Schedules a best-effort delivery attempt after the surrounding database transaction commits.
    The request thread does not call email-service. Returns webhook rows only.
    """
    event = get_event_type(event_type)
    if not event.emit_by_default and not force:
        return []

    record_event(event_type, company_id, payload, actor=actor)

    ctx = company or company_context_from_id(company_id)

    rules = list(
        ActionRule.objects.filter(
            company_id=int(company_id),
            event_type=event_type,
            enabled=True,
            action_kind=ActionRule.ACTION_WEBHOOK,
        ).order_by('pk')
    )
    outbox_rows: list[ActionOutbox] = []
    if rules:
        envelope = build_envelope(
            event_type=event_type,
            company=ctx,
            data=dict(payload),
            actor=actor,
        )
        for rule in rules:
            outbox_rows.append(
                ActionOutbox.objects.create(
                    company_id=int(company_id),
                    action_rule=rule,
                    event_type=event_type,
                    envelope=envelope,
                )
            )
    email_row = None
    if not getattr(event, 'staff_only', False):
        email_row = enqueue_email_event(
            event_type,
            int(company_id),
            payload,
            actor=actor,
            company=ctx,
        )
    delivery_ids = [row.pk for row in outbox_rows]
    if email_row is not None:
        delivery_ids.append(email_row.pk)
    if delivery_ids:
        schedule_outbox_delivery(delivery_ids)
    return outbox_rows


def emit_event_if_rules(
    event_type: str,
    company_id: int,
    payload: dict[str, Any],
    *,
    company: CompanyContext | None = None,
    actor: dict[str, Any] | None = None,
    force: bool = False,
) -> list[ActionOutbox]:
    """Like ``emit_event`` but skips unknown types and swallows errors (for hot paths)."""
    try:
        return emit_event(
            event_type,
            company_id,
            payload,
            company=company,
            actor=actor,
            force=force,
        )
    except ValueError:
        return []
