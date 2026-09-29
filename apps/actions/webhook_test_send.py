"""Send a sample webhook payload for an action rule (admin test)."""

from __future__ import annotations

from apps.actions.company import company_context_from_id
from apps.actions.envelope import build_envelope
from apps.actions.handlers.webhook import deliver_webhook_action
from apps.actions.registry import get_event_type
from apps.actions.sample_data import payload_data_from_event


def _sample_data(event_type: str) -> dict:
    event = get_event_type(event_type)
    return payload_data_from_event(event, unique_values=True)


def send_webhook_test_for_rule(*, rule, company_id: int) -> dict:
    envelope = build_envelope(
        event_type=rule.event_type,
        company=company_context_from_id(company_id),
        data=_sample_data(rule.event_type),
    )
    deliver_webhook_action(config=rule.config or {}, envelope=envelope)
    return {'ok': True, 'webhook_id': envelope['id'], 'event_type': rule.event_type}
