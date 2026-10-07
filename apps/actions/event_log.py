"""Write catalog events to the ``EventLog`` table."""

from __future__ import annotations

from typing import Any

from apps.actions.models import EventLog
from apps.actions.secret_redaction import redact_secrets

_EMPTY = (None, '', [], {})

# Stored in their own columns (or implied by the row), so not repeated in ``data``.
_SKIP = frozenset({'company_id', 'user_id'})


def compact_event_data(payload: dict[str, Any], actor: dict[str, Any] | None = None) -> dict[str, Any]:
    """Payload as stored in the log: no empty values, no ids kept in columns, plus the actor email."""
    raw = {k: v for k, v in payload.items() if k not in _SKIP and v not in _EMPTY and v is not False}
    cleaned = redact_secrets(raw)
    data = cleaned if isinstance(cleaned, dict) else {}
    email = (actor or {}).get('email')
    if email:
        data['actor_email'] = email
    return data


def _actor_user_id(actor: dict[str, Any] | None) -> int | None:
    raw = (actor or {}).get('user_id')
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        return None
    return raw


def record_event(
    event_type: str,
    company_id: int,
    payload: dict[str, Any],
    *,
    actor: dict[str, Any] | None = None,
) -> EventLog:
    return EventLog.objects.create(
        company_id=int(company_id),
        user_id=_actor_user_id(actor),
        event_type=event_type,
        data=compact_event_data(payload, actor),
    )
