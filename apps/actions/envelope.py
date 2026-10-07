"""CloudEvents-inspired JSON envelope for outbound webhooks."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from django.utils import timezone

from apps.actions.company import CompanyContext
from apps.actions.secret_redaction import redact_secrets


def build_envelope(
    *,
    event_type: str,
    company: CompanyContext,
    data: dict[str, Any],
    actor: dict[str, Any] | None = None,
    event_id: uuid.UUID | None = None,
    occurred_at: datetime | None = None,
) -> dict[str, Any]:
    cleaned = redact_secrets(dict(data))
    envelope: dict[str, Any] = {
        'id': str(event_id or uuid.uuid4()),
        'type': event_type,
        'time': (occurred_at or timezone.now()).isoformat(),
        'company': {'id': company.id, 'slug': company.slug, 'name': company.name},
        'data': cleaned if isinstance(cleaned, dict) else {},
    }
    if actor:
        cleaned_actor = redact_secrets(dict(actor))
        if isinstance(cleaned_actor, dict) and cleaned_actor:
            envelope['actor'] = cleaned_actor
    return envelope
