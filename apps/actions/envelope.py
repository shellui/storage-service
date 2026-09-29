"""CloudEvents-inspired JSON envelope for outbound webhooks."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from django.utils import timezone

from apps.actions.company import CompanyContext


def build_envelope(
    *,
    event_type: str,
    company: CompanyContext,
    data: dict[str, Any],
    actor: dict[str, Any] | None = None,
    event_id: uuid.UUID | None = None,
    occurred_at: datetime | None = None,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        'id': str(event_id or uuid.uuid4()),
        'type': event_type,
        'time': (occurred_at or timezone.now()).isoformat(),
        'company': {'id': company.id, 'slug': company.slug, 'name': company.name},
        'data': dict(data),
    }
    if actor:
        envelope['actor'] = dict(actor)
    return envelope
