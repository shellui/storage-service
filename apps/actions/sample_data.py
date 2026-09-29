"""Build sample webhook payload ``data`` from event field documentation."""

from __future__ import annotations

import uuid
from typing import Any

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.actions.registry import DomainEventType


def _materialize_example(field_name: str, example: Any, *, unique_values: bool) -> Any:
    if not unique_values:
        return example
    if isinstance(example, str):
        try:
            uuid.UUID(example)
        except ValueError:
            pass
        else:
            return str(uuid.uuid4())
        parsed = parse_datetime(example)
        if parsed is not None:
            return timezone.now().isoformat()
    return example


def payload_data_from_event(event: DomainEventType, *, unique_values: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for field in event.payload_fields:
        if field.example is not None:
            data[field.name] = _materialize_example(field.name, field.example, unique_values=unique_values)
    return data
