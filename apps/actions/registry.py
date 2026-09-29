"""In-code catalog of domain events (stable ids, labels, payload documentation)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EventFieldDoc:
    name: str
    description: str
    example: Any = None


@dataclass(frozen=True)
class DomainEventType:
    id: str
    label: str
    description: str
    payload_fields: tuple[EventFieldDoc, ...] = ()
    emit_by_default: bool = True


_REGISTRY: dict[str, DomainEventType] = {}


def register_event(event: DomainEventType) -> DomainEventType:
    if event.id in _REGISTRY:
        raise ValueError(f'Duplicate event type registration: {event.id!r}')
    _REGISTRY[event.id] = event
    return event


def get_event_type(event_id: str) -> DomainEventType:
    try:
        return _REGISTRY[event_id]
    except KeyError as exc:
        raise ValueError(f'Unknown event type: {event_id!r}') from exc


def is_registered_event(event_id: str) -> bool:
    return event_id in _REGISTRY


def all_event_types() -> list[DomainEventType]:
    return sorted(_REGISTRY.values(), key=lambda e: e.id)


def event_field_doc_dict(field: EventFieldDoc) -> dict:
    return {
        'name': field.name,
        'description': field.description,
        'example': field.example,
    }


def event_choices() -> list[tuple[str, str]]:
    return [
        (
            e.id,
            f'{e.label} ({e.id})'
            + (' — not emitted yet' if not e.emit_by_default else ''),
        )
        for e in all_event_types()
    ]
