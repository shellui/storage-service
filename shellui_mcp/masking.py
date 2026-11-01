"""Redact secrets and personal data from MCP tool arguments and responses."""

from __future__ import annotations

import re
from typing import Any

_SECRET_KEY_RE = re.compile(
    r'(password|secret|token|authorization|api[_-]?key|private[_-]?key|credential|magic[_-]?link)',
    re.I,
)
_EMAIL_RE = re.compile(r'[^@]+@[^@]+\.[^@]+')
_REDACTED = '[redacted]'


def _node_for_key(markers: dict[str, Any], key: str) -> dict[str, Any]:
    node = markers.get(key)
    if isinstance(node, dict):
        return node
    return {'secret': False, 'sensitive': False, 'children': {}}


def _should_redact_key(
    key: str,
    *,
    read_sensitive: bool,
    node: dict[str, Any],
) -> bool:
    if str(key).endswith('_hint'):
        return True
    if node.get('secret'):
        return True
    if _SECRET_KEY_RE.search(str(key)):
        return True
    if not read_sensitive and node.get('sensitive'):
        return True
    return False


def _redact_scalar(key: str, value: Any, *, read_sensitive: bool, node: dict[str, Any]) -> Any:
    if _should_redact_key(key, read_sensitive=read_sensitive, node=node):
        return _REDACTED
    if not read_sensitive and isinstance(value, str) and _EMAIL_RE.search(value):
        return _REDACTED
    return value


def _redact_value(
    key: str,
    value: Any,
    *,
    read_sensitive: bool,
    markers: dict[str, Any],
) -> Any:
    node = _node_for_key(markers, key)
    if isinstance(value, dict):
        return redact_mapping(value, read_sensitive=read_sensitive, markers=node.get('children') or {})
    if isinstance(value, list):
        child_markers = node.get('children') or {}
        return [
            _redact_value(key, item, read_sensitive=read_sensitive, markers=child_markers) for item in value
        ]
    return _redact_scalar(key, value, read_sensitive=read_sensitive, node=node)


def redact_mapping(
    data: dict[str, Any] | None,
    *,
    read_sensitive: bool,
    markers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not data:
        return {}
    field_markers = markers or {}
    out: dict[str, Any] = {}
    for key, value in data.items():
        out[key] = _redact_value(str(key), value, read_sensitive=read_sensitive, markers=field_markers)
    return out
