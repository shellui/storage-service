"""Redact secrets and personal data from MCP tool arguments and responses."""

from __future__ import annotations

import re
from typing import Any

_SECRET_KEY_RE = re.compile(
    r'(password|secret|token|authorization|api[_-]?key|private[_-]?key|credential|magic[_-]?link)',
    re.I,
)
_EMAIL_RE = re.compile(r'[^@]+@[^@]+\.[^@]+')


def _redact_value(key: str, value: Any, *, read_sensitive: bool) -> Any:
    if isinstance(value, dict):
        return redact_mapping(value, read_sensitive=read_sensitive)
    if isinstance(value, list):
        return [_redact_value(key, item, read_sensitive=read_sensitive) for item in value]
    if _SECRET_KEY_RE.search(key):
        return '[redacted]'
    if not read_sensitive and isinstance(value, str):
        if _EMAIL_RE.search(value):
            return '[redacted]'
    return value


def redact_mapping(data: dict[str, Any] | None, *, read_sensitive: bool) -> dict[str, Any]:
    if not data:
        return {}
    out: dict[str, Any] = {}
    for key, value in data.items():
        out[key] = _redact_value(str(key), value, read_sensitive=read_sensitive)
    return out
