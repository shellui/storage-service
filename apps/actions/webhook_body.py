"""Canonical JSON serialization for signed webhook payloads."""

from __future__ import annotations

import json
from typing import Any


def serialize_webhook_envelope(envelope: dict[str, Any]) -> bytes:
    """
    Compact UTF-8 JSON for signing and delivery.

    Verifiers must HMAC the raw request body bytes (not a re-encoded copy).
    """
    return json.dumps(
        envelope,
        separators=(',', ':'),
        sort_keys=True,
        ensure_ascii=False,
    ).encode('utf-8')
