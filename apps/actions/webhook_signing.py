"""Standard Webhooks-style HMAC signing for outbound payloads."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import time
import uuid


def generate_webhook_signing_secret(*, num_bytes: int = 32) -> str:
    """Return a ``whsec_<base64>`` secret suitable for new webhook rules."""
    raw = secrets.token_bytes(num_bytes)
    encoded = base64.b64encode(raw).decode('ascii')
    return f'whsec_{encoded}'


def webhook_hmac_key(secret: str) -> bytes:
    """
    Resolve HMAC key from a stored secret.

    ``whsec_<base64>`` decodes the suffix (Standard Webhooks style). Plain strings
    use UTF-8 bytes as the key.
    """
    s = (secret or '').strip()
    if not s:
        raise ValueError('Webhook signing secret is empty.')
    if s.startswith('whsec_'):
        payload = s[6:]
        pad = (-len(payload)) % 4
        try:
            return base64.b64decode(payload + ('=' * pad), validate=False)
        except (ValueError, binascii.Error) as exc:  # noqa: PERF203
            raise ValueError('Invalid whsec_ signing secret.') from exc
    return s.encode('utf-8')


def sign_webhook_body(*, secret: str, body: bytes, webhook_id: str | None = None) -> dict[str, str]:
    """
    Return headers: ``webhook-id``, ``webhook-timestamp``, ``webhook-signature``.

    ``webhook-id`` is stable across retries when ``webhook_id`` matches envelope ``id``.
    Signature format: ``v1,<base64(hmac_sha256)>`` over ``{id}.{timestamp}.{body}``.
    """
    wid = webhook_id or str(uuid.uuid4())
    ts = str(int(time.time()))
    signed_content = f'{wid}.{ts}.'.encode('utf-8') + body
    key = webhook_hmac_key(secret)
    digest = hmac.new(key, signed_content, hashlib.sha256).digest()
    sig = base64.b64encode(digest).decode('ascii')
    return {
        'webhook-id': wid,
        'webhook-timestamp': ts,
        'webhook-signature': f'v1,{sig}',
    }
