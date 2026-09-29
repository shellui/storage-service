"""Standard Webhooks-style HMAC signing for outbound payloads."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time


def generate_webhook_signing_secret() -> str:
    """Return a new Standard Webhooks style secret ``whsec_<base64>``."""
    raw = secrets.token_bytes(32)
    return f'whsec_{base64.b64encode(raw).decode("ascii")}'


def normalize_webhook_signing_secret(secret: str) -> bytes:
    """
    HMAC key bytes for signing.

    ``whsec_<base64>`` decodes the suffix (Standard Webhooks). Plain strings use UTF-8 bytes.
    """
    secret = (secret or '').strip()
    if secret.startswith('whsec_'):
        payload = secret[len('whsec_') :].strip()
        if not payload:
            raise ValueError('Webhook signing secret is empty after whsec_ prefix.')
        try:
            key = base64.b64decode(payload, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError('Webhook whsec_ secret is not valid base64.') from exc
        if not key:
            raise ValueError('Webhook whsec_ secret decoded to empty key.')
        return key
    return secret.encode('utf-8')


def encode_webhook_envelope(envelope: dict) -> bytes:
    """Compact UTF-8 JSON body (non-ASCII preserved) for signing and POST."""
    return json.dumps(
        envelope,
        separators=(',', ':'),
        sort_keys=True,
        ensure_ascii=False,
    ).encode('utf-8')


def sign_webhook_body(*, secret: str, body: bytes, webhook_id: str) -> dict[str, str]:
    """
    Return headers: ``webhook-id``, ``webhook-timestamp``, ``webhook-signature``.

    Signature format: ``v1,<base64(hmac_sha256)>`` over ``{id}.{timestamp}.{body}``.
    """
    key = normalize_webhook_signing_secret(secret)
    ts = str(int(time.time()))
    signed_content = f'{webhook_id}.{ts}.'.encode('utf-8') + body
    digest = hmac.new(key, signed_content, hashlib.sha256).digest()
    sig = base64.b64encode(digest).decode('ascii')
    return {
        'webhook-id': webhook_id,
        'webhook-timestamp': ts,
        'webhook-signature': f'v1,{sig}',
    }
