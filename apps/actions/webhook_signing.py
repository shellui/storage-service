"""Standard Webhooks-style HMAC signing for outbound payloads."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
import uuid


def sign_webhook_body(*, secret: str, body: bytes, webhook_id: str | None = None) -> dict[str, str]:
    wid = webhook_id or str(uuid.uuid4())
    ts = str(int(time.time()))
    signed_content = f'{wid}.{ts}.'.encode('utf-8') + body
    digest = hmac.new(secret.encode('utf-8'), signed_content, hashlib.sha256).digest()
    sig = base64.b64encode(digest).decode('ascii')
    return {
        'webhook-id': wid,
        'webhook-timestamp': ts,
        'webhook-signature': f'v1,{sig}',
    }
