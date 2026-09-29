from __future__ import annotations

import json
import time

from django.conf import settings

from apps.actions.webhook_signing import sign_webhook_body
from apps.actions.webhook_transport import WebhookHTTPError, post_webhook_url


class WebhookDeliveryError(Exception):
    def __init__(
        self,
        message: str,
        *,
        http_status: int | None = None,
        response_excerpt: str = '',
        permanent: bool = False,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.response_excerpt = response_excerpt
        self.permanent = permanent


def _allow_private_webhook_urls(config: dict) -> bool:
    if getattr(settings, 'ACTIONS_WEBHOOK_ALLOW_PRIVATE', False):
        return True
    return bool(config.get('allow_private_urls'))


def _permanent_http_status(status: int) -> bool:
    if status == 408 or status == 429:
        return False
    return 400 <= status < 500


def deliver_webhook_action(*, config: dict, envelope: dict) -> None:
    url = (config.get('url') or '').strip()
    if not url:
        raise WebhookDeliveryError('Webhook URL is not configured.', permanent=True)
    secret = (config.get('secret') or '').strip()
    if not secret:
        raise WebhookDeliveryError('Webhook signing secret is not configured.', permanent=True)
    allow_private = _allow_private_webhook_urls(config)

    body = json.dumps(envelope, separators=(',', ':'), sort_keys=True).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'shellui-storage-actions/1.0',
        **sign_webhook_body(secret=secret, body=body, webhook_id=envelope.get('id')),
    }
    auth_header = (config.get('authorization_header') or '').strip()
    if auth_header:
        headers['Authorization'] = auth_header

    timeout = float(getattr(settings, 'ACTIONS_WEBHOOK_TIMEOUT_SECONDS', 5.0))
    started = time.monotonic()
    try:
        status, excerpt = post_webhook_url(
            url,
            body=body,
            headers=headers,
            timeout=timeout,
            allow_private=allow_private,
        )
    except WebhookHTTPError as exc:
        permanent = exc.status is None or _permanent_http_status(exc.status)
        raise WebhookDeliveryError(
            str(exc),
            http_status=exc.status,
            response_excerpt=exc.response_excerpt,
            permanent=permanent,
        ) from exc
    except OSError as exc:
        raise WebhookDeliveryError(str(exc)) from exc
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if status >= 400:
        permanent = _permanent_http_status(status)
        raise WebhookDeliveryError(
            f'Webhook returned HTTP {status}',
            http_status=status,
            response_excerpt=excerpt,
            permanent=permanent,
        )
    _ = elapsed_ms
