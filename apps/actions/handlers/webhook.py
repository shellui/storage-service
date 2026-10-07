from __future__ import annotations

import time

from django.conf import settings

from apps.actions.webhook_retry import is_permanent_http_status
from apps.actions.webhook_signing import encode_webhook_envelope, sign_webhook_body
from apps.actions.webhook_transport import WebhookHTTPError, post_webhook_url
from config.request_context import request_id_var


class WebhookDeliveryError(Exception):
    def __init__(
        self,
        message: str,
        *,
        http_status: int | None = None,
        response_excerpt: str = '',
        permanent: bool = False,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.response_excerpt = response_excerpt
        self.permanent = permanent
        self.retry_after_seconds = retry_after_seconds


def _allow_private_webhook_urls(config: dict) -> bool:
    if getattr(settings, 'ACTIONS_WEBHOOK_ALLOW_PRIVATE', False):
        return True
    return bool(config.get('allow_private_urls'))


def deliver_webhook_action(
    *,
    config: dict,
    envelope: dict,
    attempt_number: int = 1,
) -> None:
    url = (config.get('url') or '').strip()
    if not url:
        raise WebhookDeliveryError('Webhook URL is not configured.', permanent=True)
    secret = (config.get('secret') or '').strip()
    if not secret:
        raise WebhookDeliveryError('Webhook signing secret is not configured.', permanent=True)
    allow_private = _allow_private_webhook_urls(config)

    webhook_id = envelope.get('id')
    if not webhook_id:
        raise WebhookDeliveryError('Envelope id is required for webhook delivery.', permanent=True)

    event_type = envelope.get('type') or ''
    body = encode_webhook_envelope(envelope)
    headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'User-Agent': 'shellui-storage-actions/1.0',
        'X-Shellui-Event': event_type,
        'X-Shellui-Delivery-Attempt': str(max(1, int(attempt_number))),
        **sign_webhook_body(secret=secret, body=body, webhook_id=str(webhook_id)),
    }
    # Same id as storage log lines (request id, or ``sjr-<run id>`` inside a scheduled job).
    request_id = request_id_var.get()
    if request_id and request_id != '-':
        headers['X-Request-ID'] = request_id
    auth_header = (config.get('authorization_header') or '').strip()
    if auth_header:
        headers['Authorization'] = auth_header

    timeout = float(getattr(settings, 'ACTIONS_WEBHOOK_TIMEOUT_SECONDS', 5.0))
    started = time.monotonic()
    try:
        result = post_webhook_url(
            url,
            body=body,
            headers=headers,
            timeout=timeout,
            allow_private=allow_private,
        )
    except WebhookHTTPError as exc:
        permanent = exc.permanent or is_permanent_http_status(exc.status)
        raise WebhookDeliveryError(
            str(exc),
            http_status=exc.status,
            response_excerpt=exc.response_excerpt,
            permanent=permanent,
            retry_after_seconds=exc.retry_after_seconds,
        ) from exc
    except OSError as exc:
        raise WebhookDeliveryError(str(exc)) from exc
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if result.status >= 400:
        raise WebhookDeliveryError(
            f'Webhook returned HTTP {result.status}',
            http_status=result.status,
            response_excerpt=result.excerpt,
            permanent=is_permanent_http_status(result.status),
            retry_after_seconds=result.retry_after_seconds,
        )
    _ = elapsed_ms
