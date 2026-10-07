"""Forward catalog events to email-service ``POST /api/v1/events``.

Callers (identity, storage, hosting) use the same module name and settings:

- ``EMAIL_SERVICE_URL``: origin only. Default ``https://email.shellui.com``.
- ``EMAIL_SERVICE_API_KEY``: service key, prefix ``esk_``. Empty disables forwarding.

This service sends ``service`` = ``storage``. The HTTP call runs from the existing
action outbox, after commit, and ``retry_webhooks`` retries failures.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from typing import Any

import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from apps.actions.webhook_retry import is_permanent_http_status, parse_retry_after_header
from config.request_context import request_id_var

logger = logging.getLogger(__name__)

SERVICE_NAME = 'storage'
EVENTS_PATH = '/api/v1/events'
_DEFAULT_ORIGIN = 'https://email.shellui.com'
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_REDACTED = '[redacted]'

# Webhook envelopes keep the original payload (same as hosting-service). Only the
# email body drops sign-in links and tokens.
_SENSITIVE_KEYS = frozenset({
    'magic_link',
    'magic_link_url',
    'token',
    'raw_token',
    'access_token',
    'refresh_token',
    'id_token',
    'sign_in_url',
    'sign_in_link',
    'signin_url',
    'signin_link',
})
_SIGN_IN_URL = re.compile(
    r'magic[-_]link|/sign-?in(?:[/?#]|$)|[?&#]token=',
    re.IGNORECASE,
)


def email_service_api_key() -> str:
    return (getattr(settings, 'EMAIL_SERVICE_API_KEY', '') or '').strip()


def email_service_configured() -> bool:
    """True only when a service key with the ``esk_`` prefix is set."""
    return email_service_api_key().startswith('esk_')


def email_service_origin() -> str:
    raw = (getattr(settings, 'EMAIL_SERVICE_URL', '') or '').strip().rstrip('/')
    return raw or _DEFAULT_ORIGIN


def email_events_url() -> str:
    return f'{email_service_origin()}{EVENTS_PATH}'


def redact_email_service_secret(value: str) -> str:
    """Remove the API key from text that might be logged or stored."""
    key = email_service_api_key()
    if not key or not isinstance(value, str) or key not in value:
        return value
    return value.replace(key, _REDACTED)


def _scrub_value(value: Any, key: str) -> Any:
    if isinstance(value, str) and key in value:
        return value.replace(key, _REDACTED)
    return value


class RedactEmailServiceApiKeyFilter(logging.Filter):
    """Drop ``EMAIL_SERVICE_API_KEY`` from log records before they are emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            key = email_service_api_key()
        except ImproperlyConfigured:
            return True
        if not key:
            return True
        record.msg = _scrub_value(record.msg, key)
        if isinstance(record.args, dict):
            record.args = {name: _scrub_value(item, key) for name, item in record.args.items()}
        elif isinstance(record.args, tuple):
            record.args = tuple(_scrub_value(item, key) for item in record.args)
        if isinstance(record.exc_text, str):
            record.exc_text = _scrub_value(record.exc_text, key)
        return True


class RedactEmailServiceApiKeyFormatter(logging.Formatter):
    """Redact the API key from the formatted line, including tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_email_service_secret(super().format(record))


def recipient_hints(actor: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Actor email and user id, the contract's default ``hints`` recipients."""
    if not actor:
        return []
    email = str(actor.get('email') or '').strip()
    if not _EMAIL_RE.match(email):
        return []
    hint: dict[str, Any] = {'email': email}
    raw_user_id = actor.get('user_id')
    if raw_user_id not in (None, ''):
        try:
            hint['user_id'] = int(raw_user_id)
        except (TypeError, ValueError):
            pass
    return [hint]


def _sensitive_key(key: str) -> bool:
    name = str(key).strip().lower().replace('-', '_')
    return name in _SENSITIVE_KEYS or name.endswith('_token') or name.endswith('_tokens')


def _sensitive_string(value: str) -> bool:
    """True when a string is a sign-in URL or carries a token query parameter."""
    if '://' not in value:
        return False
    return _SIGN_IN_URL.search(value) is not None


class _Drop:
    """Sentinel for a string that must not appear in the email body."""


_DROP = _Drop()


def email_event_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Event data for email-service. Sign-in links and tokens are omitted."""
    return _without_secrets(payload or {})


def _without_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if _sensitive_key(str(key)):
                continue
            kept = _without_secrets(item)
            if kept is _DROP:
                continue
            cleaned[str(key)] = kept
        return cleaned
    if isinstance(value, list):
        items = []
        for item in value:
            kept = _without_secrets(item)
            if kept is _DROP:
                continue
            items.append(kept)
        return items
    if isinstance(value, str) and _sensitive_string(value):
        return _DROP
    return value


def build_email_event_body(
    *,
    event_type: str,
    company_id: int,
    payload: dict[str, Any],
    idempotency_key: str,
    actor: dict[str, Any] | None = None,
    company: Any | None = None,
) -> dict[str, Any]:
    """Stable ``POST /api/v1/events`` body. Retries must send this object unchanged."""
    data = email_event_payload(payload)
    company_name = (getattr(company, 'name', '') or '').strip()
    if company_name and not str(data.get('company_name') or '').strip():
        data['company_name'] = company_name
    return {
        'service': SERVICE_NAME,
        'event_type': event_type,
        'company_id': int(company_id),
        'idempotency_key': idempotency_key,
        'payload': data,
        'recipients': recipient_hints(actor),
    }


def is_email_outbox(row) -> bool:
    return getattr(row, 'delivery_kind', '') == 'email'


def email_event_body(row) -> dict | None:
    if not is_email_outbox(row):
        return None
    return row.envelope if isinstance(row.envelope, dict) else None


def enqueue_email_event(
    event_type: str,
    company_id: int,
    payload: dict[str, Any],
    *,
    actor: dict[str, Any] | None = None,
    company: Any | None = None,
):
    """Write one outbox row. No HTTP. Returns None when email-service is not configured."""
    from apps.actions.models import ActionOutbox

    if not email_service_configured():
        return None
    event_id = uuid.uuid4()
    body = build_email_event_body(
        event_type=event_type,
        company_id=company_id,
        payload=payload,
        idempotency_key=str(event_id),
        actor=actor,
        company=company,
    )
    return ActionOutbox.objects.create(
        id=event_id,
        company_id=int(company_id),
        action_rule=None,
        delivery_kind=ActionOutbox.KIND_EMAIL,
        event_type=event_type,
        envelope=body,
    )


def email_failure_is_permanent(status: int | None, error_code: str = '') -> bool:
    """
    Caller retry table from the email-service integration contract.

    2xx is finished, including ``skipped_reason``. 404, 408, 409, 425, 429, other
    4xx, 5xx, timeouts, and connection errors retry. 400, 401, 403, 405, 410, 413,
    and 422 are permanent. ``error_code`` does not change the decision.
    """
    del error_code
    if status is not None and 200 <= status < 300:
        return False
    return is_permanent_http_status(status)


def _timeout_seconds() -> float:
    return float(getattr(settings, 'ACTIONS_WEBHOOK_TIMEOUT_SECONDS', 5.0))


def _failure_message(status: int | None, error_code: str, detail: str = '') -> str:
    if status is None:
        extra = f' ({detail})' if detail else ''
        return f'Email event request failed{extra}.'
    if error_code:
        return f'Email event was not accepted (HTTP {status}, {error_code}).'
    return f'Email event was not accepted (HTTP {status}).'


def _error_code(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return ''
    if isinstance(payload, dict):
        return str(payload.get('error_code') or '')
    return ''


def _attempt_meta(
    *,
    started: float,
    success: bool,
    http_status: int | None,
    error_message: str,
    permanent: bool,
    retry_after_seconds: int | None,
) -> tuple[bool, dict]:
    return success, {
        'http_status': http_status,
        'response_excerpt': '',
        'error_message': redact_email_service_secret(error_message),
        'permanent': permanent,
        'retry_after_seconds': retry_after_seconds,
        'duration_ms': int((time.monotonic() - started) * 1000),
    }


def deliver_email_event(body: dict) -> tuple[bool, dict]:
    """POST one stored event body. Does not log the API key or the request body."""
    started = time.monotonic()
    key = email_service_api_key()
    if not key.startswith('esk_'):
        return _attempt_meta(
            started=started,
            success=False,
            http_status=None,
            error_message='Email service is not configured.',
            permanent=True,
            retry_after_seconds=None,
        )
    encoded = json.dumps(body, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
    headers = {
        'Authorization': f'Bearer {key}',
        'Content-Type': 'application/json; charset=utf-8',
        'Accept': 'application/json',
        'User-Agent': 'shellui-storage-service/1.0',
    }
    request_id = request_id_var.get()
    if request_id and request_id != '-':
        headers['X-Request-ID'] = request_id
    try:
        response = requests.post(
            email_events_url(),
            data=encoded,
            headers=headers,
            timeout=_timeout_seconds(),
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        detail = redact_email_service_secret(str(exc) or exc.__class__.__name__)
        message = _failure_message(None, '', detail)
        logger.warning('email_event delivery failed: %s', message)
        return _attempt_meta(
            started=started,
            success=False,
            http_status=None,
            error_message=message,
            permanent=False,
            retry_after_seconds=None,
        )
    try:
        status = int(response.status_code)
        if 200 <= status < 300:
            return _attempt_meta(
                started=started,
                success=True,
                http_status=status,
                error_message='',
                permanent=False,
                retry_after_seconds=None,
            )
        error_code = _error_code(response)
        retry_after = None
        if status in (429, 503):
            retry_after = parse_retry_after_header(response.headers.get('Retry-After'))
        return _attempt_meta(
            started=started,
            success=False,
            http_status=status,
            error_message=_failure_message(status, error_code),
            permanent=email_failure_is_permanent(status, error_code),
            retry_after_seconds=retry_after,
        )
    finally:
        response.close()
