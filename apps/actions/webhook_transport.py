"""HTTP(S) POST to a pre-resolved webhook endpoint (SSRF-safe connect)."""

from __future__ import annotations

import ssl
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse

from apps.actions.ssrf import ResolvedWebhookEndpoint, SSRFError, resolve_webhook_endpoint

_RESPONSE_EXCERPT_MAX = 512


class WebhookHTTPError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        response_excerpt: str = '',
    ) -> None:
        super().__init__(message)
        self.status = status
        self.response_excerpt = response_excerpt


def _read_response_excerpt(response: HTTPResponse) -> str:
    try:
        raw = response.read(_RESPONSE_EXCERPT_MAX + 1)
    except OSError:
        return ''
    if not raw:
        return ''
    text = raw[:_RESPONSE_EXCERPT_MAX].decode('utf-8', errors='replace')
    if len(raw) > _RESPONSE_EXCERPT_MAX:
        text = f'{text}…'
    return text.strip()


def post_resolved_webhook(
    endpoint: ResolvedWebhookEndpoint,
    *,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
) -> tuple[int, str]:
    req_headers = dict(headers)
    req_headers['Host'] = endpoint.host_header
    if endpoint.scheme == 'https':
        context = ssl.create_default_context()
        conn: HTTPConnection | HTTPSConnection = HTTPSConnection(
            endpoint.connect_host,
            endpoint.port,
            timeout=timeout,
            context=context,
            server_hostname=endpoint.host_header.split(':')[0],
        )
    else:
        conn = HTTPConnection(endpoint.connect_host, endpoint.port, timeout=timeout)
    try:
        conn.request('POST', endpoint.path, body=body, headers=req_headers)
        response = conn.getresponse()
        status = int(response.status)
        excerpt = _read_response_excerpt(response)
        return status, excerpt
    finally:
        conn.close()


def post_webhook_url(
    url: str,
    *,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
    allow_private: bool,
) -> tuple[int, str]:
    try:
        endpoint = resolve_webhook_endpoint(url, allow_private=allow_private)
    except SSRFError as exc:
        raise WebhookHTTPError(str(exc)) from exc
    return post_resolved_webhook(endpoint, body=body, headers=headers, timeout=timeout)
