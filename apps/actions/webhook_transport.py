"""HTTP(S) POST to a pre-resolved webhook endpoint (SSRF-safe connect)."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection, HTTPResponse

from apps.actions.ssrf import ResolvedWebhookEndpoint, SSRFError, resolve_webhook_endpoint
from apps.actions.webhook_retry import parse_retry_after_header

_RESPONSE_EXCERPT_MAX = 512


class WebhookHTTPError(Exception):
    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        response_excerpt: str = '',
        retry_after_seconds: int | None = None,
        permanent: bool = False,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.response_excerpt = response_excerpt
        self.retry_after_seconds = retry_after_seconds
        self.permanent = permanent


@dataclass(frozen=True)
class WebhookPostResult:
    status: int
    excerpt: str
    retry_after_seconds: int | None = None


class PinnedHTTPSConnection(HTTPSConnection):
    """
    HTTPSConnection that dials a pinned IP (SSRF-safe) while verifying TLS for ``host``.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        pinned_host: str,
        timeout: float,
        context: ssl.SSLContext,
        source_address=None,
    ) -> None:
        super().__init__(host, port, timeout=timeout, source_address=source_address, context=context)
        self._pinned_host = pinned_host

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_host, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            server_hostname = self._tunnel_host
        else:
            server_hostname = self.host
        assert self._context is not None
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


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


def _tls_server_name(endpoint: ResolvedWebhookEndpoint) -> str:
    return endpoint.host_header.split(':')[0]


def post_resolved_webhook(
    endpoint: ResolvedWebhookEndpoint,
    *,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
) -> WebhookPostResult:
    req_headers = dict(headers)
    req_headers['Host'] = endpoint.host_header
    if endpoint.scheme == 'https':
        context = ssl.create_default_context()
        conn: HTTPConnection | HTTPSConnection = PinnedHTTPSConnection(
            _tls_server_name(endpoint),
            endpoint.port,
            pinned_host=endpoint.connect_host,
            timeout=timeout,
            context=context,
        )
    else:
        conn = HTTPConnection(endpoint.connect_host, endpoint.port, timeout=timeout)
    try:
        conn.request('POST', endpoint.path, body=body, headers=req_headers)
        response = conn.getresponse()
        status = int(response.status)
        excerpt = _read_response_excerpt(response)
        retry_raw = response.getheader('Retry-After')
        retry_after = parse_retry_after_header(retry_raw)
        return WebhookPostResult(status=status, excerpt=excerpt, retry_after_seconds=retry_after)
    finally:
        conn.close()


def post_webhook_url(
    url: str,
    *,
    body: bytes,
    headers: dict[str, str],
    timeout: float,
    allow_private: bool,
) -> WebhookPostResult:
    try:
        endpoint = resolve_webhook_endpoint(url, allow_private=allow_private)
    except SSRFError as exc:
        raise WebhookHTTPError(str(exc), permanent=True) from exc
    return post_resolved_webhook(endpoint, body=body, headers=headers, timeout=timeout)
