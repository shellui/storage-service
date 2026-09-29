"""HTTP(S) POST to a pre-resolved webhook endpoint (SSRF-safe connect)."""

from __future__ import annotations

import ipaddress
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


def _tls_server_name(endpoint: ResolvedWebhookEndpoint) -> str:
    """Hostname for TLS SNI and certificate verification from the HTTP Host value."""
    host_header = endpoint.host_header
    if host_header.startswith('['):
        end = host_header.find(']')
        if end == -1:
            return host_header
        return host_header[1:end]
    _head, sep, tail = host_header.rpartition(':')
    if sep and tail.isdigit():
        return _head
    return host_header


def _socket_connect_host(connect_host: str) -> str:
    """Normalize connect addresses for ``socket.create_connection``."""
    try:
        ip = ipaddress.ip_address(connect_host)
    except ValueError:
        return connect_host
    if isinstance(ip, ipaddress.IPv6Address):
        return ip.compressed
    return connect_host


class PinnedHTTPSConnection(HTTPSConnection):
    """TLS to the original hostname while the TCP socket targets a pinned IP."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        connect_host: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_connect_host = _socket_connect_host(connect_host)

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._pinned_connect_host, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


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
) -> WebhookPostResult:
    req_headers = dict(headers)
    req_headers['Host'] = endpoint.host_header
    tls_hostname = _tls_server_name(endpoint)
    if endpoint.scheme == 'https':
        context = ssl.create_default_context()
        conn: HTTPConnection | HTTPSConnection = PinnedHTTPSConnection(
            tls_hostname,
            endpoint.port,
            connect_host=endpoint.connect_host,
            timeout=timeout,
            context=context,
        )
    else:
        conn = HTTPConnection(
            _socket_connect_host(endpoint.connect_host),
            endpoint.port,
            timeout=timeout,
        )
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
