"""Block webhook URLs that target private or link-local addresses (SSRF)."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


class SSRFError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedWebhookEndpoint:
    """Connect to ``connect_host`` while preserving the original ``Host`` / TLS SNI."""

    original_url: str
    scheme: str
    connect_host: str
    port: int
    host_header: str
    path: str


def _validate_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool) -> None:
    if allow_private:
        return
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    ):
        raise SSRFError('Webhook URL resolves to a private or non-public address.')


def _blocked_hostname(host: str, *, allow_private: bool) -> None:
    if host in {'localhost', 'metadata.google.internal'} and not allow_private:
        raise SSRFError('Localhost webhook URLs are not allowed.')


def resolve_webhook_endpoint(url: str, *, allow_private: bool = False) -> ResolvedWebhookEndpoint:
    parsed = urlparse((url or '').strip())
    if parsed.scheme not in {'http', 'https'}:
        raise SSRFError('Webhook URL must use http or https.')
    hostname = (parsed.hostname or '').lower()
    if not hostname:
        raise SSRFError('Webhook URL must include a hostname.')
    _blocked_hostname(hostname, allow_private=allow_private)
    try:
        literal = ipaddress.ip_address(hostname)
        _validate_ip(literal, allow_private=allow_private)
        connect_host = hostname
    except ValueError:
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        try:
            infos = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            raise SSRFError(f'Could not resolve webhook hostname: {hostname}') from exc
        if not infos:
            raise SSRFError(f'Could not resolve webhook hostname: {hostname}')
        connect_host = None
        for info in infos:
            candidate = ipaddress.ip_address(info[4][0])
            try:
                _validate_ip(candidate, allow_private=allow_private)
            except SSRFError:
                continue
            connect_host = info[4][0]
            port = info[4][1] or port
            break
        if connect_host is None:
            raise SSRFError('Webhook hostname resolves only to private or non-public addresses.')
    else:
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

    path = parsed.path or '/'
    if parsed.query:
        path = f'{path}?{parsed.query}'
    return ResolvedWebhookEndpoint(
        original_url=url.strip(),
        scheme=parsed.scheme,
        connect_host=connect_host,
        port=port,
        host_header=(
            f'{hostname}:{parsed.port}'
            if parsed.port and parsed.port not in {80, 443}
            else hostname
        ),
        path=path,
    )


def validate_webhook_url(url: str, *, allow_private: bool = False) -> str:
    resolve_webhook_endpoint(url, allow_private=allow_private)
    return url.strip()
