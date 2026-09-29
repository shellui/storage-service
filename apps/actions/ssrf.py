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


_NAT64 = ipaddress.ip_network('64:ff9b::/96')
_SIX2FOUR = ipaddress.ip_network('2002::/16')
_IPV4_COMPAT = ipaddress.ip_network('::/96')
_IPV4_MAPPED = ipaddress.ip_network('::ffff:0:0/96')


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _SIX2FOUR:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    if ip in _IPV4_COMPAT and ip not in _IPV4_MAPPED:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _validate_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool) -> None:
    if allow_private:
        return
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            ip = embedded
    if not ip.is_global:
        raise SSRFError('Webhook URL resolves to a private or non-public address.')


def _blocked_hostname(host: str, *, allow_private: bool) -> None:
    if host in {'localhost', 'metadata.google.internal'} and not allow_private:
        raise SSRFError('Localhost webhook URLs are not allowed.')


def resolve_webhook_endpoint(url: str, *, allow_private: bool = False) -> ResolvedWebhookEndpoint:
    """
    Resolve the hostname once and return the address used for the TCP connection.

    The HTTP ``Host`` header (and HTTPS SNI) stay on the original hostname so TLS
    verification matches the certificate. Residual risk: a hostname could theoretically
    flip DNS between resolve and connect if TTL expires mid-request; we do not re-resolve
    on connect.
    """
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
