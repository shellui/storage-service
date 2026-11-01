"""RFC 8707 resource indicators for MCP (audience = canonical ``/mcp`` URL)."""

from __future__ import annotations

import hmac
from urllib.parse import urlsplit

MCP_RESOURCE_SUFFIX = '/mcp'


def mcp_resource_from_origin(origin: str) -> str:
    """Build the protected resource identifier for a Shellui service origin."""
    base = str(origin or '').strip().rstrip('/')
    if not base:
        return ''
    return f'{base}{MCP_RESOURCE_SUFFIX}'


def normalize_resource_indicator(raw: str | None) -> str | None:
    """
    Canonical resource URL for authorize/token/refresh ``resource`` parameter.
    Must be absolute https (or http loopback) ending in ``/mcp`` with no fragment.
    """
    s = str(raw or '').strip()
    if not s or '#' in s:
        return None
    if s.endswith('/'):
        s = s.rstrip('/')
    if not s.endswith(MCP_RESOURCE_SUFFIX):
        return None
    try:
        parsed = urlsplit(s)
    except ValueError:
        return None
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return None
    if parsed.path != MCP_RESOURCE_SUFFIX:
        return None
    if parsed.query or parsed.fragment:
        return None
    host = (parsed.hostname or '').lower()
    if parsed.scheme == 'http' and host not in ('127.0.0.1', 'localhost', '::1'):
        return None
    return s


def access_token_audience_matches(payload: dict, expected_resource: str) -> bool:
    """True when JWT ``aud`` equals this service's MCP resource URL."""
    expected = normalize_resource_indicator(expected_resource) or ''
    presented = normalize_resource_indicator(str(payload.get('aud') or '')) or ''
    if not expected or not presented:
        return False
    return hmac.compare_digest(expected, presented)
