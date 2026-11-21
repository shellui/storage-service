"""Storage-service ``POST /mcp`` Streamable HTTP endpoint."""

from __future__ import annotations

import threading

from django.conf import settings
from django.http import HttpRequest
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from shellui_django.mcp.resources import normalize_resource_indicator

from apps.storage.mcp_server_strict import StrictMcpServer
from apps.storage.mcp_identity import (
    agent_is_revoked,
    approval_state,
    consume_approval,
    create_approval_request,
)

_server: StrictMcpServer | None = None
_schema_cache: dict | None = None
_schema_lock = threading.Lock()


def _schema() -> dict:
    """Cached OpenAPI for MCP. Concurrent ``SchemaGenerator`` is not thread-safe."""
    global _schema_cache
    cached = _schema_cache
    if cached is not None:
        return cached
    with _schema_lock:
        if _schema_cache is not None:
            return _schema_cache
        _schema_cache = SchemaGenerator().get_schema(request=None, public=True)
        return _schema_cache


def _approval_state_for_mcp(payload: dict, agent_claims: dict) -> str | None:
    """Pass through Identity approval status (``expired`` means row already consumed / not reusable)."""
    return approval_state(payload, agent_claims)


def _configured_mcp_audience() -> str | None:
    """Fixed MCP resource when ``STORAGE_PUBLIC_URL`` is set. Otherwise each request host."""
    public = (getattr(settings, 'STORAGE_PUBLIC_URL', '') or '').strip().rstrip('/')
    if not public:
        return None
    return normalize_resource_indicator(f'{public}/mcp') or None


def _get_server() -> StrictMcpServer:
    global _server
    if _server is None:
        document = getattr(settings, 'IDENTITY_JWKS_DOCUMENT', None)
        jwks = document if isinstance(document, dict) else None
        _server = StrictMcpServer(
            schema_provider=_schema,
            urlconf=settings.ROOT_URLCONF,
            service_name='storage',
            identity_revocation_check=agent_is_revoked,
            approval_handler=create_approval_request,
            approval_state=_approval_state_for_mcp,
            approval_consume=consume_approval,
            identity_issuer=getattr(settings, 'IDENTITY_ISSUER', None) or '',
            identity_jwks=jwks,
            identity_jwks_url=None if jwks is not None else getattr(settings, 'IDENTITY_JWKS_URL', None),
            mcp_audience=_configured_mcp_audience(),
        )
    return _server


@csrf_exempt
def mcp_endpoint(request: HttpRequest):
    return _get_server().handle(request)
