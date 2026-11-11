"""Storage-service ``POST /mcp`` Streamable HTTP endpoint."""

from __future__ import annotations

import threading

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from rest_framework.request import Request
from apps.authapi.agent_tokens import authenticate_agent_bearer, mcp_resource_audience
from apps.authapi.mcp_authority import DelegatedAuthorityDenied, DelegatedAuthorityUnavailable
from shellui_django.mcp.resources import access_token_audience_matches

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


def _get_server() -> StrictMcpServer:
    global _server
    if _server is None:
        _server = StrictMcpServer(
            schema_provider=_schema,
            urlconf=settings.ROOT_URLCONF,
            service_name='storage',
            identity_revocation_check=agent_is_revoked,
            approval_handler=create_approval_request,
            approval_state=_approval_state_for_mcp,
            approval_consume=consume_approval,
        )
    return _server


def _agent_claims(request: HttpRequest) -> dict | None:
    header = request.headers.get('Authorization', '')
    if not header.lower().startswith('bearer '):
        return None
    raw = header.split(' ', 1)[1].strip()
    expected_resource = mcp_resource_audience(request)
    try:
        result = authenticate_agent_bearer(raw, expected_resource=expected_resource)
    except DelegatedAuthorityUnavailable:
        return {'_mcp_identity_unavailable': True}
    except DelegatedAuthorityDenied:
        return {'_mcp_delegated_authority_denied': True}
    if not result:
        return None
    principal, claims = result
    if not access_token_audience_matches(claims, expected_resource):
        return None
    request.user = principal
    drf_request = Request(request)
    drf_request.user = principal
    return dict(claims)


@csrf_exempt
def mcp_endpoint(request: HttpRequest):
    claims = _agent_claims(request)
    if isinstance(claims, dict) and claims.get('_mcp_delegated_authority_denied'):
        return JsonResponse({'error': 'forbidden'}, status=403)
    if isinstance(claims, dict) and claims.get('_mcp_identity_unavailable'):
        return JsonResponse({'error': 'identity_unavailable'}, status=503)
    expected_resource = mcp_resource_audience(request) if claims else None
    return _get_server().handle(request, agent_claims=claims, mcp_resource_audience=expected_resource)
