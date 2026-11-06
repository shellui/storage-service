"""Storage-service ``POST /mcp`` Streamable HTTP endpoint."""

from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from rest_framework.request import Request
from apps.authapi.agent_tokens import authenticate_agent_bearer, mcp_resource_audience
from shellui_django.mcp.resources import access_token_audience_matches

from apps.storage.mcp_server_strict import StrictMcpServer
from apps.storage.mcp_identity import (
    agent_is_revoked,
    approval_state,
    consume_approval,
    create_approval_request,
    forward_call_log,
)

_server: StrictMcpServer | None = None


def _schema() -> dict:
    generator = SchemaGenerator()
    return generator.get_schema(request=None, public=True)


def _approval_state_for_mcp(payload: dict, agent_claims: dict) -> str | None:
    """Map identity ``expired`` (consumed approval) to ``executed`` for the MCP server."""
    state = approval_state(payload, agent_claims)
    if state == 'expired':
        return 'executed'
    return state


def _get_server() -> StrictMcpServer:
    global _server
    if _server is None:
        _server = StrictMcpServer(
            schema_provider=_schema,
            urlconf=settings.ROOT_URLCONF,
            service_name='storage',
            identity_revocation_check=agent_is_revoked,
            on_call=forward_call_log,
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
    result = authenticate_agent_bearer(raw, expected_resource=expected_resource)
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
    expected_resource = mcp_resource_audience(request) if claims else None
    return _get_server().handle(request, agent_claims=claims, mcp_resource_audience=expected_resource)
