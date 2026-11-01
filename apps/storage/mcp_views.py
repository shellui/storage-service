"""Storage-service ``POST /mcp`` Streamable HTTP endpoint."""

from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.generators import SchemaGenerator
from rest_framework.request import Request
from shellui_mcp.server import McpServer

from apps.authapi.agent_tokens import authenticate_agent_bearer, mcp_resource_audience
from apps.storage.mcp_identity import (
    agent_is_revoked,
    approval_state,
    consume_approval,
    create_approval_request,
    forward_call_log,
)

_server: McpServer | None = None


def _schema() -> dict:
    generator = SchemaGenerator()
    return generator.get_schema(request=None, public=True)


def _get_server() -> McpServer:
    global _server
    if _server is None:
        _server = McpServer(
            schema_provider=_schema,
            urlconf=settings.ROOT_URLCONF,
            service_name='storage',
            identity_revocation_check=agent_is_revoked,
            on_call=forward_call_log,
            approval_handler=create_approval_request,
            approval_state=approval_state,
            approval_consume=consume_approval,
        )
    return _server


def _agent_claims(request: HttpRequest) -> dict | None:
    header = request.headers.get('Authorization', '')
    if not header.lower().startswith('bearer '):
        return None
    raw = header.split(' ', 1)[1].strip()
    resource_aud = mcp_resource_audience(request)
    result = authenticate_agent_bearer(raw, mcp_resource_audience=resource_aud)
    if not result:
        return None
    principal, claims = result
    request.user = principal
    drf_request = Request(request)
    drf_request.user = principal
    return dict(claims)


@csrf_exempt
def mcp_endpoint(request: HttpRequest):
    claims = _agent_claims(request)
    return _get_server().handle(request, agent_claims=claims)
