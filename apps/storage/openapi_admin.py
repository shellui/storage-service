"""OpenAPI copy for company-owner admin and MCP APIs (written for agents and humans)."""

from __future__ import annotations

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse

from apps.authapi.mcp_openapi import MCP_REQUIRED_OPERATION_IDS
from apps.storage.openapi_mcp_registry import MCP_SPECS
from apps.storage.serializers import ErrorSerializer

PERMISSIONS_BLOCK = (
    'Permissions: Shellui company owner for the JWT `company_id`, or Shellui staff. '
    'Send `Authorization: Bearer <jwt>` from identity-service. MCP agent tokens act as the company owner. '
    'Service API keys (`esk_`) cannot call these routes.'
)

BUCKET_ID_PATH = OpenApiParameter(
    name='bucket_id',
    type=OpenApiTypes.STR,
    location=OpenApiParameter.PATH,
    description='Bucket slug (for example `company` or a connector mount id).',
)

CONNECTOR_ID_PATH = OpenApiParameter(
    name='connector_id',
    type=OpenApiTypes.STR,
    location=OpenApiParameter.PATH,
    description='Connector mount slug (not the reserved `company` bucket name).',
)

OBJECT_ID_PATH = OpenApiParameter(
    name='object_id',
    type=OpenApiTypes.UUID,
    location=OpenApiParameter.PATH,
    description='Stable object UUID from list or upload responses.',
)

OBJECT_PATH_PARAM = OpenApiParameter(
    name='object_path',
    type=OpenApiTypes.STR,
    location=OpenApiParameter.PATH,
    description='Object path within the bucket (may include `/` for nested folders).',
)

GRANT_ID_PATH = OpenApiParameter(
    name='grant_id',
    type=OpenApiTypes.UUID,
    location=OpenApiParameter.PATH,
    description='Access grant UUID.',
)

COMPANY_ID_PATH = OpenApiParameter(
    name='company_id',
    type=OpenApiTypes.INT,
    location=OpenApiParameter.PATH,
    description='Target company id (owners may only use their JWT company).',
)

USER_ID_PATH = OpenApiParameter(
    name='user_id',
    type=OpenApiTypes.INT,
    location=OpenApiParameter.PATH,
    description='Shellui user id within the company.',
)

SHARE_TOKEN_PATH = OpenApiParameter(
    name='token',
    type=OpenApiTypes.STR,
    location=OpenApiParameter.PATH,
    description='Share link capability token (secret).',
)

ACTION_RULE_ID_PATH = OpenApiParameter(
    name='id',
    type=OpenApiTypes.INT,
    location=OpenApiParameter.PATH,
    description='Shellui Actions webhook rule id.',
)

DELIVERY_ID_PATH = OpenApiParameter(
    name='delivery_id',
    type=OpenApiTypes.UUID,
    location=OpenApiParameter.PATH,
    description='Webhook delivery id (UUID string).',
)

EVENT_LOG_ID_PATH = OpenApiParameter(
    name='id',
    type=OpenApiTypes.INT,
    location=OpenApiParameter.PATH,
    description='Event log row id.',
)


def admin_description(
    *,
    lead: str,
    side_effects: str,
    sends_email: bool = False,
    destructive: bool = False,
    notes: str = '',
) -> str:
    """Standard MCP-facing operation description."""
    parts = [lead.strip(), PERMISSIONS_BLOCK]
    parts.append(f'Side effects: {side_effects.strip()}')
    parts.append(f'Sends email: {"Yes" if sends_email else "No"}.')
    parts.append(f'Destructive: {"Yes" if destructive else "No"}.')
    if notes.strip():
        parts.append(notes.strip())
    return '\n\n'.join(parts)


def _error_response(description: str) -> OpenApiResponse:
    return OpenApiResponse(
        response=ErrorSerializer,
        description=description,
    )


ADMIN_API_ERRORS = {
    400: _error_response(
        'Invalid query or body. JSON uses `error` (stable code, for example `validation_failed`) and '
        '`message` with detail. Some validation responses map field names to error lists in the body.'
    ),
    401: _error_response('Missing or invalid Bearer token (`error`: `unauthorized`).'),
    403: _error_response(
        'Caller is authenticated but not allowed (`error`: `forbidden`). '
        'Common causes: missing grant, wrong company, or staff-only query parameter.'
    ),
    404: _error_response('Resource not found (`error`: `not_found` or a domain-specific code).'),
    409: _error_response(
        'Conflict with current state (`error`: for example `object_exists`, `quota_exceeded`).'
    ),
    429: _error_response(
        'Rate limited (`error`: `rate_limited` or MCP throttle). Retry after backing off.'
    ),
}


def mcp_openapi_fields(operation_id: str) -> dict[str, str]:
    """Summary and description for an MCP allowlisted operation."""
    spec = MCP_SPECS.get(operation_id)
    if spec is None:
        raise KeyError(f'missing MCP OpenAPI registry entry for {operation_id}')
    return {
        'summary': spec.summary,
        'description': admin_description(
            lead=spec.lead,
            side_effects=spec.side_effects,
            sends_email=spec.sends_email,
            destructive=spec.destructive,
            notes=spec.notes,
        ),
    }


if set(MCP_SPECS) != MCP_REQUIRED_OPERATION_IDS:
    missing = MCP_REQUIRED_OPERATION_IDS - set(MCP_SPECS)
    extra = set(MCP_SPECS) - MCP_REQUIRED_OPERATION_IDS
    raise AssertionError(f'MCP_SPECS drift: missing={sorted(missing)} extra={sorted(extra)}')
