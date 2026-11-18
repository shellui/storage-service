"""OpenAPI copy for company-owner admin and MCP APIs (written for agents and humans)."""

from __future__ import annotations

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse

from apps.authapi.mcp_openapi import MCP_REQUIRED_OPERATION_IDS
from apps.storage.openapi_mcp_registry import MCP_SPECS
from apps.storage.serializers import ErrorSerializer

PERMISSIONS_BLOCK = (
    'Permissions: Shellui company owner for the JWT `company_id`, or Shellui staff. '
    'Send `Authorization: Bearer <jwt>` from identity-service. MCP agent tokens act as the company owner. '
    'Service API keys (`esk_`) cannot call these routes.'
)

def _path_param(name: str, *, schema_type: str, description: str, schema_format: str = '') -> OpenApiParameter:
    # ``type`` may be a schema object. Description stays inside that schema so
    # tool builders that read ``parameter.schema`` keep it.
    schema: dict = {'type': schema_type, 'description': description}
    if schema_format:
        schema['format'] = schema_format
    return OpenApiParameter(
        name=name,
        type=schema,
        location=OpenApiParameter.PATH,
        required=True,
        description=description,
    )


def mcp_query_param(
    name: str,
    *,
    description: str,
    schema_type: str = 'string',
    enum: list | None = None,
    schema_extra: dict | None = None,
) -> OpenApiParameter:
    """Query parameter whose schema carries the description and enum agents read."""
    schema: dict = {'type': schema_type, 'description': description}
    if enum is not None:
        schema['enum'] = list(enum)
    if schema_extra:
        schema.update(schema_extra)
    return OpenApiParameter(
        name=name,
        type=schema,
        location=OpenApiParameter.QUERY,
        required=False,
        description=description,
    )


BUCKET_ID_PATH = _path_param(
    'bucket_id',
    schema_type='string',
    description='Bucket slug, for example `company` or a connector mount id.',
)

CONNECTOR_ID_PATH = _path_param(
    'connector_id',
    schema_type='string',
    description='Connector mount slug. Not the reserved `company` bucket name.',
)

OBJECT_ID_PATH = _path_param(
    'object_id',
    schema_type='string',
    schema_format='uuid',
    description='Stable object id from list or upload responses.',
)

OBJECT_PATH_PARAM = _path_param(
    'object_path',
    schema_type='string',
    description='Object path within the bucket. May include `/` for nested folders.',
)

GRANT_ID_PATH = _path_param(
    'grant_id',
    schema_type='string',
    schema_format='uuid',
    description='Access grant id.',
)

COMPANY_ID_PATH = _path_param(
    'company_id',
    schema_type='integer',
    description='Company id. Owners may only pass the company id from the token.',
)

USER_ID_PATH = _path_param(
    'user_id',
    schema_type='integer',
    description='Shellui user id within the company.',
)

SHARE_TOKEN_PATH = _path_param(
    'token',
    schema_type='string',
    description='Share link token (secret).',
)

ACTION_RULE_ID_PATH = _path_param(
    'id',
    schema_type='integer',
    description='Shellui Actions webhook rule id.',
)

DELIVERY_ID_PATH = _path_param(
    'delivery_id',
    schema_type='string',
    schema_format='uuid',
    description='Webhook delivery id.',
)

EVENT_LOG_ID_PATH = _path_param(
    'id',
    schema_type='integer',
    description='Event log row id.',
)

DOWNLOAD_QUERY = mcp_query_param(
    'download',
    description='Omit to stream inline. `true` uses the object file name. Any other value is the download file name.',
)

STATS_DAYS_QUERY = mcp_query_param(
    'days',
    schema_type='integer',
    description='Rolling window in days, from 1 to 90. Default 14.',
    schema_extra={'minimum': 1, 'maximum': 90},
)

GRANT_RESOURCE_TYPE_QUERY = mcp_query_param(
    'resource_type',
    description='Grant target: `bucket`, `folder`, or `object`.',
    enum=['bucket', 'folder', 'object'],
)

GRANT_INCLUDE_EFFECTIVE_QUERY = mcp_query_param(
    'include_effective',
    description='`true` includes inherited grants for the path. `false` lists stored rows only.',
    enum=['true', 'false'],
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
