"""OpenAPI path templates and MCP tool argument validation."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

_PATH_PARAM_RE = re.compile(r'\{([^}]+)\}')


class McpToolArgumentError(ValueError):
    pass


def path_parameter_names(path_template: str) -> list[str]:
    return _PATH_PARAM_RE.findall(path_template)


def materialize_openapi_path(path_template: str, path_params: dict[str, Any]) -> str:
    """Substitute ``{name}`` segments with URL-encoded values (fail closed on injection)."""
    names = path_parameter_names(path_template)
    if not isinstance(path_params, dict):
        raise McpToolArgumentError('path_params must be an object.')
    if set(path_params.keys()) != set(names):
        missing = sorted(set(names) - set(path_params.keys()))
        extra = sorted(set(path_params.keys()) - set(names))
        if missing:
            raise McpToolArgumentError(f'Missing path parameters: {", ".join(missing)}')
        raise McpToolArgumentError(f'Unexpected path parameters: {", ".join(extra)}')
    resolved = path_template
    for name in names:
        raw = path_params[name]
        if raw is None:
            raise McpToolArgumentError(f'Path parameter {name} is required.')
        text = str(raw).strip()
        if not text:
            raise McpToolArgumentError(f'Path parameter {name} is required.')
        if '/' in text or '{' in text or '}' in text:
            raise McpToolArgumentError(f'Path parameter {name} is invalid.')
        encoded = quote(text, safe='')
        token = '{' + name + '}'
        if token not in resolved:
            raise McpToolArgumentError('Unresolved path template.')
        resolved = resolved.replace(token, encoded, 1)
    if _PATH_PARAM_RE.search(resolved):
        raise McpToolArgumentError('Unresolved path template.')
    return resolved


def _validate_param_object(
    label: str,
    value: Any,
    allowed: list[str] | None,
    *,
    required: list[str] | None = None,
) -> None:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise McpToolArgumentError(f'{label} must be an object.')
    if allowed is None:
        return
    allowed_set = set(allowed)
    extra = sorted(set(value.keys()) - allowed_set)
    if extra:
        raise McpToolArgumentError(f'Unexpected {label} fields: {", ".join(extra)}')
    if required:
        missing = sorted(set(required) - set(value.keys()))
        if missing:
            raise McpToolArgumentError(f'Missing required {label} fields: {", ".join(missing)}')


def validate_mcp_tool_arguments(arguments: dict[str, Any], meta: dict[str, Any]) -> None:
    path_params = arguments.get('path_params')
    if path_params is None:
        path_params = {}
    materialize_openapi_path(str(meta.get('path') or ''), path_params)
    _validate_param_object(
        'query',
        arguments.get('query'),
        meta.get('query_fields'),
        required=meta.get('query_required') or None,
    )
    _validate_param_object(
        'body',
        arguments.get('body'),
        meta.get('body_fields'),
        required=meta.get('body_required') or None,
    )
