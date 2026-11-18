"""Flat MCP tool schemas for agents.

``shellui-django`` 0.5.1 ``tools_from_schema`` always requires ``method`` and ``path``
and nests ``query``, ``body``, and ``path_params``. This module is the schema
``tools/list`` publishes and the argument shape ``tools/call`` accepts.

A call that still sends the old ``method`` + ``path`` envelope is accepted so an
ai-service gateway can keep forwarding it until that gateway stops adding them.
"""

from __future__ import annotations

from typing import Any

from shellui_django.mcp.openapi_tools import _client_prop_schema, tools_from_schema
from shellui_django.mcp.routing import McpToolArgumentError

from apps.storage.mcp_tool_names import apply_published_tool_names

_SCHEMA_BOUNDS = ('minimum', 'maximum', 'minLength', 'maxLength')


def published_mcp_tools(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Gateway tool names, flat input schemas, and ``_meta`` for dispatch."""
    operations = _operations_by_id(schema)
    tools = apply_published_tool_names(tools_from_schema(schema))
    for tool in tools:
        meta = tool.get('_meta') or {}
        op_id = str(meta.get('operationId') or '')
        operation = operations.get(op_id)
        if operation is None:
            raise KeyError(f'no OpenAPI operation for MCP tool {tool.get("name")}')
        tool['inputSchema'] = flat_input_schema(tool, operation, schema)
    return tools


def flat_input_schema(
    tool: dict[str, Any],
    operation: dict[str, Any],
    root: dict[str, Any],
) -> dict[str, Any]:
    """Lift path, query, and body fields to one object. Drop transport keys."""
    lib_props = (tool.get('inputSchema') or {}).get('properties') or {}
    body_schema = lib_props.get('body') if isinstance(lib_props.get('body'), dict) else {}
    query_schema = lib_props.get('query') if isinstance(lib_props.get('query'), dict) else {}
    body_props = dict(body_schema.get('properties') or {})
    query_props = dict(query_schema.get('properties') or {})
    body_required = [str(name) for name in (body_schema.get('required') or [])]
    query_required = [str(name) for name in (query_schema.get('required') or [])]

    parameters = [param for param in (operation.get('parameters') or []) if isinstance(param, dict)]
    for param in parameters:
        if param.get('in') != 'query':
            continue
        name = str(param.get('name') or '')
        if name in query_props:
            query_props[name] = _overlay_query_property(query_props[name], param, root)

    properties: dict[str, Any] = {}
    required: list[str] = []
    for param in parameters:
        if param.get('in') != 'path':
            continue
        name = str(param.get('name') or '')
        if not name:
            continue
        if name in body_props or name in query_props:
            raise ValueError(f'MCP path parameter {name} clashes with a query or body field')
        properties[name] = _parameter_property(param, root)
        required.append(name)

    # Body wins when REST accepts the same name in the query (prefix delete).
    overlap = set(body_props) & set(query_props)
    for name, prop in body_props.items():
        properties[name] = prop
    for name in body_required:
        if name not in required:
            required.append(name)
    for name, prop in query_props.items():
        if name in overlap:
            continue
        properties[name] = prop
    for name in query_required:
        if name in overlap or name in required:
            continue
        required.append(name)

    flat: dict[str, Any] = {
        'type': 'object',
        'additionalProperties': False,
        'properties': properties,
    }
    if required:
        flat['required'] = required
    return flat


def coerce_mcp_call_arguments(arguments: Any, meta: dict[str, Any]) -> dict[str, Any]:
    """Return the nested envelope ``validate_mcp_tool_arguments`` expects.

    Flat calls are split into path, query, and body using the operation meta.
    A legacy call that includes both ``method`` and ``path`` is returned unchanged.
    """
    if not isinstance(arguments, dict):
        raise McpToolArgumentError('arguments must be an object.')
    if _is_legacy_envelope(arguments):
        return arguments

    path_names = [str(name) for name in (meta.get('path_params') or [])]
    query_names = [str(name) for name in (meta.get('query_fields') or [])]
    body_names = [str(name) for name in (meta.get('body_fields') or [])]
    query_only = [name for name in query_names if name not in body_names]
    allowed = set(path_names) | set(query_only) | set(body_names)
    extra = sorted(set(arguments) - allowed)
    if extra:
        raise McpToolArgumentError(f'Unexpected arguments: {", ".join(extra)}')

    missing: list[str] = []
    for name in path_names:
        if name not in arguments or arguments[name] in (None, ''):
            missing.append(name)
    for name in (meta.get('query_required') or []):
        if name not in body_names and name not in arguments:
            missing.append(name)
    for name in (meta.get('body_required') or []):
        if name not in arguments:
            missing.append(name)
    if missing:
        raise McpToolArgumentError(f'Missing required arguments: {", ".join(sorted(set(missing)))}')

    nested: dict[str, Any] = {
        'path': meta.get('path'),
        'method': meta.get('method'),
        'query': {name: arguments[name] for name in query_only if name in arguments},
        'body': {name: arguments[name] for name in body_names if name in arguments},
    }
    if path_names:
        nested['path_params'] = {name: arguments[name] for name in path_names}
    return nested


def _is_legacy_envelope(arguments: dict[str, Any]) -> bool:
    return 'method' in arguments and 'path' in arguments


def _operations_by_id(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for path_item in (schema.get('paths') or {}).values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if isinstance(operation, dict) and operation.get('operationId'):
                found[str(operation['operationId'])] = operation
    return found


def _parameter_property(param: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    raw = param.get('schema') if isinstance(param.get('schema'), dict) else {'type': 'string'}
    raw = dict(raw)
    description = str(raw.get('description') or param.get('description') or '').strip()
    if description:
        raw['description'] = description
    prop = _client_prop_schema(raw, root)
    if description and not prop.get('description'):
        prop['description'] = description
    for key in _SCHEMA_BOUNDS:
        if key in raw and key not in prop:
            prop[key] = raw[key]
    return prop


def _overlay_query_property(prop: dict[str, Any], param: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    fresh = _parameter_property(param, root)
    merged = dict(fresh)
    merged.update(prop)
    if not prop.get('description') and fresh.get('description'):
        merged['description'] = fresh['description']
    if 'enum' not in prop and fresh.get('enum'):
        merged['enum'] = fresh['enum']
    for key in _SCHEMA_BOUNDS:
        if key in fresh and key not in prop:
            merged[key] = fresh[key]
    return merged
