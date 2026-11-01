"""Build MCP tool definitions from a drf-spectacular OpenAPI schema."""

from __future__ import annotations

import re
from typing import Any

from shellui_mcp.openapi_mcp import tool_access_flags
from shellui_mcp.routing import path_parameter_names

MCP_TOOL_TAG = 'mcp-tools'


def _parameter_field_names(operation: dict[str, Any], *, location: str) -> tuple[list[str], list[str]]:
    names: list[str] = []
    required: list[str] = []
    for param in operation.get('parameters') or []:
        if not isinstance(param, dict) or param.get('in') != location:
            continue
        name = param.get('name')
        if not name:
            continue
        names.append(str(name))
        if param.get('required'):
            required.append(str(name))
    return names, required


def _body_field_names(operation: dict[str, Any]) -> tuple[list[str], list[str]]:
    request_body = operation.get('requestBody') or {}
    if not isinstance(request_body, dict):
        return [], []
    content = request_body.get('content') or {}
    schema = content.get('application/json', {}).get('schema') or {}
    if not isinstance(schema, dict):
        return [], []
    props = schema.get('properties') or {}
    if not isinstance(props, dict):
        return [], []
    names = [str(key) for key in props.keys()]
    required_raw = schema.get('required') or []
    required = [str(key) for key in required_raw if str(key) in names]
    return names, required


def _slug_tool_name(method: str, path: str, operation_id: str | None) -> str:
    if operation_id:
        base = re.sub(r'[^a-zA-Z0-9_]+', '_', operation_id).strip('_').lower()
        if base:
            return base[:120]
    cleaned = re.sub(r'[^a-zA-Z0-9_]+', '_', f'{method}_{path}').strip('_').lower()
    return cleaned[:120]


def tools_from_schema(schema: dict[str, Any]) -> list[dict[str, Any]]:
    paths = schema.get('paths') or {}
    tools: list[dict[str, Any]] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in {'get', 'post', 'put', 'patch', 'delete'}:
                continue
            if not isinstance(operation, dict):
                continue
            tags = operation.get('tags') or []
            if MCP_TOOL_TAG not in tags:
                continue
            name = _slug_tool_name(method, path, operation.get('operationId'))
            description = (operation.get('summary') or operation.get('description') or name).strip()
            path_params = path_parameter_names(path)
            query_fields, query_required = _parameter_field_names(operation, location='query')
            body_fields, body_required = _body_field_names(operation)
            properties: dict[str, Any] = {
                'path': {'type': 'string', 'const': path},
                'method': {'type': 'string', 'enum': [method.upper()]},
                'query': {'type': 'object', 'additionalProperties': False, 'properties': {}},
                'body': {'type': 'object', 'additionalProperties': False, 'properties': {}},
            }
            required = ['path', 'method']
            if path_params:
                properties['path_params'] = {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {param: {'type': 'string'} for param in path_params},
                    'required': path_params,
                }
                required.append('path_params')
            if query_fields:
                properties['query']['properties'] = {field: {} for field in query_fields}
            if body_fields:
                properties['body']['properties'] = {field: {} for field in body_fields}
            access = tool_access_flags(operation)
            tools.append(
                {
                    'name': name,
                    'description': description,
                    'inputSchema': {
                        'type': 'object',
                        'properties': properties,
                        'required': required,
                        'additionalProperties': False,
                    },
                    '_meta': {
                        'path': path,
                        'method': method.upper(),
                        'operationId': operation.get('operationId'),
                        'path_params': path_params,
                        'query_fields': query_fields or None,
                        'query_required': query_required or None,
                        'body_fields': body_fields or None,
                        'body_required': body_required or None,
                        'read_only': access['read_only'],
                        'destructive': access['destructive'],
                        'mcp_tagged': access['tagged'],
                    },
                }
            )
    tools.sort(key=lambda t: t['name'])
    return tools
