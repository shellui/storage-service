"""Build MCP tool definitions from a drf-spectacular OpenAPI schema."""

from __future__ import annotations

import re
from typing import Any

MCP_TOOL_TAG = 'mcp-tools'


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
            tools.append(
                {
                    'name': name,
                    'description': description,
                    'inputSchema': {
                        'type': 'object',
                        'properties': {
                            'path': {'type': 'string', 'const': path},
                            'method': {'type': 'string', 'enum': [method.upper()]},
                            'query': {'type': 'object', 'additionalProperties': True},
                            'body': {'type': 'object', 'additionalProperties': True},
                        },
                        'required': ['path', 'method'],
                    },
                    '_meta': {'path': path, 'method': method.upper(), 'operationId': operation.get('operationId')},
                }
            )
    tools.sort(key=lambda t: t['name'])
    return tools
