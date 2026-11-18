"""drf-spectacular hooks for Shellui MCP."""

from __future__ import annotations

from apps.authapi.mcp_openapi import MCP_EXCLUDED_PATH_PREFIXES, MCP_EXPLICIT_REGISTRY


def preprocessing_exclude_internal_endpoints(endpoints):
    """Drop staff-only and internal routes from the published schema."""
    filtered = []
    for path, path_regex, method, callback in endpoints:
        if any(str(path).startswith(prefix) for prefix in MCP_EXCLUDED_PATH_PREFIXES):
            continue
        filtered.append((path, path_regex, method, callback))
    return filtered


def postprocess_mcp_tool_tags(result, generator, request, public):
    """Attach ``mcp-tools`` tags and top-level ``x-mcp`` from the explicit registry."""
    paths = result.get('paths') or {}
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            op_id = operation.get('operationId')
            payload = MCP_EXPLICIT_REGISTRY.get(op_id)
            if not payload:
                continue
            operation['x-mcp'] = dict(payload)
            tags = list(operation.get('tags') or [])
            if 'mcp-tools' not in tags:
                tags.append('mcp-tools')
            if payload.get('destructive') and 'mcp-destructive' not in tags:
                tags.append('mcp-destructive')
            operation['tags'] = tags
    return result
