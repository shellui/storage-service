"""OpenAPI ``x-mcp`` tool metadata shared across Shellui services."""

from __future__ import annotations

from typing import Any

from shellui_mcp.write_gate import is_destructive_operation


class McpSchemaValidationError(ValueError):
    pass


def mcp_extension(operation: dict[str, Any]) -> dict[str, Any] | None:
    raw = operation.get('x-mcp')
    if isinstance(raw, dict):
        return raw
    extensions = operation.get('extensions') or {}
    nested = extensions.get('x-mcp')
    return nested if isinstance(nested, dict) else None


def tool_access_flags(operation: dict[str, Any] | None) -> dict[str, bool]:
    if not operation:
        return {'read_only': False, 'destructive': False, 'tagged': False}
    ext = mcp_extension(operation)
    if ext is None:
        return {
            'read_only': False,
            'destructive': is_destructive_operation(operation),
            'tagged': False,
        }
    return {
        'read_only': bool(ext.get('read_only')),
        'destructive': bool(ext.get('destructive')) or is_destructive_operation(operation),
        'tagged': True,
    }


def validate_read_only_post_tools(schema: dict[str, Any], *, allowlist: frozenset[str]) -> None:
    """POST operations tagged ``x-mcp.read_only`` must appear on the service allowlist."""
    paths = schema.get('paths') or {}
    violations: list[str] = []
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if str(method).upper() != 'POST' or not isinstance(operation, dict):
                continue
            ext = mcp_extension(operation)
            if not ext or not ext.get('read_only'):
                continue
            op_id = str(operation.get('operationId') or '')
            if not op_id or op_id not in allowlist:
                violations.append(op_id or f'<missing operationId> @ {method}')
    if violations:
        raise McpSchemaValidationError(
            'POST tools tagged x-mcp.read_only must be listed in the read-only POST allowlist: '
            + ', '.join(sorted(violations))
        )


def _resolve_schema(schema: dict[str, Any] | None, components: dict[str, Any]) -> dict[str, Any]:
    if not schema or not isinstance(schema, dict):
        return {}
    ref = schema.get('$ref')
    if ref and ref.startswith('#/components/schemas/'):
        name = ref.rsplit('/', 1)[-1]
        target = (components.get('schemas') or {}).get(name)
        if isinstance(target, dict):
            return _resolve_schema(target, components)
    return schema


def _merge_property_markers(
    props: dict[str, Any],
    components: dict[str, Any],
    into: dict[str, Any],
) -> None:
    for key, field in props.items():
        if not isinstance(field, dict):
            continue
        field = _resolve_schema(field, components)
        node = into.setdefault(str(key), {'secret': False, 'sensitive': False, 'children': {}})
        if field.get('x-mcp-secret') is True:
            node['secret'] = True
        if field.get('x-mcp-sensitive') is True:
            node['sensitive'] = True
        nested = field.get('properties')
        if isinstance(nested, dict):
            _merge_property_markers(nested, components, node['children'])
        items = field.get('items')
        if isinstance(items, dict):
            item_schema = _resolve_schema(items, components)
            item_props = item_schema.get('properties')
            if isinstance(item_props, dict):
                _merge_property_markers(item_props, components, node['children'])


def marker_tree_for_schema(schema: dict[str, Any] | None, root_schema: dict[str, Any]) -> dict[str, Any]:
    components = (root_schema.get('components') or {}).get('schemas') or {}
    resolved = _resolve_schema(schema, {'schemas': components})
    tree: dict[str, Any] = {}
    props = resolved.get('properties')
    if isinstance(props, dict):
        _merge_property_markers(props, {'schemas': components}, tree)
    return tree


def marker_tree_for_operation_request(operation: dict[str, Any] | None, root_schema: dict[str, Any]) -> dict[str, Any]:
    if not operation:
        return {}
    body = operation.get('requestBody') or {}
    content = body.get('content') or {} if isinstance(body, dict) else {}
    json_schema = content.get('application/json', {}).get('schema') if isinstance(content, dict) else None
    return marker_tree_for_schema(json_schema if isinstance(json_schema, dict) else None, root_schema)


def marker_tree_for_operation_response(operation: dict[str, Any] | None, root_schema: dict[str, Any]) -> dict[str, Any]:
    if not operation:
        return {}
    responses = operation.get('responses') or {}
    if not isinstance(responses, dict):
        return {}
    for status_code in ('200', '201', '202', '204'):
        response = responses.get(status_code)
        if not isinstance(response, dict):
            continue
        content = response.get('content') or {}
        if not isinstance(content, dict):
            continue
        json_schema = content.get('application/json', {}).get('schema')
        if isinstance(json_schema, dict):
            return marker_tree_for_schema(json_schema, root_schema)
    return {}
