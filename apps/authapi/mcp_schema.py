"""AutoSchema that refuses ``x-mcp`` on internal routes."""

from __future__ import annotations

from drf_spectacular.openapi import AutoSchema

from apps.authapi.mcp_openapi import MCP_EXCLUDED_PATH_PREFIXES


class McpAutoSchema(AutoSchema):
    def get_operation(self, path, path_regex, path_prefix, method, registry):
        operation = super().get_operation(path, path_regex, path_prefix, method, registry)
        if not operation:
            return operation
        if operation.get('x-mcp') and any(str(path).startswith(prefix) for prefix in MCP_EXCLUDED_PATH_PREFIXES):
            raise AssertionError(f'x-mcp is not allowed on excluded path: {path}')
        operation.pop('extensions', None)
        return operation
