"""AutoSchema that refuses ``x-mcp`` on internal routes."""

from __future__ import annotations

from drf_spectacular.openapi import AutoSchema

from apps.authapi.mcp_openapi import MCP_EXCLUDED_PATH_PREFIXES

# drf-spectacular omits request bodies on DELETE. These operations accept a JSON body.
_DELETE_JSON_BODY_OPERATION_IDS = frozenset(
    {
        'storage_v1_object_delete_many',
        'storage_v1_object_prefix_destroy',
    }
)


class McpAutoSchema(AutoSchema):
    def _get_request_body(self, direction='request'):
        if self.method == 'DELETE' and self.get_operation_id() in _DELETE_JSON_BODY_OPERATION_IDS:
            # Parent returns None for every DELETE before it reads ``request=``.
            saved = self.method
            self.method = 'POST'
            try:
                return super()._get_request_body(direction)
            finally:
                self.method = saved
        return super()._get_request_body(direction)

    def get_operation(self, path, path_regex, path_prefix, method, registry):
        operation = super().get_operation(path, path_regex, path_prefix, method, registry)
        if not operation:
            return operation
        if operation.get('x-mcp') and any(str(path).startswith(prefix) for prefix in MCP_EXCLUDED_PATH_PREFIXES):
            raise AssertionError(f'x-mcp is not allowed on excluded path: {path}')
        operation.pop('extensions', None)
        return operation
