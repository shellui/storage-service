"""Published MCP tool names.

shellui-django 0.5.1 names a tool from ``operationId``. The ai-service gateway
already publishes a different name (``storage_<verb>_<noun>``). These are those
names, keyed by operation id. ``x-mcp.tool_name`` carries the same string.
"""

from __future__ import annotations

from typing import Any

# Exact names from shellui/ai-service develop
# ``apps/connector/tests/fixtures/mcp_tool_release_snapshot.json``.
MCP_PUBLISHED_TOOL_NAMES: dict[str, str] = {
    'storage_v1_object_copy_create': 'storage_copy_object',
    'storage_v1_access_grant_create': 'storage_create_access_grant',
    'api_v1_actions_rules_create': 'storage_create_action_rules',
    'storage_v1_connector_create': 'storage_create_connector',
    'storage_v1_connector_configuration_check_create': 'storage_create_connector_configuration_check',
    'storage_v1_connector_configuration_retry_create': 'storage_create_connector_configuration_retry',
    'storage_v1_connector_configuration_validate_create': 'storage_create_connector_configuration_validate',
    'storage_v1_object_create': 'storage_create_object',
    'storage_v1_object_list_create': 'storage_create_object_list',
    'storage_v1_object_prefix_create': 'storage_create_object_prefix',
    'storage_v1_share_create': 'storage_create_share',
    'storage_v1_access_grant_destroy': 'storage_delete_access_grant',
    'api_v1_actions_rules_destroy': 'storage_delete_action_rules',
    'storage_v1_connector_destroy': 'storage_delete_connector',
    'storage_v1_share_link_destroy': 'storage_delete_link_share',
    'storage_v1_object_delete_many': 'storage_delete_many_object',
    'storage_v1_object_destroy': 'storage_delete_object',
    'storage_v1_object_prefix_destroy': 'storage_delete_object_prefix',
    'storage_v1_bucket_empty_create': 'storage_empty_bucket',
    'api_v1_actions_deliveries_retrieve': 'storage_get_action_deliveries',
    'api_v1_actions_event_log_retrieve': 'storage_get_action_event_log',
    'api_v1_actions_event_log_retention_retrieve': 'storage_get_action_event_log_retention',
    'api_v1_actions_rules_retrieve': 'storage_get_action_rules',
    'storage_v1_bucket_retrieve': 'storage_get_bucket',
    'storage_v1_connector_retrieve': 'storage_get_connector',
    'storage_v1_object_authenticated_retrieve': 'storage_get_object',
    'storage_v1_object_id_retrieve': 'storage_get_object_id',
    'storage_v1_object_info_authenticated_retrieve': 'storage_get_object_info',
    'storage_v1_object_prefix_retrieve': 'storage_get_object_prefix',
    'storage_v1_object_retrieve': 'storage_get_public_object',
    'storage_v1_quota_retrieve': 'storage_get_quota',
    'storage_v1_stats_retrieve': 'storage_get_stats',
    'storage_v1_access_grant_list': 'storage_list_access_grant',
    'api_v1_actions_deliveries_list': 'storage_list_action_deliveries',
    'api_v1_actions_event_log_list': 'storage_list_action_event_log',
    'api_v1_actions_event_log_types_list': 'storage_list_action_event_log_types',
    'api_v1_actions_events_list': 'storage_list_action_events',
    'api_v1_actions_rules_list': 'storage_list_action_rules',
    'storage_v1_bucket_list': 'storage_list_bucket',
    'storage_v1_connector_list': 'storage_list_connector',
    'storage_v1_share_list': 'storage_list_share',
    'storage_v1_object_move_create': 'storage_move_object',
    'storage_v1_connector_update': 'storage_replace_connector',
    'storage_v1_object_update': 'storage_replace_object',
    'storage_v1_quota_company_update': 'storage_replace_quota_company',
    'storage_v1_quota_company_user_update': 'storage_replace_quota_company_user',
    'api_v1_actions_deliveries_requeue': 'storage_requeue_action_deliveries',
    'api_v1_actions_rules_rotate_secret': 'storage_rotate_rule_secret',
    'api_v1_actions_rules_send_test': 'storage_send_test_rule',
    'storage_v1_object_sign_create': 'storage_sign_object',
    'storage_v1_object_sign_path_create': 'storage_sign_object_path',
    'api_v1_actions_rules_partial_update': 'storage_update_action_rules',
    'storage_v1_connector_partial_update': 'storage_update_connector',
}


def apply_published_tool_names(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace operation-id slugs with the gateway tool name. Sorts by that name."""
    for tool in tools:
        op_id = str((tool.get('_meta') or {}).get('operationId') or '')
        published = MCP_PUBLISHED_TOOL_NAMES.get(op_id)
        if not published:
            raise KeyError(f'no published MCP name for {op_id or tool.get("name")}')
        tool['name'] = published
    tools.sort(key=lambda item: item['name'])
    return tools
