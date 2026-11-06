"""Register Shellui MCP tools for storage OpenAPI (explicit opt-in only)."""

from __future__ import annotations

from apps.authapi.mcp_openapi import mcp_tool


def register_storage_mcp_tools() -> None:
    read = lambda op, **kw: mcp_tool(operation_id=op, read_only=True, **kw)  # noqa: E731
    write = lambda op, **kw: mcp_tool(operation_id=op, read_only=False, **kw)  # noqa: E731

    read('storage_v1_bucket_list')
    read('storage_v1_bucket_retrieve')
    write('storage_v1_bucket_empty_create', destructive=True)

    read('storage_v1_connector_list')
    read('storage_v1_connector_retrieve')
    write('storage_v1_connector_create', sensitive=True)
    write('storage_v1_connector_update', sensitive=True)
    write('storage_v1_connector_partial_update', sensitive=True)
    write('storage_v1_connector_destroy', destructive=True)
    write('storage_v1_connector_configuration_check_create', sensitive=True)
    write('storage_v1_connector_configuration_validate_create', sensitive=True)
    write('storage_v1_connector_configuration_retry_create', sensitive=True)

    read('storage_v1_object_list_create')
    read('storage_v1_object_id_retrieve')
    read('storage_v1_object_retrieve')
    read('storage_v1_object_authenticated_retrieve')
    read('storage_v1_object_info_authenticated_retrieve')
    write('storage_v1_object_create')
    write('storage_v1_object_update')
    write('storage_v1_object_destroy', destructive=True)
    write('storage_v1_object_delete_many', destructive=True)
    read('storage_v1_object_prefix_retrieve')
    write('storage_v1_object_prefix_create')
    write('storage_v1_object_prefix_destroy', destructive=True)
    write('storage_v1_object_move_create')
    write('storage_v1_object_copy_create')
    write('storage_v1_object_sign_create', sensitive=True)
    write('storage_v1_object_sign_path_create', sensitive=True)

    read('storage_v1_access_grant_list')
    write('storage_v1_access_grant_create')
    write('storage_v1_access_grant_destroy', destructive=True)

    read('storage_v1_share_list')
    write('storage_v1_share_create', sensitive=True)
    write('storage_v1_share_link_destroy', destructive=True)

    read('storage_v1_quota_retrieve')
    write('storage_v1_quota_company_update')
    write('storage_v1_quota_company_user_update')

    read('storage_v1_stats_retrieve', sensitive=True)

    read('api_v1_actions_events_list')
    read('api_v1_actions_rules_list', sensitive=True)
    write('api_v1_actions_rules_create', sensitive=True)
    read('api_v1_actions_rules_retrieve', sensitive=True)
    write('api_v1_actions_rules_partial_update', sensitive=True)
    write('api_v1_actions_rules_destroy', destructive=True, sensitive=True)
    write('api_v1_actions_rules_rotate_secret', sensitive=True)
    write('api_v1_actions_rules_send_test', sensitive=True)
    read('api_v1_actions_deliveries_list', sensitive=True)
    read('api_v1_actions_deliveries_retrieve', sensitive=True)
    write('api_v1_actions_deliveries_requeue', sensitive=True)
    read('api_v1_actions_event_log_list', sensitive=True)
    read('api_v1_actions_event_log_retrieve', sensitive=True)
    read('api_v1_actions_event_log_types_list')
    read('api_v1_actions_event_log_retention_retrieve')


register_storage_mcp_tools()
