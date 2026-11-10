"""MCP operation summaries and bodies. Consumed by ``openapi_admin.mcp_openapi_fields``."""

from __future__ import annotations

from typing import NamedTuple


class _McpSpec(NamedTuple):
    summary: str
    lead: str
    side_effects: str
    sends_email: bool = False
    destructive: bool = False
    notes: str = ''


# Keys must match ``MCP_REQUIRED_OPERATION_IDS`` in ``apps.authapi.mcp_openapi``.
MCP_SPECS: dict[str, _McpSpec] = {
    'storage_v1_bucket_list': _McpSpec(
        'List storage buckets',
        'Returns buckets the caller may access: the system `company` bucket and any connector mounts. '
        'Rows include `kind`, `access.can_write`, and connector metadata when present.',
        'Read-only.',
    ),
    'storage_v1_bucket_retrieve': _McpSpec(
        'Read one storage bucket',
        'Returns bucket metadata and effective write access for the caller.',
        'Read-only.',
    ),
    'storage_v1_bucket_empty_create': _McpSpec(
        'Empty a storage bucket',
        'Deletes every object the caller may write in the bucket. Refuses when the bucket is not writable.',
        'Removes object rows and backend blobs for the bucket scope.', destructive=True,
        notes='Does not delete the bucket row itself.',
    ),
    'storage_v1_connector_list': _McpSpec(
        'List external connector mounts',
        'Returns connector buckets for the JWT company. Omits secrets and returns only allowlisted `connector_settings` keys on GET detail.',
        'Read-only.',
    ),
    'storage_v1_connector_retrieve': _McpSpec(
        'Read one connector mount',
        'Returns provider, allowlisted `connector_settings`, credential presence metadata, and a stable `connector_last_issue_code` when present (no raw provider errors).',
        'Read-only. Does not return stored credentials.',
    ),
    'storage_v1_connector_create': _McpSpec(
        'Create a connector mount',
        'Company owner only. Registers a read-only `connector` bucket with optional encrypted `credential` and allowlisted `connector_settings`.',
        'Inserts a bucket row and runs a local configuration and credential check (no live provider call; no remote sync).',
        notes='`credential` is write-only with `x-mcp-secret` and never appears in list or detail responses. In DEBUG or tests, optional `connector_settings._dev_simulation` may steer the check.',
    ),
    'storage_v1_connector_update': _McpSpec(
        'Replace connector configuration (PUT)',
        'Company owner only. Replaces `connector_settings` unless `merge_settings` is true.',
        'Updates the bucket row and may rotate the encrypted credential.',
        notes='Send `credential` only when rotating. Omit the field to keep the previous secret.',
    ),
    'storage_v1_connector_partial_update': _McpSpec(
        'Patch connector configuration',
        'Company owner only. PATCH merges `connector_settings` by default.',
        'Updates the bucket row.',
        notes='Same secret rules as create and PUT.',
    ),
    'storage_v1_connector_destroy': _McpSpec(
        'Delete a connector mount',
        'Company owner only. Removes the connector bucket row (no objects are stored in connector buckets today).',
        'Deletes one bucket row.', destructive=True,
    ),
    'storage_v1_connector_configuration_check_create': _McpSpec(
        'Re-run local connector configuration check',
        'Company owner only. Validates allowlisted settings and stored credential decrypt using the same rules as create and update. Not a live provider or remote connectivity test.',
        'Updates last refresh and test timestamps, `connector_last_issue_code`, and `connector_retry_after` when the check does not pass.',
    ),
    'storage_v1_connector_configuration_validate_create': _McpSpec(
        'Validate stored connector configuration locally',
        'Company owner only. Same local check as configuration check (alias for agents).',
        'Updates last refresh and test timestamps and issue metadata when the check does not pass.',
    ),
    'storage_v1_connector_configuration_retry_create': _McpSpec(
        'Retry local configuration check after backoff',
        'Company owner only. Same local check; may clear `connector_retry_after` when the configuration check passes.',
        'Updates connector health metadata fields.',
    ),
    'storage_v1_object_list_create': _McpSpec(
        'List objects in a bucket',
        'POST body lists folders and files under an optional `prefix` with paging, search, and sort. '
        'Respects path-level access grants.',
        'Read-only listing.',
    ),
    'storage_v1_object_id_retrieve': _McpSpec(
        'Resolve object by stable id',
        'Maps a UUID object id to bucket name, path, and whether the row is a file or folder.',
        'Read-only.',
    ),
    'storage_v1_object_retrieve': _McpSpec(
        'Download an object',
        'Streams file bytes for a bucket path. Optional query `download` sets Content-Disposition.',
        'Read-only. May increment last-accessed metadata.',
    ),
    'storage_v1_object_authenticated_retrieve': _McpSpec(
        'Download an object (authenticated alias)',
        'Same as `GET /object/{bucket}/{path}` at the Supabase-compatible authenticated path.',
        'Read-only.',
    ),
    'storage_v1_object_info_authenticated_retrieve': _McpSpec(
        'Read object metadata',
        'Returns size, MIME type, etag, and ownership without downloading bytes.',
        'Read-only.',
    ),
    'storage_v1_object_create': _McpSpec(
        'Upload an object (POST)',
        'Creates a file at the path. REST clients send raw bytes or multipart form with `file`. '
        'MCP calls send JSON `content_base64` (standard base64) and optional `content_type`. '
        'Header `x-upsert: true` replaces an existing object on REST. MCP replace uses the PUT upload tool.',
        'Writes object metadata and backend storage. Counts toward company quota.',
    ),
    'storage_v1_object_update': _McpSpec(
        'Upload or replace an object (PUT)',
        'Upserts by default (Supabase-compatible). REST body shapes match POST upload. '
        'MCP calls send JSON `content_base64` and optional `content_type`.',
        'Writes or replaces object bytes and metadata.',
    ),
    'storage_v1_object_destroy': _McpSpec(
        'Delete one object',
        'Removes a single file or folder placeholder the caller may write.',
        'Deletes object row and backend blob.', destructive=True,
    ),
    'storage_v1_object_delete_many': _McpSpec(
        'Delete many objects',
        'JSON array of paths (or `{ "prefixes": [...] }`) under one bucket.',
        'Batch delete for each path.', destructive=True,
    ),
    'storage_v1_object_prefix_retrieve': _McpSpec(
        'Summarize a folder prefix',
        'Counts files, placeholders, and total bytes under query `prefix`.',
        'Read-only aggregation.',
    ),
    'storage_v1_object_prefix_create': _McpSpec(
        'Rename a folder prefix',
        'Moves every object under `from`/`source` to `to`/`destination` and updates grants.',
        'Updates many object paths and grant rows.',
    ),
    'storage_v1_object_prefix_destroy': _McpSpec(
        'Delete a folder prefix',
        'Recursively deletes objects under body or query `prefix`. Refuses an empty prefix.',
        'Recursive delete under the prefix.', destructive=True,
    ),
    'storage_v1_object_move_create': _McpSpec(
        'Move an object',
        'Body `sourceKey` and `destinationKey` use `bucket/path` form. Source and destination buckets must be accessible.',
        'Moves one object between paths or buckets.',
    ),
    'storage_v1_object_copy_create': _McpSpec(
        'Copy an object',
        'Copies bytes from source to destination. Destination must be writable.',
        'Creates a new object row and duplicates backend storage.',
    ),
    'storage_v1_object_sign_create': _McpSpec(
        'Create a signed download URL (path in body)',
        'Returns time-limited HTTPS URL for anonymous download. Optional `expiresIn` seconds.',
        'Read-only. Does not mutate objects.', notes='Treat signed URLs as secrets (`x-mcp-sensitive`).',
    ),
    'storage_v1_object_sign_path_create': _McpSpec(
        'Create a signed download URL',
        'Same as sign-with-body when the object path is in the URL.',
        'Read-only URL minting.', notes='Treat signed URLs as secrets (`x-mcp-sensitive`).',
    ),
    'storage_v1_access_grant_list': _McpSpec(
        'List access grants',
        'Filter with `resource_type`, `resource_id`, and `bucket`. '
        'Set `include_effective=true` to expand inherited deny/allow for a path.',
        'Read-only.',
    ),
    'storage_v1_access_grant_create': _McpSpec(
        'Create an access grant',
        'Grants or blocks a subject on a bucket, folder, or file path.',
        'Inserts an access grant row.',
    ),
    'storage_v1_access_grant_destroy': _McpSpec(
        'Revoke an access grant',
        'Deletes one grant by id when the caller may administer grants.',
        'Removes the grant row.', destructive=True,
    ),
    'storage_v1_share_list': _McpSpec(
        'List share links for an object',
        'Returns active and revoked links for one file. Tokens are omitted except on create.',
        'Read-only.',
    ),
    'storage_v1_share_create': _McpSpec(
        'Create a share link',
        'Returns the secret `token` once for anonymous download. Optional expiry and download limits.',
        'Inserts a share link row.', notes='Store `token` before closing the response.',
    ),
    'storage_v1_share_link_destroy': _McpSpec(
        'Revoke a share link',
        'Marks the link revoked. Anonymous redeem URLs stop working.',
        'Updates share link row.', destructive=True,
    ),
    'storage_v1_quota_retrieve': _McpSpec(
        'Read quota usage',
        'Returns company and caller user byte limits, used bytes, and remaining headroom.',
        'Read-only.',
    ),
    'storage_v1_quota_company_update': _McpSpec(
        'Set company quota limits',
        'Company owner or staff sets `max_bytes` and optional `max_bytes_per_user`.',
        'Updates company quota row.',
    ),
    'storage_v1_quota_company_user_update': _McpSpec(
        'Set per-user quota override',
        'Company owner or staff sets `max_bytes` for one user in the company.',
        'Updates or creates a user quota row.',
    ),
    'storage_v1_stats_retrieve': _McpSpec(
        'Read storage statistics',
        'Upload and storage aggregates for the company (or global when staff). Query `days` (1-90, default 14).',
        'Read-only metrics.', notes='May include recent upload filenames (`x-mcp-sensitive`).',
    ),
    'api_v1_actions_events_list': _McpSpec(
        'List Shellui Actions event types',
        'Returns storage domain event ids, labels, payload fields, and sample envelopes for webhook rules.',
        'Read-only.',
    ),
    'api_v1_actions_rules_list': _McpSpec(
        'List Shellui Actions webhook rules',
        'Each rule posts signed HTTPS webhooks when a storage domain event fires. '
        'The signing secret is shown once on the admin HTTP create or rotate response. MCP masks it.',
        'Read-only.',
    ),
    'api_v1_actions_rules_create': _McpSpec(
        'Create a Shellui Actions webhook rule. The signing secret is shown once in admin, not to the agent.',
        'Creates an HTTPS webhook rule for a registered `event_type`. '
        'The admin HTTP response returns the signing `secret` once. MCP masks it.',
        'Inserts rule row and stores encrypted secret.',
        notes='Read the secret from the admin HTTP response before you close it. URL must be publicly reachable unless staff SSRF override is enabled.',
    ),
    'api_v1_actions_rules_retrieve': _McpSpec(
        'Read one Shellui Actions webhook rule',
        'Returns rule metadata and masked secret hints. Plaintext `secret` is omitted.',
        'Read-only.',
    ),
    'api_v1_actions_rules_partial_update': _McpSpec(
        'Update a Shellui Actions webhook rule',
        'Patches name, description, enabled flag, URL, or filters.',
        'Updates rule configuration.',
    ),
    'api_v1_actions_rules_destroy': _McpSpec(
        'Delete a Shellui Actions webhook rule',
        'Removes the rule. In-flight deliveries may still complete.',
        'Deletes the rule row.', destructive=True,
    ),
    'api_v1_actions_rules_rotate_secret': _McpSpec(
        'Rotate a webhook signing secret. The new secret is shown once in admin, not to the agent.',
        'Generates a new HMAC secret. The admin HTTP response returns it once. MCP masks it.',
        'Updates encrypted secret on the rule.',
        notes='Copy the new secret from the admin HTTP response, then update your receiver.',
    ),
    'api_v1_actions_rules_send_test': _McpSpec(
        'Send a sample webhook for a rule',
        'Delivers a synthetic domain event to the rule URL synchronously for debugging.',
        'May write delivery attempt rows.', sends_email=False,
        notes='Does not send email. Delivers an HTTPS webhook only.',
    ),
    'api_v1_actions_deliveries_list': _McpSpec(
        'List recent webhook deliveries',
        'Returns delivery status, attempt counts, and errors for the company.',
        'Read-only.',
        notes='Staff may filter by `scheduled_job_run_id` (not exposed on MCP).',
    ),
    'api_v1_actions_deliveries_retrieve': _McpSpec(
        'Read one webhook delivery',
        'Returns attempts, HTTP statuses, and the signed envelope payload.',
        'Read-only.',
    ),
    'api_v1_actions_deliveries_requeue': _McpSpec(
        'Requeue a failed webhook delivery',
        'Resets a failed or dead delivery to pending for another attempt.',
        'Updates outbox status and schedule.',
    ),
    'api_v1_actions_event_log_list': _McpSpec(
        'List recent domain events for the company',
        'Returns the latest storage domain events stored for auditing and Shellui Actions rules.',
        'Read-only.',
        notes='Query `scope=platform` is staff-only and not an MCP tool.',
    ),
    'api_v1_actions_event_log_retrieve': _McpSpec(
        'Read one domain event log entry',
        'Returns full event payload for a company or platform (staff) row.',
        'Read-only.',
    ),
    'api_v1_actions_event_log_types_list': _McpSpec(
        'List domain event type ids',
        'Returns event type strings valid for log filters and Shellui Actions rules.',
        'Read-only.',
    ),
    'api_v1_actions_event_log_retention_retrieve': _McpSpec(
        'Read event log retention settings',
        'Returns configured retention days and whether stale rows exceed policy.',
        'Read-only.',
    ),
}
