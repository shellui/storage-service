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
        'Lists buckets you can access, including the company bucket and connector mounts. '
        'Returns kind, write access, and connector metadata when a mount has it.',
        'Returns buckets the caller may access: the system `company` bucket and any connector mounts. '
        'Rows include `kind`, `access.can_write`, and connector metadata when present.',
        'Read-only.',
    ),
    'storage_v1_bucket_retrieve': _McpSpec(
        'Reads one bucket by `bucket_id`. Returns metadata and whether you can write.',
        'Returns bucket metadata and effective write access for the caller.',
        'Read-only.',
    ),
    'storage_v1_bucket_empty_create': _McpSpec(
        'Deletes every object you can write in `bucket_id` and returns true. The bucket row stays.',
        'Deletes every object the caller may write in the bucket. Refuses when the bucket is not writable.',
        'Removes object rows and backend blobs for the bucket scope.', destructive=True,
        notes='Does not delete the bucket row itself.',
    ),
    'storage_v1_connector_list': _McpSpec(
        'Lists connector mounts for your company. Returns provider and settings, and omits credentials.',
        'Returns connector buckets for the JWT company. Omits secrets and returns only allowlisted `connector_settings` keys on GET detail.',
        'Read-only.',
    ),
    'storage_v1_connector_retrieve': _McpSpec(
        'Reads one connector mount by `connector_id`. Returns provider, settings, and `connector_last_issue_code`, and omits credentials.',
        'Returns provider, allowlisted `connector_settings`, credential presence metadata, and a stable `connector_last_issue_code` when present (no raw provider errors).',
        'Read-only. Does not return stored credentials.',
    ),
    'storage_v1_connector_create': _McpSpec(
        'Creates a connector mount from `name` and `connector_provider`, with optional `credential` and `connector_settings`. Returns the mount without the credential.',
        'Company owner only. Registers a read-only `connector` bucket with optional encrypted `credential` and allowlisted `connector_settings`.',
        'Inserts a bucket row and runs a local configuration and credential check (no live provider call; no remote sync).',
        notes='`credential` is write-only with `x-mcp-secret` and never appears in list or detail responses. In DEBUG or tests, optional `connector_settings._dev_simulation` may steer the check.',
    ),
    'storage_v1_connector_update': _McpSpec(
        'Replaces connector settings for `connector_id`. Send `credential` only when rotating it, and the call returns the mount without the credential.',
        'Company owner only. Replaces `connector_settings` unless `merge_settings` is true.',
        'Replaces connector settings and can replace or clear the stored credential.',
        destructive=True,
        notes='Send `credential` only when rotating. Omit the field to keep the previous secret.',
    ),
    'storage_v1_connector_partial_update': _McpSpec(
        'Patches connector settings for `connector_id`. Send `credential` to rotate it, or null to clear it, and the call returns the updated mount.',
        'Company owner only. PATCH merges `connector_settings` by default.',
        'Updates the mount and can replace or clear the stored credential.',
        destructive=True,
        notes='Same secret rules as create and PUT.',
    ),
    'storage_v1_connector_destroy': _McpSpec(
        'Deletes the connector mount `connector_id`. Returns no content.',
        'Company owner only. Removes the connector bucket row (no objects are stored in connector buckets today).',
        'Deletes one bucket row.', destructive=True,
    ),
    'storage_v1_connector_configuration_check_create': _McpSpec(
        'Re-runs the local configuration check for `connector_id` and returns status plus `connector_last_issue_code`. This does not call the provider.',
        'Company owner only. Validates allowlisted settings and stored credential decrypt using the same rules as create and update. Not a live provider or remote connectivity test.',
        'Updates last refresh and test timestamps, `connector_last_issue_code`, and `connector_retry_after` when the check does not pass.',
    ),
    'storage_v1_connector_configuration_validate_create': _McpSpec(
        'Runs the same local configuration check as the check action for `connector_id`. Returns status and issue metadata.',
        'Company owner only. Same local check as configuration check (alias for agents).',
        'Updates last refresh and test timestamps and issue metadata when the check does not pass.',
    ),
    'storage_v1_connector_configuration_retry_create': _McpSpec(
        'Re-runs the local configuration check for `connector_id` after backoff. Returns status and may clear `connector_retry_after`.',
        'Company owner only. Same local check; may clear `connector_retry_after` when the configuration check passes.',
        'Updates connector health metadata fields.',
    ),
    'storage_v1_object_list_create': _McpSpec(
        'Lists files and folders in `bucket_id`, with optional `prefix`, `limit`, `offset`, `search`, and `sortBy`. Returns object rows.',
        'POST body lists folders and files under an optional `prefix` with paging, search, and sort. '
        'Respects path-level access grants.',
        'Read-only listing.',
    ),
    'storage_v1_object_id_retrieve': _McpSpec(
        'Resolves `object_id` to its bucket, path, and type (`file` or `folder`).',
        'Maps a UUID object id to bucket name, path, and whether the row is a file or folder.',
        'Read-only.',
    ),
    'storage_v1_object_retrieve': _McpSpec(
        'Downloads bytes for `bucket_id` and `object_path`, with optional `download` as the file name. Returns `content_base64`, `content_type`, and `size`.',
        'Streams file bytes for a bucket path. Optional query `download` sets Content-Disposition.',
        'Read-only. May increment last-accessed metadata.',
    ),
    'storage_v1_object_authenticated_retrieve': _McpSpec(
        'Downloads bytes for `bucket_id` and `object_path` on the authenticated route, with optional `download` as the file name. Returns `content_base64`, `content_type`, and `size`.',
        'Same as `GET /object/{bucket}/{path}` at the Supabase-compatible authenticated path.',
        'Read-only.',
    ),
    'storage_v1_object_info_authenticated_retrieve': _McpSpec(
        'Reads metadata for `bucket_id` and `object_path`. Returns size, MIME type, and etag without the file bytes.',
        'Returns size, MIME type, etag, and ownership without downloading bytes.',
        'Read-only.',
    ),
    'storage_v1_object_create': _McpSpec(
        'Creates a file at `bucket_id` and `object_path` from `content_base64`, with optional `content_type`. Returns `Id` and `Key`, and fails when the path already exists.',
        'Creates a file at the path. REST clients send raw bytes or multipart form with `file`. '
        'MCP calls send JSON `content_base64` (standard base64) and optional `content_type`. '
        'Header `x-upsert: true` replaces an existing object on REST. MCP replace uses the PUT upload tool.',
        'Writes object metadata and backend storage. Counts toward company quota.',
    ),
    'storage_v1_object_update': _McpSpec(
        'Writes or overwrites the file at `bucket_id` and `object_path` from `content_base64`, with optional `content_type`. Returns `Id` and `Key`.',
        'Upserts by default (Supabase-compatible). REST body shapes match POST upload. '
        'MCP calls send JSON `content_base64` and optional `content_type`.',
        'Writes or replaces object bytes and metadata. The new bytes can be downloaded.',
    ),
    'storage_v1_object_destroy': _McpSpec(
        'Deletes one file or folder at `bucket_id` and `object_path`. Returns true.',
        'Removes a single file or folder placeholder the caller may write.',
        'Deletes object row and backend blob.', destructive=True,
    ),
    'storage_v1_object_delete_many': _McpSpec(
        'Deletes the object paths in `prefixes` or `paths` under `bucket_id`. Returns the deleted names.',
        'JSON array of paths (or `{ "prefixes": [...] }`) under one bucket.',
        'Batch delete for each path.', destructive=True,
    ),
    'storage_v1_object_prefix_retrieve': _McpSpec(
        'Counts files, folders, and bytes under `prefix` in `bucket_id`. Returns `object_count`, `file_count`, `placeholder_count`, and `total_bytes`.',
        'Counts files, placeholders, and total bytes under query `prefix`.',
        'Read-only aggregation.',
    ),
    'storage_v1_object_prefix_create': _McpSpec(
        'Renames a folder in `bucket_id` from `from` (or `source` or `prefix`) to `to` (or `destination`). Returns how many objects and grants moved.',
        'Moves every object under `from`/`source` to `to`/`destination` and updates grants.',
        'Updates many object paths and grant rows.',
    ),
    'storage_v1_object_prefix_destroy': _McpSpec(
        'Deletes every object under `prefix` in `bucket_id`. `prefix` is required, and the call returns the deleted paths and count.',
        'Recursively deletes objects under body or query `prefix`. Refuses an empty prefix.',
        'Recursive delete under the prefix.', destructive=True,
    ),
    'storage_v1_object_move_create': _McpSpec(
        'Moves one object. `sourceKey` and `destinationKey` use `bucket/path`, the call returns a confirmation, and it fails when the destination exists.',
        'Body `sourceKey` and `destinationKey` use `bucket/path` form. Source and destination buckets must be accessible.',
        'Moves one object between paths or buckets.',
    ),
    'storage_v1_object_copy_create': _McpSpec(
        'Copies one object. `sourceKey` and `destinationKey` use `bucket/path`, and the call returns the new `Key` or fails when the destination exists.',
        'Copies bytes from source to destination. Destination must be writable.',
        'Creates a new object row and duplicates backend storage.',
    ),
    'storage_v1_object_sign_create': _McpSpec(
        'Creates a time-limited anonymous download URL for `path` in `bucket_id`. Optional `expiresIn` is the lifetime in seconds, and the call returns `signedURL`.',
        'Returns time-limited HTTPS URL for anonymous download. Optional `expiresIn` seconds.',
        'Mints a time-limited anonymous download URL and does not change object bytes.',
        destructive=True,
        notes='Treat signed URLs as secrets (`x-mcp-sensitive`).',
    ),
    'storage_v1_object_sign_path_create': _McpSpec(
        'Creates a time-limited anonymous download URL for `bucket_id` and `object_path`. Optional `expiresIn` is the lifetime in seconds, and the call returns `signedURL`.',
        'Same as sign-with-body when the object path is in the URL.',
        'Mints a time-limited anonymous download URL and does not change object bytes.',
        destructive=True,
        notes='Treat signed URLs as secrets (`x-mcp-sensitive`).',
    ),
    'storage_v1_access_grant_list': _McpSpec(
        'Lists access grants. Optional filters are `resource_type`, `resource_id`, `bucket`, and `include_effective`, and the call returns grant rows.',
        'Filter with `resource_type`, `resource_id`, and `bucket`. '
        'Set `include_effective=true` to expand inherited deny/allow for a path.',
        'Read-only.',
    ),
    'storage_v1_access_grant_create': _McpSpec(
        'Creates an access grant. Requires `subject_type`, `subject_id`, `resource_type`, and `resource_id`, and returns the grant.',
        'Grants or blocks a subject on a bucket, folder, or file path.',
        'Inserts an access grant row.',
    ),
    'storage_v1_access_grant_destroy': _McpSpec(
        'Deletes the access grant `grant_id`. Returns no content.',
        'Deletes one grant by id when the caller may administer grants.',
        'Removes the grant row.', destructive=True,
    ),
    'storage_v1_share_list': _McpSpec(
        'Lists share links for `bucket_id` and `object_path`. Returns link rows and omits the token.',
        'Returns active and revoked links for one file. Tokens are omitted except on create.',
        'Read-only.',
    ),
    'storage_v1_share_create': _McpSpec(
        'Creates an anonymous download link for `bucket_id` and `object_path`. Optional `expires_at` and `max_downloads`, and the call returns the token once.',
        'Returns the secret `token` once for anonymous download. Optional expiry and download limits.',
        'Inserts a share link row and opens anonymous download for that object.',
        destructive=True,
        notes='Store `token` before closing the response.',
    ),
    'storage_v1_share_link_destroy': _McpSpec(
        'Revokes the share link `token` so anonymous downloads stop. Returns the link with the token redacted.',
        'Marks the link revoked. Anonymous redeem URLs stop working.',
        'Updates share link row.', destructive=True,
    ),
    'storage_v1_quota_retrieve': _McpSpec(
        'Reads storage quota for your company and your user. Returns `max_bytes`, `used_bytes`, and `remaining_bytes`.',
        'Returns company and caller user byte limits, used bytes, and remaining headroom.',
        'Read-only.',
    ),
    'storage_v1_quota_company_update': _McpSpec(
        'Overwrites quota limits for `company_id` using `max_bytes` and optional `max_bytes_per_user`. Returns the saved limits.',
        'Company owner or staff sets `max_bytes` and optional `max_bytes_per_user`.',
        'Updates the company quota row. The saved limits can be read back.',
    ),
    'storage_v1_quota_company_user_update': _McpSpec(
        'Overwrites the quota for `user_id` in `company_id`. Requires `max_bytes` and returns the saved limit.',
        'Company owner or staff sets `max_bytes` for one user in the company.',
        'Updates or creates a user quota row. The saved limit can be read back.',
    ),
    'storage_v1_stats_retrieve': _McpSpec(
        'Reads upload and storage statistics for your company. Optional `days` is 1 to 90, and the default is 14.',
        'Upload and storage aggregates for the company (or global when staff). Query `days` (1-90, default 14).',
        'Read-only metrics.', notes='May include recent upload filenames (`x-mcp-sensitive`).',
    ),
    'api_v1_actions_events_list': _McpSpec(
        'Lists Shellui Actions event types you can attach to a webhook rule. Returns id, label, payload fields, and a sample envelope.',
        'Returns storage domain event ids, labels, payload fields, and sample envelopes for webhook rules.',
        'Read-only.',
    ),
    'api_v1_actions_rules_list': _McpSpec(
        'Lists Shellui Actions webhook rules for your company. Returns rule rows with the signing secret masked.',
        'Each rule posts signed HTTPS webhooks when a storage domain event fires. '
        'The signing secret is shown once on the admin HTTP create or rotate response. MCP masks it.',
        'Read-only.',
    ),
    'api_v1_actions_rules_create': _McpSpec(
        'Creates a Shellui Actions webhook rule from `event_type`, `name`, and `url`. Returns the rule with the signing secret masked.',
        'Creates an HTTPS webhook rule for a registered `event_type`. '
        'The admin HTTP response returns the signing `secret` once. MCP masks it.',
        'Inserts rule row and stores encrypted secret.',
        notes='Read the secret from the admin HTTP response before you close it. URL must be publicly reachable unless staff SSRF override is enabled.',
    ),
    'api_v1_actions_rules_retrieve': _McpSpec(
        'Reads one Shellui Actions webhook rule by `id`. Returns metadata with the signing secret masked.',
        'Returns rule metadata and masked secret hints. Plaintext `secret` is omitted.',
        'Read-only.',
    ),
    'api_v1_actions_rules_partial_update': _McpSpec(
        'Updates a Shellui Actions webhook rule by `id` (`name`, `url`, `enabled`, `event_type`, or `secret`). Returns the rule with the secret masked.',
        'Patches name, description, enabled flag, URL, or filters.',
        'Updates rule configuration.',
    ),
    'api_v1_actions_rules_destroy': _McpSpec(
        'Deletes the Shellui Actions webhook rule `id`. Returns no content.',
        'Removes the rule. In-flight deliveries may still complete.',
        'Deletes the rule row.', destructive=True,
    ),
    'api_v1_actions_rules_rotate_secret': _McpSpec(
        'Replaces the signing secret on Shellui Actions rule `id`. Returns the rule, and the new secret stays masked for agents.',
        'Generates a new HMAC secret. The admin HTTP response returns it once. MCP masks it.',
        'Replaces the encrypted signing secret. The previous secret stops verifying deliveries.',
        destructive=True,
        notes='Copy the new secret from the admin HTTP response, then update your receiver.',
    ),
    'api_v1_actions_rules_send_test': _McpSpec(
        'Sends a sample webhook for Shellui Actions rule `id`. Returns whether the receiver accepted it.',
        'Delivers a synthetic domain event to the rule URL synchronously for debugging.',
        'Sends an HTTPS webhook to the rule URL.',
        sends_email=False,
        destructive=True,
        notes='Does not send email. Delivers an HTTPS webhook only.',
    ),
    'api_v1_actions_deliveries_list': _McpSpec(
        'Lists recent Shellui Actions webhook deliveries. Optional `status`, `event_type`, and paging, and the call returns status, attempts, and errors.',
        'Returns delivery status, attempt counts, and errors for the company.',
        'Read-only.',
        notes='`scheduled_job_run_id` is staff-only and returns 403 for other callers.',
    ),
    'api_v1_actions_deliveries_retrieve': _McpSpec(
        'Reads one Shellui Actions webhook delivery by `delivery_id`. Returns attempts and the signed envelope.',
        'Returns attempts, HTTP statuses, and the signed envelope payload.',
        'Read-only.',
    ),
    'api_v1_actions_deliveries_requeue': _McpSpec(
        'Queues failed Shellui Actions delivery `delivery_id` for another attempt. Returns the delivery with status pending.',
        'Resets a failed or dead delivery to pending for another attempt.',
        'Queues the delivery for another send to the rule URL.',
        destructive=True,
    ),
    'api_v1_actions_event_log_list': _McpSpec(
        'Lists recent domain events for your company. Optional `event_type`, `user_id`, `scope`, and time bounds, and the call returns a page of events.',
        'Returns the latest storage domain events stored for auditing and Shellui Actions rules.',
        'Read-only.',
        notes='Query `scope=platform` is staff-only and not an MCP tool.',
    ),
    'api_v1_actions_event_log_retrieve': _McpSpec(
        'Reads one domain event by `id`. Optional `scope` is `company` or `platform`, and the call returns the event payload.',
        'Returns full event payload for a company or platform (staff) row.',
        'Read-only.',
    ),
    'api_v1_actions_event_log_types_list': _McpSpec(
        'Lists domain event type ids for log filters and Shellui Actions rules. Returns the id strings.',
        'Returns event type strings valid for log filters and Shellui Actions rules.',
        'Read-only.',
    ),
    'api_v1_actions_event_log_retention_retrieve': _McpSpec(
        'Reads event log retention. Returns the configured retention days and whether rows are past policy.',
        'Returns configured retention days and whether stale rows exceed policy.',
        'Read-only.',
    ),
}
