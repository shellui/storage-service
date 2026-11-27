---
title: Shellui MCP
sidebar_label: Shellui MCP
description: Storage APIs that Shellui MCP agents may call, and how they are marked in OpenAPI.
---

# Shellui MCP

Shellui MCP exposes company-scoped storage HTTP APIs as tools. storage-service implements `POST /mcp` (Streamable HTTP JSON-RPC). Identity issues OAuth tokens; this service publishes OpenAPI with `x-mcp` extensions and OAuth protected-resource metadata at `/.well-known/oauth-protected-resource`.

Agents send a JWT whose `aud` is this service's MCP resource URL (`…/mcp`, RFC 8707). The `scope` claim must include `storage`. Tool bodies do not grant authority: storage reads only verified JWT claims for gates and assertions.

**Personal vs delegated:** A **personal** regional agent token has no `global_company_id` (and no `global_agent_id`). It is intended for direct use against this service with the storage MCP resource as `aud`. A **delegated** regional token includes `global_company_id` (and usually `global_agent_id` from the SaaS subject); it is the shape you get after the AI gateway or another regional exchange turns a global credential into a storage-scoped regional JWT. Do not point a global Shellui access JWT from the SaaS product directly at storage-service (`aud` will not match). This handbook covers only what storage-service enforces; it does not document separate storage integration or secrets MCP servers.

Exchange for regional tokens uses the Identity OAuth token endpoint for that region (for example `POST /oauth/token`). There is no storage-specific exchange URL. Pass the storage MCP resource as `aud` or `resource` per Identity docs.

## Live delegated authority (regional tokens)

Contract names and path match **identity-service** PR #135 (for example git ref `d7fe351`; storage does not accept legacy alias routes).

If `global_company_id` is present and `mcp_authority` is `delegated` (regional exchange token), storage-service calls Identity on the delegated-sensitive path after JWT verification (for example authentication on `POST /mcp`, plus approval flows that rely on the same live row).

**HTTP contract (default path; override with `IDENTITY_MCP_DELEGATED_AUTHORITY_PATH`):**

- `POST {IDENTITY_SERVICE_URL}/api/v1/mcp/internal/mcp-agent-delegated-authority`
- `Authorization: Bearer <service RS256 assertion>`
- Service assertion `aud`: `shellui-mcp-agent-delegated-authority`, `scope`: `mcp.agent.delegated.authority.read`, `target`: Identity issuer URL (see `apps.authapi.mcp_authority.build_mcp_agent_authority_assertion`)

### Request body (strict)

These keys only, same types as verified JWT claims (no string digit coercion into ints in this client):

- `agent_id` (string)
- `company_id` (int, `>= 1`, matches Identity positive regional company id)
- `global_company_id` (canonical lowercase UUID string)
- `grant_version` (int, `>= 0`)
- `company_binding_version` (int, `>= 0`)

### Response (strict)

On **200**, the JSON object must have exactly these 15 keys (no extras), per Identity ``McpInternalDelegatedAgentAuthorityView``:

- `authorized`, `active`, `revoked`, `paused` (JSON booleans, not strings)
- `agent_id`, `company_id`, `global_agent_id`, `global_company_id`, `grant_version`, `company_binding_version`
- `access_mode`, `read_level`, `allow_destructive` (live agent caps)
- `services_allowed` (JSON array of service id strings)
- `revoked_at` (JSON int epoch seconds, or JSON null)

For every outcome, values for `agent_id`, `company_id`, `global_company_id`, `grant_version`, and `company_binding_version` in the response must match the POST body. `global_agent_id` in the response must match the verified JWT.

When `authorized` is true, storage also requires the JWT to match the live row: `mcp_access` must equal `access_mode`, `mcp_read` must equal `read_level`, `mcp_destructive` must equal `allow_destructive`, and the sorted set of space-separated `scope` tokens must equal the sorted set of `services_allowed` entries (same services, no extra allowance on either side). Delegated exchange agents get `allow_destructive` false from Identity (destructive flows still use approvals). When `authorized` is true, `revoked_at` must be null.

### Errors and caching

- Transport failure or Identity **5xx**: MCP answers `503` with `identity_unavailable` (fail closed).
- Identity **401** on this route (assertion rejected): same `503` (`identity_unavailable`).
- Identity **404** (agent not found or not a delegated exchange agent): deny delegated use; `POST /mcp` returns **403** with `forbidden`.
- Identity **403**: deny delegated use; `POST /mcp` returns **403** with `forbidden`.
- **200** with any failed check above: same **403** (`forbidden`).

A short in-process TTL caches **positive** outcomes only. The cache key includes the revocation cache epoch plus the delegated identity tuple; TTL is `min(5 seconds, signed revocation list cache_seconds)`. Negative outcomes are not cached, so a small lag after revocation is possible but an infinite allow from a stale deny is not.

Personal regional tokens (no `global_company_id`) skip this live step. Configure `IDENTITY_MCP_DELEGATED_AUTHORITY_PATH` when Identity mounts the check elsewhere (see `docs/configuration.md`).

## Direct `POST /mcp` versus gateway

- **Direct:** clients call this service at `POST {public origin}/mcp` (see `STORAGE_PUBLIC_URL`). Tools use paths such as `/storage/v1/...` from OpenAPI.
- **Gateway:** regional Shellui gateways may expose MCP under a company-scoped prefix such as `…/c/{numeric_company_id}/mcp`. That is routing only. Tool names are `storage_<verb>_<noun>` (the same names the gateway publishes). OpenAPI `operationId` values stay `storage_v1_*` and `api_v1_*`. The bearer token still targets this service's resource URL (`…/mcp`) per RFC 8707.

Company AI clients usually connect through the ai-service gateway (`/c/<company_id>/mcp`). The default `tools/list` is `ai_list_services`, `ai_search_tools`, `ai_describe_tool`, and `ai_call_tool`. It also includes one list read per connected service. For storage, that read is `storage_list_bucket`.

Clients can request the full list with `?tools=all`. `ai_call_tool` uses the same approvals as a direct call. A direct service `POST /mcp` still returns this service's full catalog.

The ai-service gateway records every `tools/call`. This service does not post call logs to Identity. A client can call `POST /mcp` here directly, including with a personal regional token. That request does not pass through the gateway, so it is absent from the gateway call log.

## Agent role

Agent access tokens are accepted only on `POST /mcp`. Every other route, including the REST API, WebDAV, signed downloads and the scheduled-job routes, returns 401 for an agent token. A refresh token, a setup token or any token whose `token_type` is not `access` is not a bearer anywhere.

### Who an agent acts as

A personal agent acts as its creator. The principal's user id is `owner_user_id`, and its company role is the creator's own live role. Storage reads it from the `creator_status` field (`owner`, `member` or `gone`) of Identity's signed revocation snapshot, which it already polls every 30 seconds, and never from the token. A demotion applies on the next poll, and a creator who has left the company (`gone`) makes the agent fail with 401. A missing status, for example from an older Identity, is a plain member. A global or delegated token has no creator at all: it is user `0` and a plain member, whatever owner id or role-looking claim it carries, so it never reads its creator's private files. The agent sees and manages the files its creator can, with the same grants, and no others. Staff status never passes to an agent, including when the creator is staff. Role-looking fields such as `user_metadata` are ignored on an agent token.

An agent with no creator has user id `0`, which means "no user". It never matches a private file or a user grant. It can read and write company-visible files at its role (folders that carry a company grant), and it cannot upload a private file: the call fails with 403 `agent_has_no_owner` before the body is read, and nothing is stored. Create the agent from a user account, or upload into a folder that is already shared with the company.

### Agents and sharing

An agent cannot create or widen sharing. Creating or deleting an access grant and creating a share link are refused for agents, and those tools are not listed on `/mcp`. Calling one by name returns "Unknown tool". Narrowing stays available: an agent can list grants and share links and can revoke a share link it could already manage.

Routes marked `global_refused` (the scheduled-job routes) are not listed and are refused for agents.

Connector writes, quota changes, and Shellui Actions admin routes follow the creator's live role. An agent created by a company owner has owner access to them, and every write still goes through the approval modes below. An agent with a member creator, or no creator, receives 403 on those routes.

### Calls that always need approval

These need a person's single-use approval from an agent in every access mode, `full` included (a read only agent is refused outright):

- creating or updating an Actions webhook (`api_v1_actions_rules_create`, `api_v1_actions_rules_partial_update`)
- any quota change (`storage_v1_quota_company_update`, `storage_v1_quota_company_user_update`)
- mounting an outside bucket with credentials (`storage_v1_connector_create`). Changing or deleting a connector is already destructive and needs approval.
- moving, copying or renaming a file or folder so that anyone could read something they could not read before (`storage_v1_object_copy_create`, `storage_v1_object_move_create`, `storage_v1_object_prefix_create`). Keys are normalized the way the views do before any lookup. For each object the call affects, including every object under a moved or renamed prefix and every object left in a folder whose marker moves, storage works out who can read it now and who could read it afterwards, with the real access check (specific grants, deny wins), for a plain company member and for every person a grant names. The call is applied inside a transaction that is rolled back, so nothing changes. If anyone gains read access, or the source cannot be found or resolved, the call asks first. Staying private to the same people never asks, and a copy by an agent with no creator, which has no private space, always asks.

## Required agent token claims

Claims must use the types below. Types match Identity's regional agent access token (shellui/identity-service). There are no aliases (for example no `permission_version`). Strings are not coerced into numbers.

| Claim | Personal regional | Delegated (SaaS or global exchange) |
| --- | --- | --- |
| `company_id` | integer (regional, `>= 1`) | integer, `>= 1` (must match the snapshot row) |
| `grant_version` | required, integer 0 or higher | required, integer 0 or higher |
| `global_company_id` | omit | required UUID string |
| `company_binding_version` | omit | required integer, explicit 0 allowed |
| `global_agent_id` | omit | required for delegated exchange tokens (same lexical rules as `global_company_id`) |
| `personal_token_id` | optional UUID | omit for delegated |
| `mcp_authority` | omit | required `delegated` for exchange tokens that carry `global_company_id`; must not be `global_delegated` on regional resource tokens (that value is for direct SaaS-issued tokens only) |

If any rule fails, `POST /mcp` returns `401` with `identity_invalid`.

Connectors: at most five connector mounts are documented for agents; service-scoped tools outside `storage` are not advertised here (`scope` must still include `storage` for this service).

## Revocation and staleness

Identity returns a signed `revocation_assertion` with optional `revocation_policy_version`, `max_active_grant_version`, and agent rows. storage verifies the JWT with Identity's JWKS (`verify_mcp_revocation_list_response` in django-commons). Values in the HTTP body must match the signed claims.

When the list is unavailable, `POST /mcp` returns `503` with `identity_unavailable`.

When the signed list includes `max_active_grant_version` and the token carries `grant_version`, storage returns `409` with `out_of_sync` if `grant_version` is lower. Personal tokens may omit `grant_version`; in that case the cap is not applied. Delegated tokens must include `grant_version` for a full snapshot; if the cap is missing from the signed response, delegated requests fail closed (`503`). The cap never replaces a live snapshot: delegated tokens also need exactly one trusted snapshot row that matches regional `company_id`, canonical lowercase `global_company_id`, `company_binding_version`, and `grant_version`. Identity normalizes delegated numeric fields when verifying the signed list; storage matches the resulting ints to the token.

Revocation rows: personal snapshots use regional `company_id` only. Delegated snapshots use `global_company_id`, `company_binding_version`, and `grant_version` together, plus the same regional `company_id` as the token. storage does not match a delegated agent across companies and does not fall back to another row when a snapshot is malformed or incomplete. If the trusted list has no row for that agent, delegated access is denied. If it lists the agent but no row matches the token, or more than one row matches, access is denied. Personal tokens may proceed when there is no row for that agent as long as the agent is not in `revoked_ids` and other checks pass.

An HTTP operation becomes an MCP tool only when it is registered with `mcp_tool(operation_id=..., read_only=..., ...)` in code. There is no automatic opt-in from tags or paths.

## OpenAPI markers

Each exposed operation includes:

```yaml
x-mcp:
  read_only: true|false
  destructive: true|false
  sensitive: true|false
```

Response fields may carry `x-mcp-secret` (never return to agents) or `x-mcp-sensitive` (mask in read-safe MCP modes).

The published schema excludes `/api/v1/internal/*` and `/api/v1/scheduled-jobs*`.

## Storage tools (`/storage/v1/`)

| Area | Examples |
| --- | --- |
| Buckets | List and read the company bucket; empty a bucket (destructive). |
| Connectors | List and read mounts. Create, update, delete, and configuration checks need a company owner (the agent's creator, for an agent) or staff (`credential` is `x-mcp-secret`). Other agents receive 403 on those writes. |
| Objects | List, upload, download, move, copy, delete, folder prefix stats, rename, delete, signed URLs. |
| Access | List path-level access grants. Agents cannot create or delete grants. |
| Share links | List links for an object; revoke by token (not anonymous redeem). Agents cannot create share links. |
| Quotas | Read usage; set company or per-user limits (company owner). |
| Stats | Upload and storage statistics for the company. |

See [Buckets, folders, and files](buckets-and-objects.md), [Access grants](access.md), [Share links](sharing.md), and [Quotas](quotas.md).

## Shellui Actions tools (`/api/v1/actions/`)

Webhook rules, deliveries, event types, and the company event log carry `x-mcp` when intended for agents. Signing secrets stay masked in MCP results. The admin HTTP create and rotate responses return the secret once. See [Webhooks](actions.md).

## Not available to agents

- Public object downloads and anonymous share redeem URLs

- `POST /api/v1/internal/company-deletions` (identity-service assertion only)

- Scheduled job monitoring under `/api/v1/scheduled-jobs`

## Connect a client

1. Complete OAuth through Shellui Identity (see Identity docs for MCP and agents).

2. Call `POST /mcp` on this service with `Authorization: Bearer <agent access token>`.

3. Use JSON-RPC methods `initialize`, `tools/list`, and `tools/call`.

Before the inner REST handler runs, storage checks that the tool name, OpenAPI path template, and HTTP method match the published registry (`operationId`). A mismatch returns JSON-RPC `-32602` and the handler does not run.

Successful tool execution in JSON-RPC means `result.isError` is false. The inner storage HTTP handler may still return a Supabase-shaped body with `error` or `statusCode` while using HTTP `200`; that case is treated as failure and surfaces as `result.isError` true (HTTP status on the MCP response may be `422` for observability). Do not treat HTTP status on the MCP response alone as success for `tools/call`; inspect `isError` and the text payload.

Use `IDENTITY_SERVICE_URL` and `IDENTITY_ISSUER` for OAuth metadata and Identity internal APIs (revocation and approvals).

### Example `tools/list` (excerpt)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

### Example tools (from OpenAPI)

Published MCP names are `storage_<verb>_<noun>` from `x-mcp.tool_name`. OpenAPI `operationId` values stay `storage_v1_*` and `api_v1_*`. Examples:

**List buckets** (`storage_list_bucket`): `GET /storage/v1/bucket`. The default bucket id is `company` (auto-created). **Create bucket** (`storage_v1_bucket_create`, not an MCP tool) may respond with `bucket_create_disabled` when custom buckets are not enabled for the company.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "storage_list_bucket",
    "arguments": {}
  }
}
```

**List objects** (`storage_create_object_list`): `POST /storage/v1/object/list/{bucket_id}`. Body schema `ObjectListRequest`: optional `prefix`, `limit`, `offset`, `search`, `sortBy`.

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "storage_create_object_list",
    "arguments": {
      "bucket_id": "company",
      "prefix": "",
      "limit": 50
    }
  }
}
```

**Create connector mount** (`storage_create_connector`): `POST /storage/v1/connector`. Body schema `ConnectorBucketCreate` requires `name`, `connector_provider`; optional `connector_settings`, `credential` (`x-mcp-secret`, write-only).

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "storage_create_connector",
    "arguments": {
      "name": "backup",
      "connector_provider": "s3",
      "connector_settings": {}
    }
  }
}
```

## Tool arguments

`tools/list` names are `storage_<verb>_<noun>` from `x-mcp.tool_name`. OpenAPI `operationId` values stay `storage_v1_*` and `api_v1_*`. Arguments are the path, query, and body fields in one object. Do not send HTTP method, URL, `query`, `body`, or `path_params`. A field with a fixed set of values has `enum` and a short description. Required fields are the required path fields and required body fields.

`object_path` may contain `/`. Example: `notes/a.txt`.

Object upload and replace (`storage_create_object`, `storage_replace_object`) take a JSON body:

- `content_base64`: file bytes as standard base64, with padding
- `content_type`: optional MIME type (`application/octet-stream` when omitted)

Downloads return JSON text with `content_base64`, `content_type`, and `size`. An object larger than 8 MB returns `object_too_large_for_mcp`. Call a sign tool and fetch that URL instead.

`storage_delete_many_object` takes `{ "prefixes": ["a.txt"] }` or `{ "paths": ["a.txt"] }`.

`storage_delete_object_prefix` requires body `prefix`. The handler also reads query `prefix` when the body value is empty. The MCP schema still requires the body field.

Create share returns `token` once. Later reads omit it. Webhook signing secrets stay masked in MCP results. The admin HTTP create and rotate responses return `secret` once. `path_url` is redacted on every MCP response because the path contains the share token.

`tools/list` sets `annotations.readOnlyHint` and `annotations.destructiveHint`. Destructive tools need a fresh approval before the call runs. Other writes run when `mcp_access` is `full`, and need approval when `mcp_access` is `ask`.

## Internal assertions to Identity

Revocation polling and approvals send short-lived RS256 assertions signed with this service's key (`STORAGE_SERVICE_SIGNING_KEY`, issuer `STORAGE_SERVICE_ISSUER`). The public key is at `GET /.well-known/jwks.json` (same origin as this service). Identity must register that issuer; dynamic values such as `GITHUB_SHA` are not a substitute for the stable issuer string.

Approval assertions use `shellui_django.mcp.internal.build_mcp_approval_assertion` with the same delegated fields as the agent token when the exchange triple is present (default assertion lifetime is the ordinary internal limit, 60 seconds). Personal tokens still pass `grant_version` when present on the JWT. Internal approval HTTP calls send an empty JSON body; authority is carried only in the signed assertion (including `arguments_hash`). Storage does not call Identity to create an approval for exchange-delegated agents (`global_company_id` with `mcp_authority: delegated`); those flows must use the AI gateway (MCP surfaces `out_of_sync` instead of probing Identity with `{}`).

Generate a key with `openssl genrsa 3072` and store it in a secret or file (`STORAGE_SERVICE_SIGNING_KEY_FILE`).

Approval consume (Identity #136): storage uses **HTTP status at the boundary** (`409` means not reusable; `200` with `consumed: true` means consumed). For `200` with `consumed: false`, it maps to **denied** with `error_code` **expired** only when the response body text (for example `detail` / `message` / `error`) indicates the approval was already consumed; it does not trust guessed JSON fields such as `error_code` or `http_status` in the body.

Delegated agents must create approvals through the AI gateway; storage returns `out_of_sync` on MCP when a delegated token attempts direct approval creation without the gateway.

## Upgrading: files stored as user 0

Earlier versions gave every agent upload to user `0`, with no way to tell whose agent wrote it. After this change an agent acts as its creator, and user `0` matches nobody. The migration `0008_unowned_agent_files` therefore labels the legacy grants and keeps every file in place:

- Files whose owner is user `0` stay visible to and manageable by company owners and Shellui staff of that company. Members and agents do not see them until an owner decides.
- Nothing is deleted or moved, and quota usage does not change.
- Storage keeps no record that links an upload to an agent or its creator (the event log has no agent id), so storage cannot reassign them on its own.

To give files to a person, run, per company and optionally per folder:

```bash
python manage.py reassign_unowned_files --company 10 --user 42 --prefix reports/ --dry-run
python manage.py reassign_unowned_files --company 10 --user 42 --prefix reports/
```

It moves the owner, the private grants, the creator id and the per-user quota usage to that user. Run it with `--dry-run` first.

Deploy order: deploy Identity (#195) first, so the revocation snapshot carries `creator_status`, then storage. Until then every agent acts as a plain member of its creator, never as an owner.
