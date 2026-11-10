---
title: Shellui MCP
sidebar_label: Shellui MCP
description: Company-owner storage APIs that Shellui MCP agents may call, and how they are marked in OpenAPI.
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
| Connectors | List, read, create, update, delete connector mounts; re-run local configuration checks (`configuration/check`, `configuration/validate`, `configuration/retry`; company owner; `credential` is `x-mcp-secret`). |
| Objects | List, upload, download, move, copy, delete, folder prefix stats, rename, delete, signed URLs. |
| Access | List, create, and revoke path-level access grants. |
| Share links | Create and list links for an object; revoke by token (not anonymous redeem). |
| Quotas | Read usage; set company or per-user limits (company owner). |
| Stats | Upload and storage statistics for the company. |

See [Buckets, folders, and files](buckets-and-objects.md), [Access grants](access.md), [Share links](sharing.md), and [Quotas](quotas.md).

## Shellui Actions tools (`/api/v1/actions/`)

Webhook rules, deliveries, event types, and the company event log carry `x-mcp` when intended for agents. Signing secrets stay masked in MCP results. The admin HTTP create and rotate responses return the secret once. See [Webhooks](actions.md).

## Not available to agents

- `GET /storage/v1/metrics` and `/metrics/all` (Prometheus; staff or global PAT)

- Public object downloads and anonymous share redeem URLs

- `POST /api/v1/internal/company-deletions` (identity-service assertion only)

- Scheduled job monitoring under `/api/v1/scheduled-jobs`

## Connect a client

1. Complete OAuth through Shellui Identity (see Identity docs for MCP and agents).

2. Call `POST /mcp` on this service with `Authorization: Bearer <agent access token>`.

3. Use JSON-RPC methods `initialize`, `tools/list`, and `tools/call`.

Successful tool execution in JSON-RPC means `result.isError` is false. The inner storage HTTP handler may still return a Supabase-shaped body with `error` or `statusCode` while using HTTP `200`; that case is treated as failure and surfaces as `result.isError` true (HTTP status on the MCP response may be `422` for observability). Do not treat HTTP status on the MCP response alone as success for `tools/call`; inspect `isError` and the text payload.

Use `IDENTITY_SERVICE_URL` and `IDENTITY_ISSUER` for OAuth metadata and Identity internal APIs (revocation, approvals, call logs).

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

Operation ids match `tools/list` names. Examples:

**List buckets** (`storage_list_bucket`): `GET /storage/v1/bucket`. The default bucket id is `company` (auto-created). **Create bucket** (`storage_v1_bucket_create`, not an MCP tool) may respond with `bucket_create_disabled` when custom buckets are not enabled for the company.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "storage_list_bucket",
    "arguments": {
      "path": "/storage/v1/bucket",
      "method": "GET",
      "query": {},
      "body": {}
    }
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
      "path": "/storage/v1/object/list/{bucket_id}",
      "method": "POST",
      "path_params": {"bucket_id": "company"},
      "query": {},
      "body": {"prefix": "", "limit": 50}
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
      "path": "/storage/v1/connector",
      "method": "POST",
      "query": {},
      "body": {
        "name": "backup",
        "connector_provider": "s3",
        "connector_settings": {}
      }
    }
  }
}
```

## Tool arguments

`tools/list` names match OpenAPI `operationId` values. Each input schema requires `path` and `method`. Copy both from the tool. When the path has parameters, send `path_params` too.

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

Revocation polling, approvals, and call logs send short-lived RS256 assertions signed with this service's key (`STORAGE_SERVICE_SIGNING_KEY`, issuer `STORAGE_SERVICE_ISSUER`). The public key is at `GET /.well-known/jwks.json` (same origin as this service). Identity must register that issuer; dynamic values such as `GITHUB_SHA` are not a substitute for the stable issuer string.

Approval assertions use `shellui_django.mcp.internal.build_mcp_approval_assertion` with the same delegated fields as the agent token when the exchange triple is present (default assertion lifetime is the ordinary internal limit, 60 seconds). Personal tokens still pass `grant_version` when present on the JWT. Internal approval HTTP calls send an empty JSON body; authority is carried only in the signed assertion (including `arguments_hash`). Storage does not call Identity to create an approval for exchange-delegated agents (`global_company_id` with `mcp_authority: delegated`); those flows must use the AI gateway (MCP surfaces `out_of_sync` instead of probing Identity with `{}`).

Generate a key with `openssl genrsa 3072` and store it in a secret or file (`STORAGE_SERVICE_SIGNING_KEY_FILE`).

### Call log payload to Identity

Each tool attempt forwards a small JSON object. Before executing the inner REST handler, storage checks that the tool `name`, OpenAPI path template, and inner HTTP method match the published registry (`operationId` triple); mismatches answer JSON-RPC `-32602` and are not executed. When the caller marks the row trusted (`tool_registry_valid`), a rare OpenAPI triple mismatch is still forwarded with a warning log so owner-visible activity is not wiped. **Identity ingest** expects the downstream JSON-RPC surface only: wire `method` is always **`POST`**, and wire **`path` is always the literal `/mcp`** (public MCP activity route; not a host prefix derived from `STORAGE_PUBLIC_URL`). Identity maps that to a stable `resource_label` for the service.

Storage does not forward `operation_title`, `resource_label`, `global_agent_id`, `result`, or raw MCP arguments. There is no raw MCP `arguments` map in the log payload.

Fields on the wire include `agent_id`, `company_id`, `service`, `tool`, `scope` (exact string from the verified JWT, unchanged), `method`, `path`, `access_kind`, required `outcome`, `status` (non-negative int), `duration_ms`, `grant_version` (strict JSON int copied from the verified JWT), optional `error_code`. **Delegated** agents (regional token with `global_company_id`) send `global_company_id` and `company_binding_version` on the wire; **personal** agents omit both.

For inner REST operations classified as **destructive**, successful `allowed` or `session_used` rows require a canonical `approval_id` (UUID). Other destructive outcomes keep `access_kind` **destructive** (for example waiting on approval or failure) so the log stays truthful. For successful `allowed` rows with HTTP status below 400, `error_code` is omitted even when an inner business error was redacted into the MCP result text (the legacy `result` field is not forwarded). Canonical outcomes are `waiting_approval`, `allowed`, `denied`, `failed`, and `session_used`; legacy `pending_approval` is normalized to `waiting_approval` before forward. **session_used** is reserved for valid session-permission reuse within TTL, not for consumed approvals. Error taxonomy for failures uses `error_code`, not nested objects; values outside Identity's allowlist map to `unknown`.

Approval consume (Identity #136): storage uses **HTTP status at the boundary** (`409` means not reusable; `200` with `consumed: true` means consumed). For `200` with `consumed: false`, it maps to **denied** with `error_code` **expired** only when the response body text (for example `detail` / `message` / `error`) indicates the approval was already consumed; it does not trust guessed JSON fields such as `error_code` or `http_status` in the body.

Delegated agents must create approvals through the AI gateway; storage returns `out_of_sync` on MCP when a delegated token attempts direct approval creation without the gateway.
