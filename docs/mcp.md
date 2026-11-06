---
title: Shellui MCP
sidebar_label: Shellui MCP
description: Company-owner storage APIs that Shellui MCP agents may call, and how they are marked in OpenAPI.
---

# Shellui MCP

Shellui MCP exposes company-scoped storage HTTP APIs as tools. storage-service implements `POST /mcp` (Streamable HTTP JSON-RPC). Identity issues OAuth tokens; this service publishes OpenAPI with `x-mcp` extensions and OAuth protected-resource metadata at `/.well-known/oauth-protected-resource`.

Agents send a JWT whose `aud` is this service's MCP resource URL (`…/mcp`, RFC 8707). The `scope` claim must include `storage`. Tool bodies do not grant authority: storage reads only verified JWT claims for gates and assertions.

Do not point a global Shellui access JWT from the SaaS product directly at storage-service. Personal MCP uses a regional resource audience from Identity. Global agents reach storage through the AI gateway, which mints a regional MCP credential with the correct `aud` (see Shellui SaaS documentation on `develop` once the handbook merges).

Exchange for regional tokens uses the Identity OAuth token endpoint for that region (for example `POST /oauth/token`). There is no storage-specific exchange URL. Pass the storage MCP resource as `aud` or `resource` per Identity docs.

## Live delegated authority (regional tokens)

If `global_company_id` is present and `mcp_authority` is `delegated` (regional exchange token), storage-service calls Identity before **every** delegated-sensitive path: approval create, approval state, approval consume, and each `tools/call` that reaches a direct storage operation.

**HTTP contract (canonical unless Identity publishes a different path; override with `IDENTITY_MCP_DELEGATED_AUTHORITY_PATH`):**

- `POST {IDENTITY_SERVICE_URL}/api/v1/mcp/internal/mcp-delegated-agent-authority`
- `Authorization: Bearer <service RS256 assertion>`
- Service assertion `aud`: `shellui-mcp-agent-authority`, `scope`: `mcp.agent.authority.verify`, `target`: Identity issuer URL (see `apps.authapi.mcp_authority.build_mcp_agent_authority_assertion`).

**JSON body (only these keys, strict JSON integers for versions):**

- `agent_id` (UUID string)
- `company_id` (int, regional)
- `global_company_id` (canonical lowercase UUID string)
- `grant_version` (int, `0` is valid)
- `company_binding_version` (int, `0` is valid)

No string digit coercion: claim parsing rejects non-integers before the request is built.

**Identity must answer with a single authoritative row.** The response is rejected unless `authorized` is `true`, `revoked` is `false`, `paused` is `false`, and `row` is an object whose `agent_id`, `company_id`, `global_company_id`, `grant_version`, and `company_binding_version` match the request exactly (same int and UUID rules). Any mismatch, ambiguous semantics, `404`, `5xx`, or transport error is failure. A signed revocation list alone cannot prove “not revoked” or “active”; it only enumerates revocations. Positive authorization comes from this live check (and from the signed snapshot inside the revocation JWT where applicable).

Results for `tools/call`: if Identity is required but unavailable, the HTTP response is `503`. If Identity denies or the row does not match, the HTTP response is `401`. Wrong `iss` or `aud` on the agent token skips the network call and fails closed for delegated exchange tokens. Personal tokens (no `global_company_id`) skip this step.

A short in-process cache (at most a few seconds) is keyed with the revocation cache epoch and bounded by the signed list `cache_seconds`, so a success does not outlive the revocation validation window.

Configure `IDENTITY_MCP_DELEGATED_AUTHORITY_PATH` when Identity mounts the check elsewhere (see `docs/configuration.md`). Identity and email-service should implement the **same** URL and payload; do not keep parallel GET query routes for live checks.

## Direct `POST /mcp` versus gateway

- **Direct:** clients call this service at `POST {public origin}/mcp` (see `STORAGE_PUBLIC_URL`). Tools use paths such as `/storage/v1/...` from OpenAPI.
- **Gateway:** regional Shellui gateways may expose MCP under a company-scoped prefix such as `…/c/{numeric_company_id}/mcp`. That is routing only: the tool definitions and `storage_v1_*` operation ids are the same; the bearer token still targets this service's resource URL (`…/mcp`) per RFC 8707.

## Required agent token claims

Claims must use the types below. Types match Identity’s regional agent access token (shellui/identity-service). There are no aliases (for example no `permission_version`). Strings are not coerced into numbers.

| Claim | Personal regional | Delegated (SaaS or global exchange) |
| --- | --- | --- |
| `company_id` | integer (regional) | integer (must match the snapshot row) |
| `grant_version` | optional (omit allowed) | required, integer 0 or higher |
| `global_company_id` | omit | required UUID string |
| `company_binding_version` | omit | required integer, explicit 0 allowed |
| `global_agent_id` | omit | optional; when present, `global_company_id` and the full triple are required (no partial global) |
| `personal_token_id` | optional UUID | omit for delegated |
| `mcp_authority` | omit | required `delegated` for exchange tokens that carry `global_company_id`; must not be `global_delegated` on regional resource tokens (that value is for direct SaaS-issued tokens only) |

If any rule fails, `POST /mcp` returns `401` with `identity_invalid`.

Connectors: at most five connector mounts are documented for agents; service-scoped tools outside `storage` are not advertised here (`scope` must still include `storage` for this service).

## Revocation and staleness

Identity returns a signed `revocation_assertion` with optional `revocation_policy_version`, `max_active_grant_version`, and agent rows. storage verifies the JWT with Identity’s JWKS (`verify_mcp_revocation_list_response` in django-commons). Values in the HTTP body must match the signed claims.

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

Webhook rules, deliveries, event types, and the company event log carry `x-mcp` when intended for agents. Signing secrets are write-only except immediately after create or rotate. See [Webhooks](actions.md).

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

**List buckets** (`storage_v1_bucket_list`): `GET /storage/v1/bucket`. The default bucket id is `company` (auto-created). **Create bucket** (`storage_v1_bucket_create`) may respond with `bucket_create_disabled` when custom buckets are not enabled for the company.

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "storage_v1_bucket_list",
    "arguments": {
      "path": "/storage/v1/bucket",
      "method": "GET",
      "query": {},
      "body": {}
    }
  }
}
```

**List objects** (`storage_v1_object_list_create`): `POST /storage/v1/object/list/{bucket_id}`. Body schema `ObjectListRequest`: optional `prefix`, `limit`, `offset`, `search`, `sortBy`.

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "storage_v1_object_list_create",
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

**Create connector mount** (`storage_v1_connector_create`): `POST /storage/v1/connector`. Body schema `ConnectorBucketCreate` requires `name`, `connector_provider`; optional `connector_settings`, `credential` (`x-mcp-secret`, write-only).

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "storage_v1_connector_create",
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

## Internal assertions to Identity

Revocation polling, approvals, and call logs send short-lived RS256 assertions signed with this service's key (`STORAGE_SERVICE_SIGNING_KEY`, issuer `STORAGE_SERVICE_ISSUER`). The public key is at `GET /.well-known/jwks.json` (same origin as this service). Identity must register that issuer; dynamic values such as `GITHUB_SHA` are not a substitute for the stable issuer string.

Approval assertions use `shellui_django.mcp.internal.build_mcp_approval_assertion` with the same optional delegated fields as the agent token (default assertion lifetime is the ordinary internal limit, 60 seconds). Personal tokens may omit `grant_version` in the assertion; delegated tokens pass the full triple. Internal approval HTTP calls send an empty JSON body; authority is carried only in the signed assertion (including `arguments_hash`).

This repo pins `shellui-django[mcp]` to an exact commit on [django-commons](https://github.com/shellui/django-commons) (`1f0754b421688ed26b7eb2e76b25b6fa3eea2a37`). Install with `uv lock` and `uv sync`; Docker images install `git` so `uv` can fetch that git source dependency.

Generate a key with `openssl genrsa 3072` and store it in a secret or file (`STORAGE_SERVICE_SIGNING_KEY_FILE`).

### Call log payload to Identity

Each tool attempt forwards a small JSON object. Allowed keys are fixed; values are type-checked and trimmed. `tool`, `resource_path`, and `http_method` are matched against the published OpenAPI registry (`operationId` plus path template and method). `operation_title` is taken from that operation's `summary` when present; arbitrary titles from the caller are not forwarded. Paths are OpenAPI templates only (no resolved ids, no query strings). There is no raw MCP `arguments` map and no response body in the log payload.

Fields include `tool`, `operation_title`, `resource_path`, `http_method`, `access_kind` (`read` or `write`), `outcome`, `status`, `duration_ms`, optional `error_code`, `grant_version`, optional `global_company_id` and `company_binding_version`, and UUID `approval_request_id` / `approval_id` when applicable. Allowed `outcome` values are `pending_approval`, `allowed`, `denied`, `failed`, and `session_used`. Error taxonomy for failures uses `error_code`, not nested objects.
