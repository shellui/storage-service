---
title: Shellui MCP
sidebar_label: Shellui MCP
description: Company-owner storage APIs that Shellui MCP agents may call, and how they are marked in OpenAPI.
---

# Shellui MCP

Shellui MCP exposes company-scoped storage HTTP APIs as tools. storage-service implements `POST /mcp` (Streamable HTTP JSON-RPC). Identity issues OAuth tokens; this service publishes OpenAPI with `x-mcp` extensions and OAuth protected-resource metadata at `/.well-known/oauth-protected-resource`.

Agents send a JWT whose `aud` is this service's MCP resource URL (`…/mcp`, RFC 8707). The `scope` claim must include `storage`. Tool bodies do not grant authority: storage reads only verified JWT claims for gates and assertions.

Do not point a global Shellui access JWT from the SaaS product directly at storage-service. Personal MCP uses a regional resource audience from Identity. Global agents reach storage through the AI gateway, which mints a regional MCP credential with the correct `aud` (see Shellui SaaS documentation on `develop` once the handbook merges).

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

Use `IDENTITY_SERVICE_URL` and `IDENTITY_ISSUER` for OAuth metadata and Identity internal APIs (revocation, approvals, call logs).

## Internal assertions to Identity

Revocation polling, approvals, and call logs send short-lived RS256 assertions signed with this service's key (`STORAGE_SERVICE_SIGNING_KEY`, issuer `STORAGE_SERVICE_ISSUER`). The public key is at `GET /.well-known/jwks.json` (same origin as this service). Identity must register that issuer; dynamic values such as `GITHUB_SHA` are not a substitute for the stable issuer string.

Approval assertions use `shellui_django.mcp.internal.build_mcp_approval_assertion` with the same optional delegated fields as the agent token (default assertion lifetime is the ordinary internal limit, 60 seconds). Personal tokens may omit `grant_version` in the assertion; delegated tokens pass the full triple. Internal approval HTTP calls send an empty JSON body; authority is carried only in the signed assertion (including `arguments_hash`).

This repo pins `shellui-django[mcp]` to an exact commit on [django-commons](https://github.com/shellui/django-commons) (`1f0754b421688ed26b7eb2e76b25b6fa3eea2a37`). Install with `uv lock` and `uv sync`; Docker images install `git` so `uv` can fetch that git source dependency.

Generate a key with `openssl genrsa 3072` and store it in a secret or file (`STORAGE_SERVICE_SIGNING_KEY_FILE`).

### Call log payload to Identity

Each tool attempt forwards a small JSON object. Allowed keys are fixed; values are type-checked and trimmed. `tool`, `resource_path`, and `http_method` are matched against the published OpenAPI registry (`operationId` plus path template and method). `operation_title` is taken from that operation's `summary` when present; arbitrary titles from the caller are not forwarded. Paths are OpenAPI templates only (no resolved ids, no query strings). There is no raw MCP `arguments` map and no response body in the log payload.

Fields include `tool`, `operation_title`, `resource_path`, `http_method`, `access_kind` (`read` or `write`), `outcome`, `status`, `duration_ms`, optional `error_code`, `grant_version`, optional `global_company_id` and `company_binding_version`, and UUID `approval_request_id` / `approval_id` when applicable. Allowed `outcome` values are `pending_approval`, `allowed`, `denied`, `failed`, and `session_used`. Error taxonomy for failures uses `error_code`, not nested objects.
