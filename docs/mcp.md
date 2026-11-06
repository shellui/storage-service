---
title: Shellui MCP
sidebar_label: Shellui MCP
description: Company-owner storage APIs that Shellui MCP agents may call, and how they are marked in OpenAPI.
---

# Shellui MCP

Shellui MCP exposes company-scoped storage HTTP APIs as tools. storage-service implements `POST /mcp` (Streamable HTTP JSON-RPC). Identity issues OAuth tokens; this service publishes OpenAPI with `x-mcp` extensions and OAuth protected-resource metadata at `/.well-known/oauth-protected-resource`.

Agents send a JWT whose `aud` is this service's MCP resource URL (`…/mcp`, RFC 8707). The `scope` claim must include `storage`. Tool bodies do not grant authority: storage reads only verified JWT claims for gates and assertions.

## Required agent token claims

Claims must use the types below. There are no aliases (for example no `permission_version`). Strings are not coerced into numbers.

- **`company_id`** (integer, regional tenant id)

- **`grant_version`** (integer, 0 or higher): optional for personal regional tokens (no `global_company_id`). Required when `global_company_id` is present (delegated global authority); do not omit it and rely on a default.

- **`global_company_id`** (optional): when present, a lowercase UUID string for the global org. Omit for personal regional tokens.

- **`company_binding_version`** (integer, 0 or higher): required when `global_company_id` is present (explicit `0` is valid); must be absent when `global_company_id` is absent.

If any rule fails, `POST /mcp` returns `401` with `identity_invalid`.

## Revocation and staleness

Identity returns a signed `revocation_assertion` with `revocation_policy_version`, `max_active_grant_version`, and optional agent rows. storage rejects the poll when those signed fields are missing or malformed.

When the list is unavailable, `POST /mcp` returns `503` with `identity_unavailable`.

When the token carries `grant_version` and it is below `max_active_grant_version`, storage returns `409` with `out_of_sync`. Personal tokens without `grant_version` skip this check.

Revocation rows use the same typing rules: regional `company_id` is an integer; `global_company_id` in a row is a UUID string. storage does not compare regional ids to global UUIDs.

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

Revocation polling, approvals, and call logs send short-lived RS256 assertions signed with this service's key (`STORAGE_SERVICE_SIGNING_KEY`, issuer `STORAGE_SERVICE_ISSUER`). The public key is at `GET /.well-known/jwks.json`. Identity trusts it only when `STORAGE_SERVICE_ISSUER` matches its registration.

Approval assertions use `shellui_django.mcp.internal.build_mcp_approval_assertion` with the same optional delegated fields as the agent token (default assertion lifetime is the ordinary internal limit, 60 seconds).

This repo pins `shellui-django[mcp]` to an exact commit on [django-commons](https://github.com/shellui/django-commons) (`5f0fdf44bb140848fb1440cf04da6ada7996711d`) until a matching release is published to PyPI. Local development needs Git available to install that source dependency; workflows use `uv lock` / `uv sync` accordingly.

Generate a key with `openssl genrsa 3072` and store it in a secret or file (`STORAGE_SERVICE_SIGNING_KEY_FILE`).

### Call log payload to Identity

Each tool attempt forwards a small JSON object. Allowed keys are fixed; values are type-checked and trimmed. There is no raw MCP `arguments` map and no response body: only a `result_shape` enum (`dict`, `list`, `scalar`, `empty`).

Fields include `tool`, `operation_title` (from OpenAPI `summary`, truncated), `path` (no query string), `method`, `access_kind`, `outcome`, `status`, `duration_ms`, `error` (`code` only), `grant_version`, optional `global_company_id` and `company_binding_version`, and UUID `approval_request_id` / `approval_id` when applicable.
