---
title: Shellui MCP
sidebar_label: Shellui MCP
description: Company-owner storage APIs that Shellui MCP agents may call, and how they are marked in OpenAPI.
---

# Shellui MCP

Shellui MCP connects AI agents to company-scoped storage APIs. storage-service runs `POST /mcp` (Streamable HTTP JSON-RPC). Identity remains the OAuth authorization server; this service publishes OpenAPI with `x-mcp` extensions and exposes OAuth protected-resource metadata at `/.well-known/oauth-protected-resource`.

Agents authenticate with a JWT whose `aud` is this service's MCP resource URL (`…/mcp`, RFC 8707) only. The token `scope` claim must include `storage`. Agents act as the company owner for the JWT `company_id`. Agent tokens cannot approve their own pending requests; only a company owner user JWT can approve in Identity. Staff-only routes, anonymous share redeem URLs, and internal service callbacks are never MCP tools.

An HTTP operation becomes an MCP tool only when it is registered with `mcp_tool(operation_id=..., read_only=..., ...)` in code. There is no automatic opt-in from tags or paths.

## OpenAPI markers

Each exposed operation includes:

```yaml
x-mcp:
  read_only: true|false
  destructive: true|false
  sensitive: true|false
```

Response fields may carry `x-mcp-secret` (never return to agents, for example share link tokens) or `x-mcp-sensitive` (mask in read-safe MCP modes).

The published schema excludes `/api/v1/internal/*` and `/api/v1/scheduled-jobs*`.

## Storage tools (`/storage/v1/`)

| Area | Examples |
| --- | --- |
| Buckets | List and read the company bucket; empty a bucket (destructive). |
| Connectors | List, read, create, update, delete connector mounts; refresh, test, or retry connectivity (company owner; `credential` is `x-mcp-secret`). |
| Objects | List, upload, download, move, copy, delete, folder prefix stats/rename/delete, signed URLs. |
| Access | List, create, and revoke path-level access grants. |
| Share links | Create and list links for an object; revoke by token (not anonymous redeem). |
| Quotas | Read usage; set company or per-user limits (company owner). |
| Stats | Upload and storage statistics for the company. |

See [Buckets, folders, and files](buckets-and-objects.md), [Access grants](access.md), [Share links](sharing.md), and [Quotas](quotas.md).

## Shellui Actions tools (`/api/v1/actions/`)

Webhook rules, deliveries, event types, and the company event log carry `x-mcp` when intended for agents. Signing secrets are write-only except immediately after create or rotate. See [Webhooks](actions.md).

## Not available to agents

- `GET /storage/v1/metrics` and `/metrics/all` (Prometheus; staff or global PAT).
- Public object downloads and anonymous share redeem URLs.
- `POST /api/v1/internal/company-deletions` (identity-service assertion only).
- Scheduled job monitoring under `/api/v1/scheduled-jobs`.

## Connect a client

1. Complete OAuth through Shellui Identity (see Identity docs: MCP and agents).
2. Call `POST /mcp` on this service with `Authorization: Bearer <agent access token>`.
3. Use JSON-RPC methods `initialize`, `tools/list`, and `tools/call`.

No new required environment variables: use existing `IDENTITY_SERVICE_URL` and `IDENTITY_ISSUER` for OAuth metadata and identity internal APIs (revocation, approvals, call logs).

## Internal assertions to Identity

Revocation polling, approvals and call logs send Identity a short-lived RS256 assertion signed with this service's own key (`STORAGE_SERVICE_SIGNING_KEY`, issuer `STORAGE_SERVICE_ISSUER`, `shellui-django` 0.4.0+). The public key is served at `GET /.well-known/jwks.json`. Identity trusts it only when its own `STORAGE_SERVICE_ISSUER` matches, and reads the key from `STORAGE_SERVICE_JWKS_URL` or a pinned `STORAGE_SERVICE_JWKS`. Without a key, MCP fails closed: agents are refused and call logs are skipped.

Generate a key with `openssl genrsa 3072` and keep it in a secret store or a mounted file (`STORAGE_SERVICE_SIGNING_KEY_FILE`).
