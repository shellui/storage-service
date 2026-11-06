---
title: Shellui MCP
sidebar_label: Shellui MCP
description: Company-owner storage APIs that Shellui MCP agents may call, and how they are marked in OpenAPI.
---

# Shellui MCP

Shellui MCP connects AI agents to company-scoped storage APIs. storage-service runs `POST /mcp` (Streamable HTTP JSON-RPC). Identity remains the OAuth authorization server; this service publishes OpenAPI with `x-mcp` extensions and exposes OAuth protected-resource metadata at `/.well-known/oauth-protected-resource`.

Agents authenticate with a JWT whose `aud` is this service's MCP resource URL (`…/mcp`, RFC 8707) only. The token `scope` claim must include `storage`. Agents act as the company owner for the JWT `company_id`. Identity issues binding metadata on that token; storage does not trust tool request bodies for authority. Agent tokens cannot approve their own pending requests; only a company owner user JWT can approve in Identity. Staff-only routes, anonymous share redeem URLs, and internal service callbacks are never MCP tools.

### Identity claims on the agent access token

storage-service reads only verified JWT claims (not MCP JSON-RPC parameters) for security decisions:

| Claim | Role |
| --- | --- |
| `grant_version` | Integer grant generation for the agent. When absent it is treated as `0` for revocation cache and staleness only. Non-read-only agents must send an explicit value for approval assertions. |
| `global_company_id` | Global company id when the token binds a regional `company_id` to a global org. Optional for personal or single-region tokens. |
| `company_binding_version` | Integer version of that binding. Required when `global_company_id` is present and the agent is not read-only. |

`company_id` in the token must match `global_company_id` when both are integers. Mismatch returns `401` with `identity_invalid`.

The signed Identity revocation list JWT may include `max_active_grant_version`. If the token's effective grant version (missing means `0`) is lower, `POST /mcp` returns `409` with `out_of_sync` so clients refresh before writes.

When Identity cannot return a verified revocation list, `POST /mcp` returns `503` with `identity_unavailable`. Revocation checks fail closed: a listed revoked agent is refused even when the unsigned HTTP body disagrees with the signed `revocation_assertion`.

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
| Connectors | List, read, create, update, delete connector mounts; re-run local configuration checks (`configuration/check`, `configuration/validate`, `configuration/retry`; company owner; `credential` is `x-mcp-secret`). |
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

Approval assertions to Identity include the same binding fields as the access token: `grant_version`, and when applicable `global_company_id` and `company_binding_version` (embedded in the signed JWT body). This extends the stock `build_mcp_approval_assertion` helper from `shellui-django`, which does not yet carry those claims.

Generate a key with `openssl genrsa 3072` and keep it in a secret store or a mounted file (`STORAGE_SERVICE_SIGNING_KEY_FILE`).

### Call log payload to Identity

Each successful or blocked tool attempt sends a JSON object to `mcp-call-logs` with:

- `tool`: registered tool name (operation id slug).
- `operation_title`: OpenAPI `summary` for that operation, or `Operation {tool}` when missing.
- `path`: resolved API path only (no query string).
- `method`: HTTP method.
- `access_kind`: `read` when the tool is tagged read-only, otherwise `write`.
- `destructive`: boolean from tool metadata.
- `read_level`: `safe` or `sensitive` from the token.
- `outcome`: one of `allowed`, `failed`, `pending_approval`, `session_used`, `denied`, `unknown`, `not_found`, `conflict`, `rate_limited`, `timeout`, `upstream_error`, `internal_error`.
- `status`: HTTP status or synthetic code for gate results (for example `202` for pending approval, `503` when Identity approval RPCs fail).
- `duration_ms`: wall time for the handler.
- `arguments`: request arguments after `x-mcp` redaction (no raw secrets).
- `result`: redacted response body for successful HTTP calls only.
- `approval_request_id`: Identity pending row id when a new approval was created.
- `approval_id`: consumed approval UUID after approval.
- `error`: when present, `{ "code": "<allowlisted>" }` using AI gateway codes such as `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `rate_limited`, `timeout`, `upstream_error`, `internal_error`, `denied`, `expired`, `out_of_sync`, `unknown`, `identity_unavailable`, `identity_invalid`, `agent_revoked`.
- `grant_version`, `global_company_id`, `company_binding_version`: integers from the verified token (normalized), not from clients.
