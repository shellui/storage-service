# shellui_mcp

Copy this directory into storage-service, hosting-service, email-service, and saas-service unchanged.

## Service wiring

1. Mount `POST /mcp` with `shellui_mcp.server.McpServer`.
2. Tag OpenAPI operations with `mcp-tools` using `@mcp_expose_tool` (never tag staff-only routes).
3. Publish `/.well-known/oauth-protected-resource` pointing at Identity.
4. Poll Identity `GET /api/v1/mcp/internal/mcp-revocations` every 30 seconds with a signed service assertion.
5. Forward call logs with `POST /api/v1/mcp/internal/mcp-call-logs` and signed assertions (`shellui_mcp.internal`).
6. Create approval requests with `POST /api/v1/mcp/internal/mcp-approval-requests` when writes need confirmation.

See [MCP and agents](../docs/mcp-and-agents.md) in identity-service docs.

## RFC 8707 resource indicators (required)

Each Shellui MCP server is a separate OAuth protected resource. The canonical resource identifier is the service origin plus `/mcp` (no trailing slash on the origin, path exactly `/mcp`).

| Setting (identity example) | Resource URL |
| --- | --- |
| `JWT_ISSUER=https://auth.example.com` | `https://auth.example.com/mcp` |
| `STORAGE_SERVICE_URL=https://storage.example.com` | `https://storage.example.com/mcp` |
| `HOSTING_SERVICE_URL=…` | `{origin}/mcp` |
| `EMAIL_SERVICE_URL=…` (when configured) | `{origin}/mcp` |

Use `shellui_mcp.resources.mcp_resource_from_origin(origin)` in each service. Derive `origin` from the same URL setting you already use for that service.

### Client OAuth flow

1. Load protected resource metadata (`/.well-known/oauth-protected-resource`) for the MCP URL the client will call. The `resource` field is the indicator value.
2. Send `resource=<that URL>` on authorize (`GET /oauth/mcp/authorize`), token exchange (`POST /oauth/mcp/token`, `grant_type=authorization_code`), and refresh (`grant_type=refresh_token`).
3. Receive an access token whose JWT `aud` claim equals that resource URL exactly (not a shared product audience).
4. Call `POST /mcp` on that same origin with `Authorization: Bearer <access_token>`.

One agent may hold several refresh tokens (one per resource). Each access token is valid only on the matching service.

### Service-side validation

On every `POST /mcp` request:

```python
from django.conf import settings
from shellui_mcp.resources import access_token_audience_matches, mcp_resource_from_origin

expected = mcp_resource_from_origin(settings.YOUR_SERVICE_ORIGIN_SETTING)
# Identity: JWT_ISSUER. Storage: STORAGE_SERVICE_URL. Same pattern elsewhere.

if not access_token_audience_matches(agent_claims, expected):
    return 401
```

Decode agent JWTs with issuer and signature checks; do not accept a global `JWT_AUDIENCE` for MCP agent tokens. The `aud` must match this service's `/mcp` resource only.

Agent tokens still carry `scope` as a space-separated list of allowed service ids (`identity`, `storage`, …). `McpServer` rejects tools when the server `service_name` is not in `scope`.

## Internal Identity calls (signed assertions)

All use Identity as issuer, short TTL (~60s), and `target` set to the Identity origin (`JWT_ISSUER` without path).

| Purpose | HTTP | Assertion audience (`aud`) | Scope |
| --- | --- | --- | --- |
| Revocation poll | `GET /api/v1/mcp/internal/mcp-revocations` | `shellui-mcp-revocation` | `mcp.revocation.read` |
| Call log ingest | `POST /api/v1/mcp/internal/mcp-call-logs` | `shellui-mcp-call-log` | `mcp.call_log.create` |
| Approval create | `POST /api/v1/mcp/internal/mcp-approval-requests` | `shellui-mcp-approval` | `mcp.approval.create` |

Builders in `shellui_mcp.internal`:

- `build_mcp_revocation_assertion(audience_url=identity_origin)`
- `build_mcp_call_log_assertion(audience_url=identity_origin)`
- `build_mcp_approval_assertion(..., audience_url=identity_origin)`

Send `Authorization: Bearer <assertion>` (or JSON `assertion` on POST bodies). Revocation responses use `Cache-Control: private, max-age=30`.

## Staff and operators

Staff accounts (`is_staff`, `is_superuser`, global staff) cannot authorize MCP agents or call `/api/v1/mcp/*` company admin APIs. Company owners (non-staff) and human user JWTs approve pending writes; agent bearer tokens cannot approve.
