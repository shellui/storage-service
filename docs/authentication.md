# Authentication (JWKS)

`storage-service` does **not** issue tokens. It verifies Bearer JWTs created by identity-service.

## Configure the identity URL

Set this in `.env` (or your orchestrator / Coolify / Compose env). **`IDENTITY_JWKS_URL` is the main knob** — switch between local and production without code changes.

```bash
# Local identity-service
IDENTITY_JWKS_URL=http://localhost:8000/.well-known/jwks.json

# Hosted identity
IDENTITY_JWKS_URL=https://id.shellui.com/.well-known/jwks.json
```

Shorthand (JWKS path appended automatically):

```bash
IDENTITY_SERVICE_URL=https://id.shellui.com
# → https://id.shellui.com/.well-known/jwks.json
```

If both are set, `IDENTITY_JWKS_URL` wins. If neither is set, the default is `http://localhost:8000/.well-known/jwks.json`.

Docker Compose passes `IDENTITY_JWKS_URL` from `.env` (default inside Compose: `http://host.docker.internal:8000/.well-known/jwks.json` so the container can reach identity on the host).

`GET /storage/v1/health` shows the resolved JWKS URL so you can confirm what the process is using.

## Configuration reference

| Variable | Purpose |
|----------|---------|
| `IDENTITY_JWKS_URL` | Full JWKS document URL (preferred) |
| `IDENTITY_SERVICE_URL` | Identity base URL; JWKS path is derived if `IDENTITY_JWKS_URL` is empty |
| `IDENTITY_ISSUER` | Optional `iss` claim check |
| `IDENTITY_AUDIENCE` | Optional `aud` claim check |
| `JWKS_CACHE_TTL` | Seconds to cache JWKS (default `900`) |
| `JWKS_TIMEOUT` | Seconds to wait for a JWKS HTTP response (default `15`; connect cap `5`) |
| `JWKS_RETRIES` | Extra JWKS fetch attempts after timeout / 5xx (default `2`) |
| `JWT_HS256_FALLBACK_SECRET` | Dev-only: verify HS256 when JWKS has no keys (identity `DEBUG=true`). **Rejected at startup if `DEBUG=false`** unless `ALLOW_JWT_HS256_FALLBACK=true` |
| `ALLOW_JWT_HS256_FALLBACK` | Explicit escape hatch to allow HS256 fallback when `DEBUG=false` (not recommended in production) |
| `JWT_ALGORITHMS` | Default `RS256` |

## Expected claims

| Claim | Use |
|-------|-----|
| `sub` / `user_id` | Owner id for uploads and per-user quotas |
| `company_id` | Tenancy — buckets and objects are scoped to this company |
| `email` | Informational |
| `user_metadata.is_staff` | Quota admin APIs |
| `user_metadata.is_company_owner` | Quota admin for own company |

## Client headers

```http
Authorization: Bearer <access_token>
```

Optional Supabase-style `apikey` header is accepted by CORS but ignored for authorization.

## WebDAV

Third-party WebDAV clients may send:

- `Authorization: Bearer <jwt>`, or
- HTTP Basic where the **password** is the JWT (username can be the user email).
