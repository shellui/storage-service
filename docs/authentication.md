# Authentication (JWKS)

`storage-service` does **not** issue tokens. It verifies Bearer JWTs created by identity-service using the identity **public** JWKS document (RSA keys). That document is not a private certificate; it is safe to copy into Coolify or a local file.

## Production: store the keys locally

Do **not** fetch `https://id.shellui.com/.well-known/jwks.json` from a container on the same host. That public URL hairpins and times out.

From a laptop (outside the server):

```bash
curl -sS https://id.shellui.com/.well-known/jwks.json
```

Then set **one** of these on storage-service and restart:

```bash
# Coolify env (easiest)
IDENTITY_JWKS={"keys":[...paste the JSON...]}

# Or a file on the data volume
IDENTITY_JWKS_FILE=/app/data/jwks.json
```

When either is set, storage never calls identity at runtime. After identity rotates signing keys, update the JSON and restart storage.

`GET /storage/v1/health` reports `identity_jwks_source` as `env`, `file`, or `url`.

## Local/dev: fetch from identity

```bash
IDENTITY_JWKS_URL=http://localhost:8000/.well-known/jwks.json
```

From Docker on the host, use `http://host.docker.internal:8000/.well-known/jwks.json`.

If `IDENTITY_JWKS_FILE` or `IDENTITY_JWKS` is set, it wins and the URL is ignored.

## Configuration reference

| Variable | Purpose |
|----------|---------|
| `IDENTITY_JWKS_FILE` | Path to a JWKS JSON file (production, preferred with a volume) |
| `IDENTITY_JWKS` | JWKS JSON inline (production, easy in Coolify) |
| `IDENTITY_JWKS_URL` | Fetch URL for local/dev only |
| `IDENTITY_SERVICE_URL` | Identity base URL; JWKS path is derived if `IDENTITY_JWKS_URL` is empty and no local document is set |
| `IDENTITY_ISSUER` | Optional `iss` claim check |
| `IDENTITY_AUDIENCE` | Optional `aud` claim check |
| `JWKS_CACHE_TTL` | Seconds to cache a **fetched** JWKS (default `900`; unused for local documents) |
| `JWKS_TIMEOUT` | Seconds to wait for a JWKS HTTP response (default `15`; connect cap `5`) |
| `JWKS_RETRIES` | Extra JWKS fetch attempts after timeout / 5xx (default `2`; 4xx is not retried) |
| `JWT_HS256_FALLBACK_SECRET` | Dev-only: verify HS256 when JWKS has no keys (identity `DEBUG=true`). **Rejected at startup if `DEBUG=false`** unless `ALLOW_JWT_HS256_FALLBACK=true` |
| `ALLOW_JWT_HS256_FALLBACK` | Explicit escape hatch to allow HS256 fallback when `DEBUG=false` (not recommended in production) |
| `JWT_ALGORITHMS` | Default `RS256` |

## Expected claims

| Claim | Use |
|-------|------|
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
