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

## Debugging failed tokens

API clients still get a generic 401 (`Token is invalid or could not be verified against identity JWKS.`) so the token is not leaked. The **process logs** have the details.

Look for `JWT` on the `apps.authapi.authentication` / `apps.authapi.jwks_client` loggers. Useful fields:

| Log field | What it tells you |
|-----------|-------------------|
| `alg` / `kid` | Token header. `HS256` with no fallback means identity is in DEBUG mode — set `JWT_HS256_FALLBACK_SECRET`. `kid` missing from `jwks_kids` means storage's JWKS is stale; recopy `IDENTITY_JWKS`. |
| `iss` / `aud` / `exp` | Unverified claims (signature not trusted). Mismatch against `IDENTITY_ISSUER` / `IDENTITY_AUDIENCE` if those are set. |
| `jwks_source` / `jwks_kids` | Where keys were loaded (`env`, `file`, or `url`) and which `kid`s storage currently has. |
| `request_id` / `[req=…]` | Correlate one HTTP call. The 401 JSON includes `request_id`; the same value is in `X-Request-ID`. |

How to read logs:

```bash
# Local runserver — logs print in that terminal
uv run python manage.py runserver 8001

# Docker
docker logs -f <container> 2>&1 | grep JWT

# Coolify / systemd — open the service logs and search for "JWT authentication failed"
```

On startup, storage logs `Identity JWKS auth ready: source=… key_count=… kids=…`. If `key_count=0` and you are not using HS256 fallback, every request will 401.

When `DEBUG=true`, the 401 `detail` string also appends the PyJWT exception (`InvalidSignatureError`, `DecodeError`, missing `kid`, …).

## WebDAV

Third-party WebDAV clients may send:

- `Authorization: Bearer <jwt>`, or
- HTTP Basic where the **password** is the JWT (username can be the user email).
