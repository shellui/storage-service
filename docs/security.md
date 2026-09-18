# Production security

Operational controls for deploying `storage-service` alongside [identity-service](https://github.com/shellui/identity-service) **0.5.0+** in a multi-tenant Shellui stack.

## CORS (M-01)

Browser API calls use **Bearer JWT** — not cookies. `CORS_ALLOW_CREDENTIALS` defaults to `false`, so `Access-Control-Allow-Origin: *` is safe for token-based auth.

| Variable | Default | Notes |
|----------|---------|-------|
| `CORS_ALLOW_ALL_ORIGINS` | `true` | Intentional for multi-tenant hosting previews. Set `false` only when you want a first-party-only API. |
| `CORS_ALLOW_CREDENTIALS` | `false` | Must stay `false` when allow-all is enabled. Startup **fails** if both are `true`. |
| `CORS_ALLOWED_ORIGINS` | Shellui dev/admin origins | Used when `CORS_ALLOW_ALL_ORIGINS=false`. |

Token delivery is not governed by storage CORS — identity OAuth redirect allowlists (`CompanyOAuthRedirect`) are the boundary for where login codes/tokens may be sent.

## JWT issuer and audience (M-03)

When `DEBUG=false`, **`IDENTITY_ISSUER` and `IDENTITY_AUDIENCE` are required**. They must match the values identity-service uses to sign tokens:

| storage-service | identity-service (0.5.0+) | Example |
|-----------------|---------------------------|---------|
| `IDENTITY_ISSUER` | `JWT_ISSUER` | `https://id.shellui.com` |
| `IDENTITY_AUDIENCE` | `JWT_AUDIENCE` | `shellui` |

Copy both from the identity deployment env. Mismatched `iss`/`aud` claims produce 401s; check process logs for `iss=` / `aud=` on failed JWT verification.

## Transport and database TLS

When `DEBUG=false`, HTTPS and secure cookies are enabled by default:

| Variable | Production default |
|----------|-------------------|
| `SECURE_SSL_REDIRECT` | `true` |
| `SECURE_HSTS_SECONDS` | `31536000` (1 year) |
| `SESSION_COOKIE_SECURE` | `true` |
| `CSRF_COOKIE_SECURE` | `true` |

Override individual settings for local HTTP testing.

Postgres connections require TLS when `DEBUG=false` (`POSTGRES_SSL_REQUIRE=true` by default). Set `POSTGRES_SSL_REQUIRE=false` only for trusted internal databases (e.g. Coolify Postgres on the same Docker network without TLS).

## Signed URLs and media exposure (M-22)

| Backend | `POST /storage/v1/object/sign/...` behaviour |
|---------|-----------------------------------------------|
| **S3** (`STORAGE_BACKEND=s3`) | Returns a **cryptographically signed** pre-signed URL (query-string auth). Suitable for production when clients fetch directly from object storage. |
| **Filesystem** | Returns a plain `/media/objects/...` path. **Not signed** — anyone who knows or guesses the URL can fetch the object if media is publicly served. |

**Production guidance:**

- Use `STORAGE_BACKEND=s3` for signed URL flows.
- Do **not** expose `/media/` on the public internet when using the filesystem backend.
- Authenticated downloads (`GET /storage/v1/object/...`) always stream through Django regardless of backend — that path does not rely on signed URLs.

## Django admin isolation (M-23)

The admin at `/admin/` shows **cross-tenant** data (all companies' buckets, objects, quotas). Treat it as a privileged operator surface, not an end-user UI.

| Control | Recommendation |
|---------|----------------|
| **Disable on API pods** | `DJANGO_ADMIN_ENABLED=false` on internet-facing replicas; run admin on a separate internal deployment or ingress. |
| **Network restriction** | Bind admin to a private ingress, VPN, or IP allowlist — do not publish `/admin/` on the same public hostname as the storage API without additional controls. |
| **MFA** | Enforce MFA on operator accounts (identity / SSO provider). Django admin uses local superuser credentials — prefer `manage.py createsuperuser` in production over the one-time home-page bootstrap when `DEBUG=false`. |
| **Audit** | Monitor admin login and model changes via your platform logs / SIEM. |

See [Admin panel](admin.md) for dashboard features.

## Environment file hygiene (M-12)

`.env.example` contains **placeholders only**. Generate `SECRET_KEY` locally; never commit real JWKS private keys, AWS credentials, or production DSNs.
