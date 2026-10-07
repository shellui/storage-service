---
description: Production controls for CORS, JWT checks, HTTPS, Postgres, signed URLs, and Django admin.
---

# Security hardening

Set the controls on this page before you expose storage-service beyond a local machine. Defaults below follow `DEBUG=false` unless a row says otherwise. Variable names and defaults are also in [Configuration](configuration.md).

## CORS for browser API calls

Customer shells run on hostnames you do not list in advance, and they call `/storage/v1/*` with a Bearer JWT. A fixed `CORS_ALLOWED_ORIGINS` list does not cover those shells.

Leave `CORS_ALLOW_ALL_ORIGINS=true` and `CORS_ALLOW_CREDENTIALS=false`. Auth is the Bearer JWT, not a cookie, so the API allows every origin and refuses credentials.

Where the browser may return after login is the identity-service redirect allowlist, not storage CORS.

To lock the API to known origins, set `CORS_ALLOW_ALL_ORIGINS=false` and list them in `CORS_ALLOWED_ORIGINS`.

Startup fails when `CORS_ALLOW_ALL_ORIGINS=true` and `CORS_ALLOW_CREDENTIALS=true`. Wildcard origins cannot carry credentials safely.

## JWT verification in production

When `DEBUG=false`:

- `IDENTITY_ISSUER` and `IDENTITY_AUDIENCE` are required, and `iss` / `aud` are checked
- Pin the JWKS document with `IDENTITY_JWKS_FILE` or `IDENTITY_JWKS`. Fetching `IDENTITY_JWKS_URL` still starts, and it will time out if the container cannot reach identity-service

Copy both issuer and audience from the identity-service deployment (`JWT_ISSUER` and `JWT_AUDIENCE`). A mismatch is a 401. The log line includes `iss` and `aud`.

Privileged claims are listed in [JWT and claim trust](authentication.md). Leave `JWT_HS256_FALLBACK_SECRET` unset in production.

## HTTPS, HSTS, and cookies

When `DEBUG=false`:

- `SECURE_SSL_REDIRECT=true` redirects HTTP to HTTPS. Turn it off only behind a TLS terminator that already redirects
- `SECURE_HSTS_SECONDS=31536000` (1 year), including subdomains
- `SESSION_COOKIE_SECURE=true` and `CSRF_COOKIE_SECURE=true`

Override any of these in the environment. See [`.env.example`](../.env.example). Django admin uses these cookies. The storage API does not.

## Postgres SSL

When `POSTGRES_DATABASE_URL` is set and `DEBUG=false`, connections use TLS (`ssl_require=true`). Set `POSTGRES_SSL_REQUIRE=false` only for a database without TLS on a private network, such as a Coolify internal database.

## Signed URLs and media files

| Backend | `POST /storage/v1/object/sign/…` |
| --- | --- |
| S3 | Cryptographic pre-signed URL. Suitable when a client fetches from object storage |
| Filesystem | Plain `/media/objects/…` path. Not signed. Anyone who can request that path can read the object |

Use `STORAGE_BACKEND=s3` when you sign URLs. Do not publish `/media/` on the public internet for the filesystem backend. Authenticated `GET /storage/v1/object/…` still streams through Django and does not depend on the signed URL. Anonymous download is a [share link](sharing.md). The public object route returns 403.

## Django admin

Django admin is cross-tenant. It uses local Django users, not the JWT company scope. The statistics page lists every company's objects, quotas, and recent uploads.

- Expose `/admin/` on an internal hostname or a VPN, not on the public storage host
- Require MFA for staff at the identity provider that signs them into admin
- Set `DJANGO_ADMIN_ENABLED=false` to remove the admin routes when this pod should not serve them
- Create the first superuser with `manage.py createsuperuser`. The home-page form in production needs `SETUP_TOKEN`

What the statistics page shows is in [Run storage-service](getting-started.md).

## Shared cache

Redis is required when `DEBUG=false` (`REDIS_URL`, for example `redis://redis:6379/0`). It is the shared cache and the broker for the scheduled jobs. Without it the container exits 1, and `manage.py check --deploy` reports `authapi.E004`. `authapi.W001` is still a warning when production uses the in-process cache with more than one Gunicorn worker.

storage-service does not enforce request rate limits. The first webhook POST does not use Redis. Retries do, because they run on the scheduled job.

## Access logs and error reports

Gunicorn writes an access line with the method and the path. The line omits the query string and the Referer header, so `/?setup_token=…` is not copied to stdout. A share-link token in the path is replaced with `[filtered]` before the line is written.

When `SENTRY_DSN` is set, events omit stack locals, request bodies, and cookies. Authorization, Cookie, and Referer headers are removed. Query strings are removed from the request URL before the event is sent. Share-link tokens in that URL are replaced with `[filtered]`.

## Email-service URLs

`EMAIL_SERVICE_URL` is checked the same way as a Shellui Actions webhook URL. A private, loopback, or link-local address is refused unless `EMAIL_SERVICE_ALLOW_PRIVATE=true`. Set that when the email-service URL is internal (for example `http://localhost:8003` or `http://host.docker.internal:8003`). The POST does not follow redirects. The service key is not written to the outbox or to logs.

Webhook envelopes, the event log, and the email body omit tokens, sign-in links, signed URLs, and secret-shaped fields.

## Webhook targets

Outbound webhook URLs are checked for private, loopback, and non-global addresses. `ACTIONS_WEBHOOK_ALLOW_PRIVATE` defaults to false in every mode. Staff can allow one rule to call a private URL. See [Webhooks](actions.md).
