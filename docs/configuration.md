---
description: Environment variables for storage-service, grouped by topic, with the defaults from settings and .env.example.
---

# Configuration

storage-service reads configuration from environment variables. Copy [`.env.example`](../.env.example) to `.env` for local runs. Pass the same keys to Docker, Coolify, or your orchestrator in production.

An empty boolean uses the default. `1`, `true`, `yes`, and `on` are true. Any other value, including `false`, is false. Byte sizes accept a bare integer or a `K`, `M`, `G`, or `T` suffix. Each suffix is a multiple of 1024, so `10G` is 10737418240 bytes.

## Required to start

`SECRET_KEY` is required in every mode. Django uses it to sign sessions and CSRF tokens. Generate one with:

```bash
python - <<'PY'
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())
PY
```

## Required when DEBUG is false

The Docker image sets `DEBUG=false`. Startup fails until these are set:

| Variable | Purpose |
| --- | --- |
| `IDENTITY_ISSUER` | JWT `iss` must match this value |
| `IDENTITY_AUDIENCE` | JWT `aud` must match this value |

`JWT_HS256_FALLBACK_SECRET` is refused unless you also set `ALLOW_JWT_HS256_FALLBACK=true`. `CORS_ALLOW_ALL_ORIGINS=true` together with `CORS_ALLOW_CREDENTIALS=true` is also refused.

Pin a JSON Web Key Set (JWKS) with `IDENTITY_JWKS_FILE` or `IDENTITY_JWKS` in production. A URL fetch is allowed at startup, and it is the wrong choice on a host that cannot reach `https://id.shellui.com` from the container. Copy the document from outside the server and restart after identity-service rotates keys. See [JWT and claim trust](authentication.md).

## Runtime

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEBUG` | `false` | Local mode. The image sets `false`. Compose passes the value from `.env`, where the example file sets `true` |
| `LOG_LEVEL` | `INFO`, or `DEBUG` when `DEBUG=true` | Python log level |
| `SETUP_TOKEN` | empty | One-time token for the web form that creates the first superuser when `DEBUG=false` |
| `STORAGE_SERVICE_PORT` | `8001` | Host port published by Docker Compose. Gunicorn inside the image listens on 8000 |
| `ALLOWED_HOSTS` | `localhost`, `127.0.0.1` | Comma-separated hostnames, no scheme |
| `CSRF_TRUSTED_ORIGINS` | local dev origins and `https://admin.shellui.com` | Full origins for Django admin form posts |
| `DJANGO_ADMIN_ENABLED` | `true` | `false` removes `/admin/` routes |

## Identity and JWT

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDENTITY_SERVICE_URL` | empty | identity-service base URL. JWKS is `{url}/.well-known/jwks.json` when no document is pinned |
| `IDENTITY_JWKS_URL` | derived, or `http://localhost:8000/.well-known/jwks.json` | Fetch URL when no document is pinned. Ignored for verification when a document is set |
| `IDENTITY_JWKS_FILE` | empty | Path to a JWKS file. Relative paths are from the repository root. Wins over `IDENTITY_JWKS` |
| `IDENTITY_JWKS` | empty | JWKS JSON in the environment, used when no file is set |
| `IDENTITY_ISSUER` | empty | Expected `iss`. Required when `DEBUG=false` |
| `IDENTITY_AUDIENCE` | empty | Expected `aud`. Required when `DEBUG=false` |
| `JWKS_CACHE_TTL` | `900` | Seconds to cache a fetched JWKS document. Unused for a pinned document |
| `JWKS_TIMEOUT` | `15` | Seconds for one JWKS HTTP call |
| `JWKS_RETRIES` | `2` | Extra attempts after a timeout or HTTP 5xx. HTTP 4xx is not retried |
| `JWT_ALGORITHMS` | `RS256` | Comma-separated algorithms accepted for RS256 verification |
| `JWT_HS256_FALLBACK_SECRET` | empty | HS256 secret for local identity debug tokens. Set it to the identity `SECRET_KEY` |
| `ALLOW_JWT_HS256_FALLBACK` | `false` | Allow the HS256 secret when `DEBUG=false` |

Issuer and audience checks run only when the matching variable is set. Production always sets both.

## Object storage

| Variable | Default | Purpose |
| --- | --- | --- |
| `STORAGE_BACKEND` | `filesystem` | `filesystem` or `s3` |
| `MEDIA_ROOT` | `data/media`, `/app/data/media` in Docker | Filesystem root. Blobs live under `objects/` |
| `STORAGE_KEY_PREFIX` | `shellui` | Key prefix in front of every blob path |
| `SIGNED_URL_EXPIRES` | `3600` | Maximum signed-URL lifetime in seconds. Client values above this are reduced |

S3 settings apply when `STORAGE_BACKEND=s3`. `AWS_STORAGE_BUCKET_NAME` is required in that mode.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | empty | S3 credentials |
| `AWS_STORAGE_BUCKET_NAME` | empty | Bucket name |
| `AWS_S3_REGION_NAME` | `us-east-1` | Region |
| `AWS_S3_ENDPOINT_URL` | empty | Custom S3 endpoint, scheme and host only. Leave empty for AWS. MinIO in Compose is `http://minio:9000` |
| `AWS_S3_CUSTOM_DOMAIN` | empty | Public host for the bucket, if it differs from the API endpoint. Leave empty unless you have a CDN |
| `AWS_S3_SIGNATURE_VERSION` | `s3v4` | Signature version |
| `AWS_S3_ADDRESSING_STYLE` | inferred | `path` for MinIO, `virtual` for AWS and OVH, or `auto` |

`POST /storage/v1/object/sign/…` returns a cryptographic pre-signed URL on S3. On the filesystem backend it returns a plain `/media/objects/…` path. See [Downloads and signed URLs](downloads.md).

## Quotas and uploads

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEFAULT_COMPANY_QUOTA_BYTES` | `10G` | Company cap applied when the quota row is created |
| `DEFAULT_USER_QUOTA_BYTES` | `0` | Default per-user cap. `0` leaves the per-user cap off |
| `MAX_UPLOAD_BYTES` | `5G` | Hard cap for one upload. A bucket `file_size_limit` cannot raise it |
| `DATA_UPLOAD_MAX_MEMORY_SIZE` | `12M` | Django in-memory request limit. The object is still capped by `MAX_UPLOAD_BYTES` |

Staff and company owners can replace the company and per-user caps over the API. See [Quotas](quotas.md).

## WebDAV

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEBDAV_ENABLED` | `true` | `false` removes the WebDAV routes |
| `WEBDAV_PATH_PREFIX` | `/dav` | URL prefix. Clients use `/dav/{bucket}/…` |

WebDAV uses the same grants, quotas, and upload signals as the REST API. See [WebDAV](clients.md).

## Database

| Variable | Default | Purpose |
| --- | --- | --- |
| `POSTGRES_DATABASE_URL` | empty | PostgreSQL DSN. Unset uses SQLite |
| `SQLITE_PATH` | `db.sqlite3`, `/app/data/db.sqlite3` in Docker | SQLite file |
| `POSTGRES_SSL_REQUIRE` | `true` when `DEBUG=false` | Require TLS to PostgreSQL. Set `false` for a private database without TLS |

## Cache and scheduled jobs

`REDIS_URL` is required when `DEBUG=false`. Redis is the shared cache and the broker for the scheduled jobs. Without it, the container logs `REDIS_URL is required when DEBUG is false` and exits with status 1, and `manage.py check --deploy` reports `authapi.E004`. That check still fails when `SCHEDULER_ENABLED=false` or when only `CELERY_BROKER_URL` is set.

With `DEBUG=true` and `REDIS_URL` unset, each process uses an in-memory cache and the scheduled jobs do not start. `authapi.W001` remains a warning when production still uses that in-memory cache with more than one Gunicorn worker.

```bash
REDIS_URL=redis://redis:6379/0
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCHEDULER_ENABLED` | `true` | `false` keeps the Celery worker out of this container |
| `CELERY_BROKER_URL` | `REDIS_URL` | A different Redis for the jobs. Does not replace `REDIS_URL` |
| `CELERY_WORKER_CONCURRENCY` | `2` | Threads in the worker |

Schedules, locks, the staff API and metrics are in [Scheduled jobs](maintenance-jobs.md).

## CORS and HTTPS

| Variable | Default | Purpose |
| --- | --- | --- |
| `CORS_ALLOW_ALL_ORIGINS` | `true` | Allow browser calls from any origin |
| `CORS_ALLOW_CREDENTIALS` | `false` | Must stay `false` while all origins are allowed. That combination refuses to start |
| `CORS_ALLOWED_ORIGINS` | local dev origins, plus extras you append | Used when `CORS_ALLOW_ALL_ORIGINS=false` |
| `CORS_ALLOW_PRIVATE_NETWORK` | `true` | Private Network Access preflight header |
| `SECURE_SSL_REDIRECT` | on when `DEBUG=false` | Redirect HTTP to HTTPS |
| `SECURE_HSTS_SECONDS` | `31536000` when `DEBUG=false`, else `0` | HSTS max-age |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | on when `DEBUG=false` | Include subdomains in HSTS |
| `SECURE_HSTS_PRELOAD` | `false` | HSTS preload flag |
| `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` | on when `DEBUG=false` | Secure attribute on Django cookies |

API auth is the Bearer JWT, not a cookie. Permissive CORS is the default for that reason. Where the browser may return after login is the identity-service redirect allowlist, not this CORS list.

## Gunicorn

The image entrypoint runs migrations, `check --deploy`, then Gunicorn. In `web` mode it also starts the Celery worker and beat unless `SCHEDULER_ENABLED=false` or, with `DEBUG=true`, Redis is unset. `worker` mode starts only the scheduler. See [Scheduled jobs](maintenance-jobs.md).

| Variable | Default | Purpose |
| --- | --- | --- |
| `GUNICORN_WORKERS` | `2` | Worker processes |
| `GUNICORN_THREADS` | `2` | Threads per worker |
| `GUNICORN_TIMEOUT` | `120` | Seconds before Gunicorn kills a silent worker. Sized for large uploads |

## Shellui Actions

Webhooks do not need Redis. These variables tune delivery. The catalog and the admin API are in [Webhooks](actions.md).

| Variable | Default | Purpose |
| --- | --- | --- |
| `ACTIONS_OUTBOX_MAX_ATTEMPTS` | `8` | Attempts before a delivery is dead |
| `ACTIONS_WEBHOOK_TIMEOUT_SECONDS` | `5` | Timeout of one webhook POST |
| `ACTIONS_WEBHOOK_RETRY_LEASE_SECONDS` | `120` | How long one retry run holds a row |
| `ACTIONS_WEBHOOK_DISPATCH_WORKERS` | `4` | Threads used for post-commit delivery |
| `ACTIONS_WEBHOOK_SYNC_DELIVERY` | `false` | Deliver inside the request. Leave `false` outside tests |
| `ACTIONS_WEBHOOK_ALLOW_PRIVATE` | `false` | Allow webhook URLs that resolve to private or loopback addresses. Unset stays off, including when `DEBUG=true` |

Staff can also set **allow private URLs** on one rule. Changing the URL clears that flag unless a superuser sets it again.

## Email notifications

Set `EMAIL_SERVICE_API_KEY` to forward storage events to email-service. An empty key sends nothing. Webhook and email bodies omit sign-in links, tokens, signed URLs, and secret-shaped fields. See [Email notifications](email.md).

| Variable | Default | Purpose |
| --- | --- | --- |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` | Origin only. storage-service appends `/api/v1/events` |
| `EMAIL_SERVICE_API_KEY` | empty | Service key (`esk_`). Empty disables forwarding |
| `EMAIL_SERVICE_ALLOW_PRIVATE` | `false` | Allow a URL that resolves to a private or loopback address. Set this for an internal email-service URL |

## Event log

| Variable | Default | Purpose |
| --- | --- | --- |
| `EVENT_LOG_RETENTION_DAYS` | `7` | Days to keep event-log rows and finished webhook and email deliveries. Values below 1 are treated as 1 |

`purge_expired_data` deletes older rows every hour inside the container. See [Event log](event-log.md) and [Scheduled jobs](maintenance-jobs.md).

## Error reporting

| Variable | Default | Purpose |
| --- | --- | --- |
| `SENTRY_DSN` | empty | Turns on Sentry. No personal data is attached |
| `SENTRY_ENVIRONMENT` | `development` or `production` from `DEBUG` | Sentry environment tag |
| `SENTRY_RELEASE` | the package version | Sentry release tag |
| `SENTRY_TRACES_SAMPLE_RATE` | `0` | Share of requests traced. `0` reports errors only |

## Related

- [Run storage-service](getting-started.md)
- [Security hardening](security.md)
- [PUBLISH.md](../PUBLISH.md)
