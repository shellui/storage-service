# Change Log

Notable changes to this project. Format: [Keep a Changelog](http://keepachangelog.com/). Versioning: [Semantic Versioning](http://semver.org/).

<!---
## [Unreleased] - yyyy-mm-dd

### ✨ Feature - for new features
### 🛠 Improvements - for general improvements
### 🚨 Changed - for changes in existing functionality
### ⚠️ Deprecated - for soon-to-be removed features
### 📚 Documentation - for documentation update
### 🗑 Removed - for removed features
### 🐛 Bug Fixes - for any bug fixes
### 🔒 Security - in case of vulnerabilities
### 🏗 Chore - for tidying code

See for sample https://raw.githubusercontent.com/favoloso/conventional-changelog-emoji/master/CHANGELOG.md
-->

## [Unreleased] - 2026-10-07

### ✨ Feature

- **In-container scheduler:** the Docker image runs a Celery worker and beat next to Gunicorn. `retry_webhooks` runs every minute and `purge_expired_data` runs hourly at minute 17. Redis `SET NX` locks stop the same job from overlapping across replicas. `SCHEDULER_ENABLED` defaults to true. The entrypoint accepts `web` (default) and `worker`. See [docs/maintenance-jobs.md](docs/maintenance-jobs.md).
- **Scheduled job monitoring:** staff-only `GET /api/v1/scheduled-jobs` (same shape as identity-service), Prometheus metrics `shellui_storage_scheduled_job_*` and `shellui_storage_scheduler_*` on `GET /storage/v1/metrics/all` only, and staff-only events `storage.scheduled_job.succeeded` and `storage.scheduled_job.failed`. Webhook retries from a job send `X-Request-ID: sjr-<id>`.

### 🚨 Changed

- **Redis is required in production.** When `DEBUG=false` and `REDIS_URL` is unset, the container exits 1 and `manage.py check --deploy` reports `authapi.E004`, including when `SCHEDULER_ENABLED=false`. With `DEBUG=true`, Redis stays optional and the jobs do not start.
- Run the `apps.actions` migration `0003_scheduled_job_runs` after upgrade. `EventLog.company_id` may be null for platform events. List them with `GET /api/v1/actions/event-log?scope=platform` (staff only).

### 📚 Documentation

- **Handbook:** [`docs/index.md`](docs/index.md) is the storage homepage, with [`docs/sidebars.js`](docs/sidebars.js) for the sidebar on `docs.shellui.com/storage`. New pages cover running the service, configuration, buckets and files, maintenance jobs, and the API. Access grants, share links, quotas, downloads, WebDAV, JWT claim trust, Shellui Actions webhooks, the event log, and security hardening are refreshed against `develop`. CI builds the storage docs with shellui/shellui.
- **Publish note:** [PUBLISH.md](PUBLISH.md) points readers at `docs.shellui.com/storage`. The old `storage.docs.shellui.com` hostname no longer resolves.
- **In-repo docs site removed:** `deploy-docs.yml`, `tools/docusaurus/`, `tools/generate-docs.sh`, and the root `CNAME` are gone. Docs are published only by [shellui/shellui](https://github.com/shellui/shellui).

### 🏗 Chore

- Allow the handbook placeholder `your_access_token_here` in the gitleaks scan. The upload example passes the token as `$ACCESS_TOKEN`.

### ✨ Feature

- **Event log:** every `storage.*` event is stored, with or without a webhook rule, and listed at `GET /api/v1/actions/event-log` (filters: type, user, date range) for the admin panel **Storage > Log events** page. See [docs/event-log.md](docs/event-log.md).
- **Data retention:** `EVENT_LOG_RETENTION_DAYS` (default 7). `manage.py purge_expired_data` deletes expired events and finished webhook deliveries in short batches. The container runs it every hour. `GET /api/v1/actions/event-log/retention` reports `stale_events` when the job is not running.

### 🐛 Bug Fixes

- **Django admin deletes:** deleting a file or a bucket in Django admin now goes through the same path as the REST API: blobs are removed, quota usage goes down, and `storage.object.deleted` is emitted for each file. It previously left blobs and usage behind and emitted nothing.
- `storage.bucket.created` now includes the user whose first request provisioned the bucket.

## [0.4.0] - 2026-09-29

### ✨ Feature

- Public homepage aligned with identity-service, with a staff-only Django admin link
- **Shellui Actions**: signed outbound webhooks for `storage.*` events at `/api/v1/actions/*`
- n8n-ready delivery: `whsec_` secrets, retry headers, rotate-secret, and an [n8n guide](docs/n8n.md)
- Optional `REDIS_URL` shared cache; LocMem stays the default

### 🛠 Improvements

- Root `AGENTS.md` for Shellui writing and design guidelines
- Docusaurus theme and favicons for docs at `storage.docs.shellui.com`

### 🚨 Changed

- Homepage uses Shellui brand, a **Shellui Storage** title, and Tailwind v4 `static/css/site.css`
- Docs and Compose examples use `REDIS_URL` and `https://storage.shellui.com`
- Run `apps.actions` migrations after upgrade
- Schedule `python manage.py retry_webhooks` every minute
- Set `REDIS_URL` when `GUNICORN_WORKERS` is greater than 1

### 🐛 Bug Fixes

- HTTPS webhooks on Python 3.14 use pinned TLS connect, aligned with identity-service

### 🔒 Security

- Webhook SSRF: reject non-global, CGNAT, NAT64, 6to4, and IPv4-compatible IPv6
- Changing a webhook URL clears `allow_private_urls` unless a superuser re-enables it

## [0.3.0] - 2026-09-18

### 🔒 Security

- CORS: `CORS_ALLOW_ALL_ORIGINS=true` is allowed in production when credentials are off
- Require `IDENTITY_ISSUER` and `IDENTITY_AUDIENCE` when `DEBUG=false`
- `.env.example` uses placeholders only
- Filesystem signed URLs are not cryptographic; use S3 in production
- Optional `DJANGO_ADMIN_ENABLED=false` for API pods
- HSTS and secure cookies when `DEBUG=false`; `POSTGRES_SSL_REQUIRE` defaults to `true`
- Bulk, prefix, and empty delete enforce path-level write ACL
- Prefix stats omit objects you cannot read
- Signed URL TTL is capped to `SIGNED_URL_EXPIRES` (default 3600s)
- Anonymous health returns only `status` and `version`
- First-run superuser at `/` needs `SETUP_TOKEN` when `DEBUG=false`

### 📚 Documentation

- [Production security](docs/security.md) guide
- `./tools/prod-config-check.sh` smoke test for live HTTPS deploys

## [0.2.1] - 2026-09-07

### 🚨 Changed

- Default `CORS_ALLOW_ALL_ORIGINS=true` with `CORS_ALLOW_CREDENTIALS=false`

## [0.2.0] - 2026-09-03

### 🔒 Security

- Dependency bumps for `pip-audit`: Django 6.0.8, cryptography 50.0.0, and related packages

### 🐛 Bug Fixes

- WebDAV `PROPFIND` on a missing path returns 404, not an empty 207

### 🏗 Chore

- GitHub Actions CI: tests, lockfile, `pip-audit`, gitleaks, lychee, Docker build
- Pre-release checks via `./tools/pre-release-check.sh`
- Product strings use Shellui spelling

### 🛠 Improvements

- JWT/JWKS failure logs include algorithm, key id, issuer, audience, and JWKS kids
- API 401s include `request_id` matching `X-Request-ID`
- OpenAPI covers storage APIViews with unique operation IDs

### 📚 Documentation

- Swagger UI and ReDoc follow shell appearance
- How to read logs locally, in Docker, and in Coolify
- Shellui favicon on the Docusaurus site

## [0.1.1] - 2026-08-18

### 🛠 Improvements

- Slimmer homepage
- JWTs from a local JWKS file or `IDENTITY_JWKS` (no runtime HTTP to identity)

### 🐛 Bug Fixes

- JWKS URL loading

## [0.1.0] - 2026-08-17

### ✨ Feature

- Initial `storage-service` release
- Supabase-compatible REST API under `/storage/v1/*`
- One company bucket; files private to the creator; share with access grants
- Share links with expiry and download caps
- JWT auth via identity-service JWKS
- S3 or filesystem blob backend
- Company quota and optional per-user quota
- WebDAV at `/dav/`
- Prometheus metrics at `/storage/v1/metrics`
- Django signals on upload and delete

### 🛠 Improvements

- OpenAPI (Swagger + ReDoc) and home page
- Django admin upload statistics
- Downloads stream through Django (`FileResponse`)
- MIME detection and per-bucket allow-lists
- CORS for local Shellui, admin, and extra origins

### 🚨 Changed

- Local setup: `uv sync` / `uv run`
- Docker: `uv sync --frozen`

### 📚 Documentation

- Guides for auth, quotas, metrics, downloads, clients, access, sharing, signals, and admin
