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

## [0.5.0] - 2026-10-07

### ✨ Feature

- Scheduled jobs: the image runs `retry_webhooks` every minute and `purge_expired_data` hourly at minute 17, with a Redis lock so one run proceeds across replicas.
- Staff read job health at `GET /api/v1/scheduled-jobs`. Scheduler series stay on `GET /storage/v1/metrics/all`.
- With `EMAIL_SERVICE_API_KEY` set, storage events are posted to email-service, and every event is stored for `GET /api/v1/actions/event-log`.

### 🚨 Changed

- Production (`DEBUG` false) requires `REDIS_URL`. The container exits if it is missing.

### 📚 Documentation

- The handbook covers setup, buckets, access, scheduled jobs, email, and the API. The in-repo docs site is removed.

### 🐛 Bug Fixes

- Django admin deletes remove stored blobs and quota usage, and emit `storage.object.deleted`. `storage.bucket.created` includes the acting user.
- `retry_webhooks` locks the outbox row on Postgres and claims an email delivery that has no action rule.

### 🔒 Security

- Private email-service URLs need `EMAIL_SERVICE_ALLOW_PRIVATE`. Webhook and email bodies omit tokens, sign-in links, signed URLs, and secret-shaped fields.
- Access logs omit query strings, Referer, and share-link tokens. Sentry drops those, authorization headers, and stack locals.

### ⬆️ Upgrade notes

- Apply migrations through `0004_email_service_outbox`, set `REDIS_URL`, and drop any external cron for these two jobs (or set `SCHEDULER_ENABLED=false`).
- Set `EMAIL_SERVICE_ALLOW_PRIVATE=true` when `EMAIL_SERVICE_URL` is an internal or loopback address.

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
