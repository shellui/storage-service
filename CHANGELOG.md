# Change Log

Notable changes to this project. Format: [Keep a Changelog](http://keepachangelog.com/). Versioning: [Semantic Versioning](http://semver.org/).

<!---
## [x.y.z] - yyyy-mm-dd

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

## [Unreleased]

### 🔒 Security

- Agent access tokens are accepted only on `POST /mcp`, and only when `token_type` is `access`. Every other route returns 401 for them, including WebDAV and the scheduled-job routes. `/mcp` does not list or run the scheduled-job routes (`global_refused`).
- A personal agent acts as its creator, with the creator's file access and live company role. The role is read from the `creator_status` field of Identity's signed revocation snapshot (polled every 30 seconds), not from the token, so a demotion applies within that window. If the creator has left the company (`gone`) the agent is refused with 401. No `creator_status` (an older Identity) means a plain member, never an owner. Global and delegated tokens are always plain members and any role-looking claim on them is ignored. It never gains staff status. User `0` means no user: it never matches a private file or a user grant. An agent with no creator can use only company-visible files and cannot upload a private file (403 `agent_has_no_owner`).
- Agents cannot create or delete access grants or create share links. Those tools are not listed on `/mcp` and calling one returns "Unknown tool". Revoking a share link stays available.
- Signed URLs for private objects are always signed against the S3 endpoint. `AWS_S3_CUSTOM_DOMAIN` is no longer used for them, so an unsigned CDN URL can no longer replace a signed, expiring one.
- A replaced file is written to a new key first. The old bytes are deleted only after the new file is saved and the database write succeeds. The checksum is computed on the same stream that is saved, and an orphan blob is removed when the database write fails.
- S3 signed URLs set `ResponseContentDisposition` and `ResponseContentType`. HTML, SVG, XML, scripts, and other active types are attachments with a safe content type. Raster images other than SVG, PDF, plain text, audio, and video stay inline.
- Uploads stream to storage in 1 MiB chunks. `Content-Length` above the cap is rejected before the body is read. The cap is the lower of the bucket `file_size_limit` and `MAX_UPLOAD_BYTES` (default 5 GiB). Multipart form uploads may declare up to 1 MiB above that cap for form framing.
- Django 6.1.3 includes the Django security releases of October and November 2026, among them a fix for memory use when parsing large multipart uploads.

### 🚨 Changed

- `shellui-django` 0.8.0 with Django 6.1.3, Django REST framework 3.18.3 and drf-spectacular 0.30.0. The shellui-django pins are exact, so these move together.
- gunicorn 27.0.1. A request whose `Transfer-Encoding` does not end with `chunked` (for example `identity` alone) now gets HTTP 400. No gunicorn setting changed.
- Connector writes, quota changes, and Shellui Actions admin calls from an agent follow its creator's live role. An agent whose creator is a company owner has owner access, and any other agent gets 403. A human company-owner JWT is unchanged.
- An agent now needs a person's approval, in every access mode including `full`, to: create or update an Actions webhook, change any quota, mount an outside bucket (create a connector, which carries credentials), and copy or move a file to a place more people can see than at the source (a company-visible or shared folder, or a folder shared with someone the source is not). Changing or deleting a connector, deleting a webhook and other destructive calls already needed approval. A read only agent is still refused. The approval is single use and bound to the exact arguments.
- Deploy notes: `AWS_S3_ENDPOINT_URL` must be a public URL that clients can reach, because private objects are always signed against it (an internal-only endpoint produces signed links nobody can open). A token with no `token_type` is no longer a bearer and now gets 401; refresh and setup tokens are refused the same way. Deploy Identity (#195) first.
- Deploy note: files that earlier versions stored as user `0` stay in place and become visible to and manageable by company owners and staff. Migration `0008_unowned_agent_files` labels them, and `manage.py reassign_unowned_files --company N --user M [--prefix P] [--dry-run]` gives them to a person. See [MCP agents](docs/mcp.md#upgrading-files-stored-as-user-0). Deploy Identity (#195) first: it adds `creator_status` to the revocation snapshot. Storage on an older Identity treats every agent as a plain member.

### 🏗 Chore

- Node.js 26, the current LTS, for the image build stage and CI.
- GitHub Actions: actions/checkout v7, actions/setup-node v7, astral-sh/setup-uv v10.4.0, docker/build-push-action v7, docker/login-action v4, docker/metadata-action v6, docker/setup-buildx-action v4, docker/setup-qemu-action v4, peter-evans/dockerhub-description v5.0.0.
- Python dependencies: python-dotenv 1.2.4, psycopg 3.3.9, sentry-sdk 2.77.0, cryptography 50.0.2, requests 2.34.2, markdown 3.11.4, redis 8.2.0, sqlparse 0.6.1, celery 5.7.0.
- npm dependencies: @tailwindcss/cli 4.3.5, tailwindcss 4.3.5.

## [0.9.1] - 2026-11-24

### 🐛 Bug Fixes

- With `OTEL_EXPORTER_OTLP_ENDPOINT` set, `manage.py` (and so the container start) failed with `AppRegistryNotReady`, because telemetry registered the storage metrics before Django loaded its apps. Telemetry now loads the apps first.
- The Celery worker no longer registers the storage and scheduled-job gauges. Its thread pool shares one database connection, so the metric reader thread could fail with `another command is already in progress`. Gunicorn still publishes the gauges.

## [0.9.0] - 2026-11-24

### ✨ Feature

- OpenTelemetry traces, metrics, and log correlation through `shellui-django[otel]` 0.7.0. Export stays off until `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Log lines include `trace_id` and `span_id` (both `0` when telemetry is off). Outbound `requests` calls and Celery tasks keep the W3C `traceparent`. S3 calls are spans with the bucket name and operation. Object keys are not recorded.
- Storage and scheduled-job Prometheus series are OpenTelemetry instruments with the same meaning. `company_id` stays on the storage gauges. Scheduled-job labels stay `job`, `status`, and `kind`. Names are listed in [Configuration](docs/configuration.md) and [Scheduled jobs](docs/maintenance-jobs.md).

### 🗑 Removed

- **Breaking:** `GET /storage/v1/metrics` and `GET /storage/v1/metrics/all` are removed, along with the Prometheus client. Those paths no longer serve a scrape. JSON `GET /storage/v1/stats` and `GET /api/v1/scheduled-jobs` are unchanged.
- The `pat_agm` claim (`access_global_metrics`) is ignored. It only authorized the removed global metrics route.

### ⚠️ Deprecated

- Personal access tokens may still carry `pat_agm`. storage-service does not read it. No database column is dropped in this release.

## [0.8.0] - 2026-11-18

### ✨ Feature

- Shellui MCP endpoint for agents at `POST /mcp`.
- OpenAPI descriptions and markers so MCP agents can discover storage tools.
- REST and MCP APIs for external connector lifecycle and local configuration checks. Credentials are encrypted at rest and omitted from responses.

### 🛠 Improvements

- MCP tool names match the ai-service gateway (`storage_<verb>_<noun>`). OpenAPI operation ids are unchanged.
- Tool arguments are the operation fields in one object, with enums for fixed values. Method and path are not inputs.
- `tools/call` accepts base64 upload content, allows `/` in object paths, and returns download bytes as base64.
- A new share link returns the token once. Signing secrets, path URLs, and signed URLs stay masked or follow read rules.
- Destructive tools (deletes, public links, signed URLs, webhook tests, secret rotation) ask for approval even in full access. Creating or updating a Shellui Actions rule stays a non-destructive write.
- `tools/list` keeps each tool's registry hints for the ai-service gateway.
- `POST /mcp` allows 120 requests a minute per agent. Set `MCP_RATE_LIMIT_AGENT` to change that cap.

### 🚨 Changed

- Dependabot version updates now open against develop.

### 🐛 Bug Fixes

- Agent tokens are checked against the public MCP URL when set, so the ai gateway can reach `/mcp` on an internal host.
- Delete-many and prefix-delete tools accept their JSON body fields (`prefixes`, `paths`, `prefix`).
- A destructive approval open sends `is_destructive: true`, so identity can store the matching call log after consume.
- ReDoc and Swagger UI render before the Shellui SDK finishes loading.
- `POST /mcp` serves a cached OpenAPI tool list under a lock.

### 🔒 Security

- **Breaking for inline previews:** downloads, share links, and WebDAV serve HTML, SVG, scripts, XML, and unknown types as attachments. Images, PDF, plain text, audio, and video stay inline. Clients that rendered those types in the browser now receive a file download. Every stored-file response sets `nosniff` and a sandbox content security policy, and filenames follow RFC 6266.
- Delegated agent tokens are checked with identity before a tool runs, and a second consume of the same approval is denied.
- `POST /mcp` returns `503 identity_unavailable` when the signed revocation list cannot be loaded, and agents are revoked only from that trusted list.
- Agent tokens with staff operator claims are refused, and approval consume requires `consumed: true` from identity.

### 🗑 Removed

- Storage no longer posts tool-call logs to identity. The ai-service gateway records each `tools/call`. Token checks, revocation, and approvals stay on this service.

### 📚 Documentation

- The publish workflow writes the Docker Hub overview from `DOCKERHUB.md` after it pushes an image.
- That step needs GitHub Actions secrets `DOCKERHUB_DESCRIPTION_USERNAME` and `DOCKERHUB_DESCRIPTION_TOKEN`: a Docker Hub personal access token with Read, Write, and Delete, from a user with Admin on the repository. The image still publishes when those secrets are unset, and the overview step is skipped.

### 🏗 Chore

- Use `shellui-django[mcp]==0.5.1` and sign internal MCP assertions with this service's RS256 key.
- Docker dev target and handbook notes for the Shellui local dev stack.
- Docs CI fetches the identity, hosting, and email handbooks so Shellui pages that link to them still build. Storage docs stay from this checkout.

### ⬆️ Upgrade notes

- Apply migrations `0006_connector_bucket_lifecycle` and `0007_connector_safe_settings_and_issues`. The image entrypoint applies them on start.
- MCP revocation checks and approvals need `STORAGE_SERVICE_SIGNING_KEY` or `STORAGE_SERVICE_SIGNING_KEY_FILE` (RSA PEM, 2048 bits or more) and `STORAGE_SERVICE_ISSUER`. Register that same issuer on identity-service. If either value is missing, those identity-service calls fail closed (`503`).
- Set `STORAGE_PUBLIC_URL` to this service's public origin when the ai gateway calls an internal host. Agent tokens must target `{url}/mcp`. Leave it empty to use the request host.

## [0.7.1] - 2026-11-01

### 🐛 Bug Fixes

- Access log: a response without `X-Request-ID` (health check, redirect) no longer makes logging fail and print request headers, including the identity bearer token, to stderr.

## [0.7.0] - 2026-11-01

### ✨ Feature

- Company deletion: identity-service flags a deleted company and a Celery job purges its files (S3 or disk) and rows every 60 seconds.

## [0.6.2] - 2026-10-27

### 🐛 Bug Fixes

- ReDoc at `/api/docs/redoc/` loads again, and ReDoc, Swagger UI and the Shellui SDK are served from the service's own static files instead of a CDN.

## [0.6.1] - 2026-10-24

### 🏗 Chore

- Docker publish only moves `latest` for the highest stable tag and fails early when Docker Hub secrets are missing.

## [0.6.0] - 2026-10-24

### ✨ Feature

- Docker `HEALTHCHECK` on the new `GET /health/live` liveness probe, with no database or Redis work.
- Publishing a GitHub release pushes the multi-arch image (amd64, arm64) to Docker Hub.
- `manage.py generate_env` prints the production settings with a fresh `SECRET_KEY`.

### 🚨 Changed

- `.env.example` is generated from `config/env_registry.py` and lists only required settings, with optional ones commented out.
- With `DEBUG=false`, a `SECRET_KEY` shorter than 50 characters or a placeholder refuses to start.

### 🛠 Improvements

- **Errors:** Error pages use the Shellui design, and API errors always return JSON.

### 🔒 Security

- JWKS verification rejects a token `kid` that is not in the key set, including when that set has one key.
- Secure admin cookies are named `__Host-sessionid` and `__Host-csrftoken`, the CSRF cookie is HttpOnly, and neither cookie sets Domain.
- certifi upgraded to 2026.10.19 (PYSEC-2026-4320).
- djangorestframework upgraded to 3.18.2 (CVE-2026-114136, CVE-2026-114137, CVE-2026-114138).

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
