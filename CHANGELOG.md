# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

<!---
## [Unreleased] - yyyy-mm-dd

### ✨ Feature – for new features
### 🛠 Improvements – for general improvements
### 🚨 Changed – for changes in existing functionality
### ⚠️ Deprecated – for soon-to-be removed features
### 📚 Documentation – for documentation update
### 🗑 Removed – for removed features
### 🐛 Bug Fixes – for any bug fixes
### 🔒 Security – in case of vulnerabilities
### 🏗 Chore – for tidying code

See for sample https://raw.githubusercontent.com/favoloso/conventional-changelog-emoji/master/CHANGELOG.md
-->

## [Unreleased]

### ✨ Feature

- **One company bucket** per company; personal `user-*` buckets are no longer provisioned.
- **Access grants enforced** for bucket / folder / object (`allow` / `deny`, read/write/admin) via `/storage/v1/access/grant`.
- **Private by default**: new folders and uploads are restricted to the creator; nested **folders copy** the parent folder's grants; nested files inherit via path matching. Share via manual grants or [share links](docs/sharing.md).
- Opening a nested path (folder **or file**) to the whole company while a **parent folder is private** returns `400 parent_folder_private`.
- `GET /storage/v1/access/grant?include_effective=1` returns `{ grants, private_ancestor }` so the Files UI can show inherited privacy.
- Object **list** rows include a path-aware `access` summary (`restricted` / `limited` audiences) so Files can show who can access each folder/file.
- **Folder rename** via `POST /storage/v1/object/prefix/{bucket}` (`from` / `to`); moves nested objects and rewrites matching access grants.
- **Share links**: secret capability URLs with `expires_at` and/or `max_downloads` (`/storage/v1/share/...`); anonymous redeem, no public directory, no registration.
- Connector buckets (`kind=connector`) listed as **read-only** when present (SharePoint / Dropbox prep).
- Docs: [Access control](docs/access.md), [Share links](docs/sharing.md).

### 🚨 Changed

- Bucket list returns the company bucket (plus any connector mounts), not personal buckets.
- Path ACL applies on list/download/upload; public bucket downloads remain disabled in favor of share links.

### 🗑 Removed

- Auto-provisioning of personal `user-{id}` buckets.
- `BucketKind.USER` / legacy personal bucket kind from the model and admin (existing `kind=user` rows are deleted on migrate).

### 🔒 Security

- Regression tests: expired JWTs are rejected with 401 on bucket list, object list, and object download/preview (no file bytes returned).
- Auth unit tests for `IdentityJWKSAuthentication` expired / missing-`exp` tokens.

### 🐛 Bug Fixes

- After deleting a blob on the filesystem backend, prune empty parent directories (UUID / bucket path leftovers under `data/media/objects/`).

### ✨ Feature (earlier)

- Django admin dashboard with upload statistics: totals, documents, MIME families, company/bucket breakdowns, quota meters, daily upload chart, and recent files (`/admin/`, `/admin/statistics/`).
- REST `GET /storage/v1/stats` for ShellUI admin (company-scoped; staff see global).
- Folder prefix API: `GET/DELETE /storage/v1/object/prefix/{bucket}` to count and recursively delete folder contents.
- Auth hardening: refuse `JWT_HS256_FALLBACK_SECRET` when `DEBUG=false` (unless `ALLOW_JWT_HS256_FALLBACK`); public downloads no longer pick an arbitrary company via `.first()`; authenticated downloads use `Cache-Control: private, no-store`.
- Docs describe third-party WebDAV/S3 clients in general (`docs/clients.md`) rather than a single vendor app.
- Free-form bucket creation and public object downloads disabled (use share links for anonymous access).

## [0.1.0] - 2026-08-08

### ✨ Feature

- Initial Django storage backend with Supabase-compatible `/storage/v1/*` APIs (buckets, objects, list with folders, move/copy, signed URLs, public downloads).
- JWT authentication via identity-service JWKS (RS256) with optional HS256 fallback for local DEBUG.
- Pluggable blob storage: S3 (django-storages / MinIO / R2) or filesystem.
- Per-company quotas with optional per-user caps; MIME detection and bucket allow-lists.
- WebDAV endpoint (`/dav/`) for third-party clients (shares quotas and upload signals).
- Download modes: signed redirect, NGINX `X-Accel-Redirect`, or Django stream (`DOWNLOAD_MODE=auto`).
- Django signals on upload/delete, including Markdown text sidecar metadata.
- Home page with Swagger UI and ReDoc; Docker Compose and docs.
