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

- Fixed system buckets: auto-provisioned **company** (shared) and **user-{id}** (personal) buckets; custom bucket create/update/delete disabled.
- Access descriptor on bucket and object list responses for clear UI labeling; `StorageAccessGrant` model reserved for future invite/block sharing.
- Docs: [Access control](docs/access.md).

### 🐛 Bug Fixes

- After deleting a blob on the filesystem backend, prune empty parent directories (UUID / bucket path leftovers under `data/media/objects/`).

### 🗑 Removed

- Free-form bucket creation and public object downloads in v1.

### ✨ Feature (earlier)

- Django admin dashboard with upload statistics: totals, documents, MIME families, company/bucket breakdowns, quota meters, daily upload chart, and recent files (`/admin/`, `/admin/statistics/`).
- REST `GET /storage/v1/stats` for ShellUI admin (company-scoped; staff see global).
- Folder prefix API: `GET/DELETE /storage/v1/object/prefix/{bucket}` to count and recursively delete folder contents.
- Auth hardening: refuse `JWT_HS256_FALLBACK_SECRET` when `DEBUG=false` (unless `ALLOW_JWT_HS256_FALLBACK`); public downloads no longer pick an arbitrary company via `.first()`; authenticated downloads use `Cache-Control: private, no-store`.
- Docs describe third-party WebDAV/S3 clients in general (`docs/clients.md`) rather than a single vendor app.

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
