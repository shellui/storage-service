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

### 🔒 Security

- Bump dependencies to clear `pip-audit` findings: Django `6.0.8`, cryptography `50.0.0`, djangorestframework `3.17.2`, requests `2.33.0`, PyJWT `2.13.0`, sqlparse `0.6.0`.

### 🐛 Bug Fixes

- WebDAV `PROPFIND` on a missing path returns **404** instead of an empty `207` collection.

### 🏗 Chore

- Add GitHub Actions CI on PRs and `main`/`develop`: Django tests, `uv lock --check`, `pip-audit`, gitleaks, lychee link checks, and Docker build.
- Rename remaining product strings from ShellUI to Shellui.

### 🛠 Improvements

- Log JWT/JWKS verification failures with algorithm, key id, issuer/audience, and loaded JWKS kids (token values are never logged). API 401s include a `request_id` matching `X-Request-ID`.
- Document storage APIViews for OpenAPI (serializers + unique operation IDs) so schema generation no longer skips endpoints.

### 📚 Documentation

- Sync embedded Swagger UI and ReDoc light/dark mode with shellui appearance (native Swagger UI dark mode and Redoc presets).
- Document how to read storage-service logs locally and in Docker/Coolify.
- Add Shellui brand favicon (ICO + PNG sizes) to the Docusaurus docs site.

## [0.1.1] - 2026-08-18

### 🛠 Improvements

- Remove some informations from homepage to keep it minimalist
- Verify JWTs from a local JWKS file or `IDENTITY_JWKS` env (no runtime HTTP to identity).

### 🐛 Bug Fixes

- Fix issues loading JWKS_URL.

## [0.1.0] - 2026-08-17

### ✨ Feature

- Initial release of `storage-service`.
- Added **Supabase-compatible** Storage REST API under `/storage/v1/*` (upload, download, list with folders, move/copy, signed URLs).
- Added **one bucket per company** with files **private to the creator** by default; share via **access grants** (user / company / folder / object). Nested items inherit the parent folder's permissions.
- Added **share links** — secret capability URLs with expiry and/or max downloads.
- Added JWT authentication via identity-service JWKS (`IDENTITY_JWKS_URL`).
- Added pluggable blob backend: **S3** (AWS, MinIO, R2, …) or **filesystem**.
- Added company total quota and optional per-user quota.
- Added WebDAV at `/dav/` for third-party file clients.
- Added Prometheus metrics (`GET /storage/v1/metrics`, `GET /storage/v1/metrics/all`).
- Added Django signals on upload/delete (including Markdown sidecar extraction).

### 🛠 Improvements

- Added OpenAPI documentation (Swagger + ReDoc) and a simple home page.
- Added Django admin with upload statistics (documents, MIME breakdown, quotas, recent files).
- Downloads stream through Django (`FileResponse`) so the Files UI can open files same-origin.
- MIME type detection and per-bucket allow-lists.
- CORS for local Shellui (`http://localhost:4000`), admin, and extra origins.

### 🚨 Changed

- Local setup uses `uv sync` / `uv run` (`pyproject.toml` + `uv.lock`).
- Docker installs with `uv sync --frozen`.

### 📚 Documentation

- Added topic guides for authentication, quotas, metrics, downloads, clients, access control, sharing, signals, and admin statistics.
