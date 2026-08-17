# storage-service

`storage-service` is a Django backend that provides **Supabase-compatible** object storage APIs for ShellUI (`/storage/v1/*`).

It authenticates with JWTs issued by [identity-service](https://github.com/shellui/identity-service) (JWKS / RS256), stores blobs in **S3** (or local filesystem), enforces **per-company** and optional **per-user** quotas, exposes **WebDAV** for third-party file clients, and fires Django **signals** on upload/delete (including Markdown sidecar extraction).

## Features

- Supabase-compatible Storage REST API under `/storage/v1/*` (one company bucket, upload, download, list with folders, move/copy, signed URLs)
- **One bucket per company** — new folders/files are **private to the creator** by default; share with **access grants** (user / company / folder / object). Nested items inherit the parent folder's permissions.
- **Share links** — secret capability URLs with expiry and/or max downloads (no registration; not listed publicly)
- Reserved **connector** buckets (SharePoint / Dropbox, …) as future **read-only** mounts
- JWT verification via identity-service JWKS (`IDENTITY_JWKS_URL`)
- Pluggable blob backend: **S3** (AWS, MinIO, R2, …) or **filesystem**
- Company total quota + optional per-user quota
- MIME type detection and per-bucket allow-lists
- Nested folder listing (prefix-based, same shape as Supabase)
- WebDAV at `/dav/` for third-party file clients (quotas + signals apply)
- Downloads stream through Django (`FileResponse`) so the Files UI can open files same-origin
- OpenAPI docs (Swagger + ReDoc) and a simple home page
- Django admin with upload statistics (documents, MIME breakdown, quotas, recent files)
- CORS for local ShellUI (`http://localhost:4000`), admin, and extra origins

## Project structure

- `config/` — Django settings and URL routing
- `apps/authapi/` — JWKS JWT authentication
- `apps/storage/` — buckets, objects, quotas, downloads, signals
- `apps/webdav/` — WebDAV connector
- `docs/` — topic guides (Docusaurus)

## Main endpoints

| Area | Path |
|------|------|
| Health | `GET /storage/v1/health` |
| Buckets | `GET/POST /storage/v1/bucket`, `GET/PUT/DELETE /storage/v1/bucket/{name}` |
| Access grants | `GET/POST /storage/v1/access/grant`, `DELETE /storage/v1/access/grant/{id}` |
| Share links | `POST/GET /storage/v1/share/{bucket}/{*path}`, `GET/DELETE /storage/v1/share/link/{token}` |
| Upload | `POST/PUT /storage/v1/object/{bucket}/{*path}` |
| Download | `GET /storage/v1/object/{bucket}/{*path}` |
| By id (picker) | `GET /storage/v1/object/id/{uuid}` |
| List (folders) | `POST /storage/v1/object/list/{bucket}` |
| Folder prefix | `GET/POST/DELETE /storage/v1/object/prefix/{bucket}` (stats, rename, recursive delete) |
| Delete many | `DELETE /storage/v1/object/{bucket}` |
| Move / copy | `POST /storage/v1/object/move`, `POST /storage/v1/object/copy` |
| Sign URL | `POST /storage/v1/object/sign/{bucket}/{*path}` |
| Quota | `GET /storage/v1/quota` |
| Stats | `GET /storage/v1/stats` |
| Metrics | `GET /storage/v1/metrics`, `GET /storage/v1/metrics/all` |
| WebDAV | `/dav/{bucket}/…` |
| OpenAPI | `/api/docs/`, `/api/docs/redoc/` |

Auth header: `Authorization: Bearer <access_token>` from identity-service. Supabase clients may also send `apikey` (ignored; JWT is authoritative).

## Quick start

```bash
# Requires https://docs.astral.sh/uv/
uv sync
cp .env.example .env
# Set SECRET_KEY; point IDENTITY_JWKS_URL at identity-service
uv run python manage.py migrate
uv run python manage.py runserver 8001
```

Open `http://localhost:8001/` for Swagger / ReDoc. Create the one-time admin user from the home page if you need Django admin (quotas, grants, share links).

Dependencies live in `pyproject.toml` and are locked in `uv.lock`. Add a package with `uv add <name>`; refresh the lock with `uv lock`.

### Identity wiring

Tokens come from identity-service. Point storage at its JWKS with an env var:

```bash
# Local
IDENTITY_JWKS_URL=http://localhost:8000/.well-known/jwks.json

# Production
IDENTITY_JWKS_URL=https://id.shellui.com/.well-known/jwks.json

# Or only the base URL (path /.well-known/jwks.json is appended):
IDENTITY_SERVICE_URL=https://id.shellui.com
```

Copy `.env.example` → `.env` and change the value there (Compose and `runserver` both load it).

For identity DEBUG/HS256 locally, also set `JWT_HS256_FALLBACK_SECRET` to the same `SECRET_KEY` as identity-service.

### S3 / MinIO

```bash
STORAGE_BACKEND=s3
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_STORAGE_BUCKET_NAME=shellui
AWS_S3_ENDPOINT_URL=http://localhost:9000   # MinIO; omit for AWS
AWS_S3_REGION_NAME=us-east-1
AWS_S3_ADDRESSING_STYLE=path                # path for MinIO; virtual for AWS
```

These `AWS_*` values are used by Django (django-storages) for uploads and streamed downloads. In Compose, point the endpoint at the MinIO service hostname:

```bash
AWS_S3_ENDPOINT_URL=http://minio:9000
docker compose --profile s3 up --build
```

## Downloads

Object `GET` streams through Django. Optional signed URLs: `POST /storage/v1/object/sign/{bucket}/{path}`.

See [docs/downloads.md](docs/downloads.md).

## ShellUI frontend (future connector)

Mirror Supabase Storage so one client can target either backend:

```ts
// Planned shape — not shipped in shellui yet
storage: {
  type: 'shellui', // or 'supabase'
  url: 'http://localhost:8001',
}
// Client calls `${url}/storage/v1/...` like @supabase/storage-js
```

## Docker

```bash
cp .env.example .env
docker compose up --build
```

Default host port: `8001`.

## Tests

```bash
uv run python manage.py test
```

## Documentation

Hosted at [https://storage.docs.shellui.com](https://storage.docs.shellui.com) (published to GitHub Pages on `main` and `v*` tags).

- [API overview](docs/index.md)
- [JWKS auth](docs/authentication.md)
- [Access control & grants](docs/access.md)
- [Share links](docs/sharing.md)
- [Quotas](docs/quotas.md)
- [Metrics (Prometheus)](docs/metrics.md)
- [Downloads](docs/downloads.md)
- [Third-party clients (WebDAV / S3)](docs/clients.md)
- [Signals](docs/signals.md)

Build docs site: `./tools/generate-docs.sh`
