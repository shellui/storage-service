# Publish and deploy

How to build, publish, and run the `shellui/storage-service` Docker image on [Docker Hub](https://hub.docker.com/r/shellui/storage-service).

Publishing is **manual** — there is no CI workflow for Docker Hub yet.

## Image overview

| Item        | Value                                                                  |
| ----------- | ---------------------------------------------------------------------- |
| Registry    | Docker Hub                                                             |
| Repository  | `shellui/storage-service`                                              |
| Listen port | `8000` (Compose maps host `${STORAGE_SERVICE_PORT:-8001}`)             |
| Data volume | `/app/data` (SQLite `db.sqlite3` + filesystem blobs under `media/`)    |

The image contains application code and collected static files only. Secrets and runtime configuration are supplied via environment variables at container start (see `.env.example`).

## Pre-release checklist

Complete these steps **before** building and pushing a release tag.

### 1. Version alignment

Ensure these match the release version (e.g. `0.1.0`):

- `version` in `pyproject.toml` (OpenAPI / API metadata via `config.settings.VERSION`)
- `CHANGELOG.md` entry with date
- Git tag `v0.1.0` (optional but recommended)

### 2. No secrets in the build context

Confirm locally:

```bash
# .env must not be tracked or copied into the image
test ! -f .env || grep -q '^\.env$' .gitignore

docker build -t shellui/storage-service:release-check .
docker run --rm --entrypoint sh shellui/storage-service:release-check \
  -c 'test ! -f /app/.env && echo "OK: .env not in image"'
```

`.dockerignore` excludes `.env`, `*.sqlite3`, `.git`, and local tooling artifacts. Only `.env.example` is included (placeholders only).

### 3. Smoke test the image

```bash
export SECRET_KEY="$(uv run python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())")"

VERSION=0.1.0
docker build -t "shellui/storage-service:${VERSION}" .

docker run --rm -d --name storage-release-smoke -p 18001:8000 \
  -e SECRET_KEY \
  -e ALLOWED_HOSTS=localhost,127.0.0.1 \
  -e IDENTITY_JWKS_URL=http://host.docker.internal:8000/.well-known/jwks.json \
  "shellui/storage-service:${VERSION}"

# Expect 200 and version 0.1.0
curl -s http://127.0.0.1:18001/storage/v1/health

docker stop storage-release-smoke
```

## Publish to Docker Hub

### Prerequisites

1. Docker Hub account with push access to the `shellui` organization (or your namespace).
2. Docker CLI logged in:

```bash
docker login
```

3. Clean git tree at the commit you intend to release.

### Tagging

For semver release `0.1.0`, typical Docker Hub tags:

| Tag      | Purpose                                  |
| -------- | ---------------------------------------- |
| `0.1.0`  | Exact release (pin in production)        |
| `0.1`    | Latest patch in the 0.1 line             |
| `latest` | Newest published release (use with care) |

### Option A — single platform

From the repository root:

```bash
VERSION=0.1.0
IMAGE=shellui/storage-service

docker build -t "${IMAGE}:${VERSION}" .
docker push "${IMAGE}:${VERSION}"

# Optional extra tags
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:0.1"
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
docker push "${IMAGE}:0.1"
docker push "${IMAGE}:latest"
```

### Option B — multi-arch (recommended for production)

If you build on Apple Silicon, a plain `docker build` may produce `linux/arm64` only. Most cloud VMs expect `linux/amd64`. Publish both with buildx:

```bash
VERSION=0.1.0
IMAGE=shellui/storage-service

docker buildx create --use --name multi 2>/dev/null || docker buildx use multi

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "${IMAGE}:${VERSION}" \
  -t "${IMAGE}:latest" \
  --push .
```

### Git tag (recommended)

```bash
VERSION=0.1.0
git tag -a "v${VERSION}" -m "Release ${VERSION}"
git push origin "v${VERSION}"
```

Pushing a `v*` tag that points at `main` runs [`.github/workflows/deploy-docs.yml`](.github/workflows/deploy-docs.yml) and publishes Docusaurus to GitHub Pages at [https://storage.docs.shellui.com](https://storage.docs.shellui.com).

Enable Pages once in the GitHub repo (source: `gh-pages` branch) and point a DNS CNAME `storage.docs.shellui.com` at `<org>.github.io`.

## Deploy

Pull and run the published image:

```bash
docker volume create storage-service-data

docker run -d \
  --name storage-service \
  -p 8001:8000 \
  -v storage-service-data:/app/data \
  -e SECRET_KEY='replace-with-generated-key' \
  -e ALLOWED_HOSTS='storage.example.com' \
  -e CSRF_TRUSTED_ORIGINS='https://storage.example.com' \
  -e CORS_ALLOWED_ORIGINS='https://app.example.com,https://admin.shellui.com' \
  -e IDENTITY_JWKS_URL='https://id.shellui.com/.well-known/jwks.json' \
  shellui/storage-service:0.1.0
```

The entrypoint runs migrations on start, then starts Gunicorn as user `appuser`.

Or with Compose: copy `.env.example` → `.env`, set `SECRET_KEY` and `IDENTITY_JWKS_URL`, then `docker compose up --build`.

### Required runtime env vars (production)

| Variable            | Notes                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------ |
| `SECRET_KEY`        | Required; Django sessions/CSRF. Generate with `get_random_secret_key()`.                   |
| `IDENTITY_JWKS_URL` | identity-service JWKS, e.g. `https://id.shellui.com/.well-known/jwks.json`.                |
| `ALLOWED_HOSTS`     | Comma-separated hostnames, no scheme.                                                      |
| `CSRF_TRUSTED_ORIGINS` | Full URLs with scheme when using browser flows behind HTTPS.                            |
| `CORS_ALLOWED_ORIGINS` | ShellUI / admin front-end origins.                                                      |

### Optional runtime env vars

| Variable                | Notes                                                                 |
| ----------------------- | --------------------------------------------------------------------- |
| `POSTGRES_DATABASE_URL` | Use Postgres instead of SQLite.                                       |
| `STORAGE_BACKEND`       | `filesystem` (default in the image) or `s3`.                          |
| `AWS_*`                 | Required when `STORAGE_BACKEND=s3`.                                   |
| `DOWNLOAD_MODE`         | `auto` (default), `redirect`, `xaccel`, or `stream`.                  |
| `SENTRY_DSN`            | Sentry error reporting.                                               |
| `SENTRY_ENVIRONMENT`    | e.g. `staging`, `production`.                                         |

With Postgres:

```bash
-e POSTGRES_DATABASE_URL='postgres://user:pass@host:5432/dbname'
```

With S3:

```bash
-e STORAGE_BACKEND=s3
-e AWS_STORAGE_BUCKET_NAME=shellui
-e AWS_ACCESS_KEY_ID=...
-e AWS_SECRET_ACCESS_KEY=...
```

## Security notes

| Topic                   | Status                                              |
| ----------------------- | --------------------------------------------------- |
| `.env` in image         | Excluded via `.dockerignore`                        |
| Runtime `SECRET_KEY`    | Must be provided; never baked into the image        |
| `DEBUG`                 | Defaults to `false` in Dockerfile                   |
| HS256 JWT fallback      | Refused when `DEBUG=false` unless explicitly allowed |
| SQLite / blob files     | Excluded from image; use volume or S3 + Postgres    |
| Public object downloads | Disabled; use share links for anonymous access      |

Do not commit `.env` or real AWS keys to git. Do not pass secrets as Docker build args unless you accept they may appear in image history.

## Rollback

Pull and run a previous tag or digest:

```bash
docker pull shellui/storage-service:0.1.0
```

Data in `storage-service-data` (or Postgres / S3) is independent of the image tag; test migrations when downgrading.
