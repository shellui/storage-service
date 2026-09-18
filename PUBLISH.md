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

The image contains application code and collected static files. Gunicorn listens on port **8000**. Secrets and runtime configuration are supplied via environment variables at container start (see `.env.example`). Object downloads stream through Django.

## Pre-release checklist

Complete these steps **before** building and pushing a release tag. Prefer the automated script (same checks run on PRs to `main`):

```bash
./tools/pre-release-check.sh
```

| Step | What it verifies |
|------|------------------|
| Version alignment | `pyproject.toml` version matches a dated `CHANGELOG.md` entry (`## [x.y.z] - YYYY-MM-DD`) and `uv.lock` |
| Build secrets | `.env` / `*.sqlite3` not tracked; `.gitignore` / `.dockerignore` exclude `.env`; built image has no `/app/.env` |
| Image smoke test | Container serves `/storage/v1/health` with `status=ok` (static `IDENTITY_JWKS` + prod security defaults) |

Options: `--skip-docker` (version + git hygiene only), `--image TAG`, `--port PORT`.

GitHub Actions: [`.github/workflows/pre-release.yml`](.github/workflows/pre-release.yml) runs this script on every pull request targeting `main` (and via **workflow_dispatch**).

Manual equivalents (if you are not using the script):

### 1. Version alignment

Ensure these match the release version (e.g. `0.3.0`):

- `version` in `pyproject.toml` (OpenAPI / API metadata via `config.settings.VERSION`)
- `CHANGELOG.md` entry with date
- Git tag `v0.3.0` (optional but recommended; not enforced by the script)
- CI green on the release commit (`.github/workflows/ci.yml` + pre-release workflow)

### 2. No secrets in the build context

```bash
# .env must not be tracked or copied into the image
test ! -f .env || grep -qE '^\.env$' .gitignore

docker build -t shellui/storage-service:release-check .
docker run --rm --entrypoint sh shellui/storage-service:release-check \
  -c 'test ! -f /app/.env && echo "OK: .env not in image"'
```

`.dockerignore` excludes `.env`, `*.sqlite3`, `.git`, and local tooling artifacts. Only `.env.example` is included (placeholders only).

### 3. Smoke test the image

Covered by `./tools/pre-release-check.sh`. Manual form:

```bash
export SECRET_KEY="$(uv run python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())")"
# Prefer a static JWKS document for offline smoke tests (see the script).

VERSION=0.3.0
docker build -t "shellui/storage-service:${VERSION}" .

docker run --rm -d --name storage-release-smoke -p 18001:8000 \
  -e SECRET_KEY \
  -e ALLOWED_HOSTS=localhost,127.0.0.1 \
  -e STORAGE_BACKEND=filesystem \
  -e IDENTITY_JWKS \
  -e IDENTITY_ISSUER=https://pre-release.test \
  -e IDENTITY_AUDIENCE=shellui \
  -e SECURE_SSL_REDIRECT=false \
  -e POSTGRES_SSL_REQUIRE=false \
  "shellui/storage-service:${VERSION}"

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

For semver release `0.3.0`, typical Docker Hub tags:

| Tag      | Purpose                                  |
| -------- | ---------------------------------------- |
| `0.3.0`  | Exact release (pin in production)        |
| `0.3`    | Latest patch in the 0.3 line             |
| `latest` | Newest published release (use with care) |

### Option A — single platform

From the repository root:

```bash
VERSION=0.3.0
IMAGE=shellui/storage-service

docker build -t "${IMAGE}:${VERSION}" .
docker push "${IMAGE}:${VERSION}"

# Optional extra tags
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:0.3"
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
docker push "${IMAGE}:0.3"
docker push "${IMAGE}:latest"
```

### Option B — multi-arch (recommended for production)

If you build on Apple Silicon, a plain `docker build` may produce `linux/arm64` only. Most cloud VMs expect `linux/amd64`. Publish both with buildx:

```bash
VERSION=0.3.0
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
VERSION=0.3.0
git tag -a "v${VERSION}" -m "Release ${VERSION}"
git push origin "v${VERSION}"
```

Pushes to `main` and `v*` tags that point at `main` run [`.github/workflows/deploy-docs.yml`](.github/workflows/deploy-docs.yml) and publish Docusaurus to GitHub Pages at [https://storage.docs.shellui.com](https://storage.docs.shellui.com).

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
  -e IDENTITY_JWKS='{"keys":[...]}' \
  shellui/storage-service:0.3.0
```

The entrypoint runs migrations on start, then starts Gunicorn on port 8000.

Or with Compose: copy `.env.example` → `.env`, set `SECRET_KEY` and a local JWKS (`IDENTITY_JWKS` or `IDENTITY_JWKS_FILE`), then `docker compose up --build`.

### Post-deploy production config check

Quick copy-paste commands and exit-code notes: [README — Post-deploy prod check](README.md#post-deploy-prod-check).

After deploying a release, run the smoke script against the live HTTPS storage URL:

```bash
./tools/prod-config-check.sh https://files.shellui.com
```

The script prints explicit `PASS:` / `FAIL:` / `WARN:` / `INFO:` lines and exits non-zero if any hard check fails. It verifies HTTPS reachability, public `GET /storage/v1/health` (200 JSON with `status=ok`), that protected `/storage/v1/*` routes return 401/403 (not 500) without a Bearer token, that `/` is not an open superuser signup form, permissive CORS for preview origins, identity JWKS wiring notes (via health + checklist), and security headers (HSTS warn-only).

Optional environment:

| Variable                   | Default                                      |
| -------------------------- | -------------------------------------------- |
| `CORS_PROBE_ORIGIN`        | `https://example-preview-slug.shellui.app`   |
| `EXPECTED_IDENTITY_ISSUER` | unset (printed as INFO checklist)            |
| `EXPECTED_IDENTITY_AUDIENCE` | `shellui`                                  |

Full JWT upload/download flows cannot be verified without identity-service tokens — the script prints guidance for `IDENTITY_JWKS` / `IDENTITY_JWKS_FILE` and `IDENTITY_ISSUER` / `IDENTITY_AUDIENCE`.

**Coolify / internal Postgres:** storage parses `POSTGRES_DATABASE_URL` with `ssl_require=false` by default. If boot still fails with SSL errors against an internal Docker Postgres, set `POSTGRES_SSL_REQUIRE=false` in orchestration (same gotcha as identity-service 0.5.0).

One-off without a full clone:

```bash
curl -fsSL https://raw.githubusercontent.com/shellui/storage-service/develop/tools/prod-config-check.sh -o prod-config-check.sh
chmod +x prod-config-check.sh
./prod-config-check.sh https://files.shellui.com
```

### Required runtime env vars (production)

| Variable            | Notes                                                                                      |
| ------------------- | ------------------------------------------------------------------------------------------ |
| `SECRET_KEY`        | Required; Django sessions/CSRF. Generate with `get_random_secret_key()`.                   |
| `IDENTITY_JWKS` or `IDENTITY_JWKS_FILE` | Public JWKS JSON (preferred in production; no HTTP to identity).          |
| `IDENTITY_ISSUER`   | Required when `DEBUG=false`; must match identity `JWT_ISSUER` (0.5.0+).                   |
| `IDENTITY_AUDIENCE` | Required when `DEBUG=false`; must match identity `JWT_AUDIENCE` (typically `shellui`).      |
| `ALLOWED_HOSTS`     | Comma-separated hostnames, no scheme.                                                      |
| `CSRF_TRUSTED_ORIGINS` | Full URLs with scheme when using browser flows behind HTTPS.                            |

First superuser: run `python manage.py createsuperuser` inside the container (or exec), or set a one-time `SETUP_TOKEN` and open `/?setup_token=<token>` — the public home form is disabled when `DEBUG=false` and no token is provided.

### Optional runtime env vars

| Variable                | Notes                                                                 |
| ----------------------- | --------------------------------------------------------------------- |
| `CORS_ALLOW_ALL_ORIGINS` | Default `true` (permissive API CORS; Bearer JWT is the auth boundary). Set `false` to lock down. |
| `CORS_ALLOW_CREDENTIALS` | Default `false`. Must not be `true` when allow-all is enabled.          |
| `CORS_ALLOWED_ORIGINS`  | Used when `CORS_ALLOW_ALL_ORIGINS=false`; Shellui / admin front-end origins. |
| `POSTGRES_DATABASE_URL` | Use Postgres instead of SQLite.                                       |
| `POSTGRES_SSL_REQUIRE`  | Default `true` when `DEBUG=false`; set `false` for internal DB only.  |
| `DJANGO_ADMIN_ENABLED`  | Default `true`; set `false` on public API pods (see `docs/security.md`). |
| `STORAGE_BACKEND`       | `filesystem` (default in the image) or `s3`.                          |
| `AWS_*`                 | django-storages when `STORAGE_BACKEND=s3`.                            |
| `AWS_S3_ENDPOINT_URL`   | MinIO/R2 origin (e.g. `http://minio:9000`). Omit for AWS.             |
| `AWS_S3_ADDRESSING_STYLE` | `path` (MinIO) or `virtual` (AWS). Empty = path if endpoint is set. |
| `SENTRY_DSN`            | Sentry error reporting.                                               |
| `SENTRY_ENVIRONMENT`    | e.g. `staging`, `production`.                                         |
| `LOG_LEVEL`             | `DEBUG`, `INFO`, `WARNING`, … (default `DEBUG` when `DEBUG=true`, else `INFO`). |
| `SETUP_TOKEN`           | One-time token for web superuser bootstrap when `DEBUG=false`; prefer `createsuperuser`. |

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
| JWT `iss` / `aud`       | Required when `DEBUG=false` (`IDENTITY_ISSUER` / `IDENTITY_AUDIENCE`) |
| CORS allow-all          | Allowed when credentials are off; startup fails if both allow-all and credentials |
| HS256 JWT fallback      | Refused when `DEBUG=false` unless explicitly allowed |
| Filesystem signed URLs  | Not cryptographically signed; use S3 in production  |
| Django admin            | Cross-tenant; disable on API pods or restrict network + MFA |
| SQLite / blob files     | Excluded from image; use volume or S3 + Postgres    |
| Public object downloads | Disabled; use share links for anonymous access      |
| First-run bootstrap     | Home superuser form disabled when `DEBUG=false` without `SETUP_TOKEN` |

Do not commit `.env` or real AWS keys to git. Do not pass secrets as Docker build args unless you accept they may appear in image history.

## Rollback

Pull and run a previous tag or digest:

```bash
docker pull shellui/storage-service:0.1.0
```

Data in `storage-service-data` (or Postgres / S3) is independent of the image tag; test migrations when downgrading.
