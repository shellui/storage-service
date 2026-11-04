---
description: Run storage-service in the Shellui sibling-repo dev stack (shellui/shellui dev/docker-compose.yml).
---

# Local dev stack

The Shellui monorepo layout runs every service from one Compose file in `shellui/shellui` at `dev/docker-compose.yml`. Then:

```bash
cd shellui/dev
./start.sh
```

Clone layout, URLs, common commands and troubleshooting are in the [Shellui dev stack guide](https://github.com/shellui/shellui/blob/develop/docs/dev-stack.md). This page only covers what is specific to this service.

This repository's Dockerfile exposes a **`dev`** build target for that stack. Compose builds `../../storage-service` with `target: dev`, bind-mounts this checkout at `/app`, and publishes the API on host port **8002** (`http://localhost:8002`).

Production images are unchanged: the default (final) Dockerfile stage is still the Gunicorn image used by publish workflows.

## Start storage-service in the stack

1. Clone `storage-service` next to `shellui/shellui` (see the shared contract in the Shellui handbook).
2. Ensure `dev/.env.local` defines the storage variables below (Compose maps prefixed names like `STORAGE_SECRET_KEY` to `SECRET_KEY` inside the container).
3. From `shellui/dev`, run `./start.sh`.

Health check: [http://localhost:8002/storage/v1/health](http://localhost:8002/storage/v1/health).

The `dev` container runs `migrate` then `python manage.py runserver 0.0.0.0:8000` with autoreload. Python dependencies live in `/opt/venv` so the bind mount does not hide them.

## Environment variables

Set these in `dev/.env.local` (prefixed names avoid clashes across services). Compose copies them into the storage container under the unprefixed names listed here.

| Variable | Example for the stack | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | `STORAGE_SECRET_KEY` in `.env.local` | Django signing key. Any non-empty value is fine when `DEBUG=true` |
| `DEBUG` | `true` | Local mode: optional issuer/audience, HTTP cookies, in-memory cache if Redis is missing |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,storage` | Host header allowlist |
| `CSRF_TRUSTED_ORIGINS` | `http://localhost:8002,http://127.0.0.1:8002` | Django admin form posts from the browser |
| `POSTGRES_DATABASE_URL` | `postgres://shellui:shellui@postgres:5432/storage` | Shared Postgres, database name `storage` (Compose supplies the exact DSN) |
| `POSTGRES_SSL_REQUIRE` | `false` | TLS off inside the dev network |
| `REDIS_URL` | `redis://redis:6379/1` | Shared Redis; DB index `1` for storage-service |
| `IDENTITY_ISSUER` | `http://localhost:8001` | Public JWT `iss` (browser-facing identity port) |
| `IDENTITY_AUDIENCE` | `shellui` | JWT `aud`; must match identity-service `JWT_AUDIENCE` |
| `IDENTITY_JWKS_URL` | `http://identity:8000/.well-known/jwks.json` | Server-side JWKS fetch (Docker DNS, port 8000 inside the network) |
| `IDENTITY_SERVICE_URL` | `http://identity:8000` | Server-side calls to identity MCP internal APIs (revocations, approvals, call logs) |
| `EMAIL_SERVICE_URL` | `http://email:8000` | Forward storage events when `EMAIL_SERVICE_API_KEY` is set |
| `EMAIL_SERVICE_ALLOW_PRIVATE` | `true` | Allow the internal email-service origin |
| `STORAGE_BACKEND` | `filesystem` | Local blobs under `/app/data/media` (use a volume or bind mount for persistence) |

Optional but useful:

| Variable | Example | Purpose |
| --- | --- | --- |
| `JWT_HS256_FALLBACK_SECRET` | same as identity `SECRET_KEY` | Accept HS256 debug tokens from identity when JWKS is empty |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5174,http://localhost:5175` | Extra browser origins (Files and dashboard dev servers) |
| `SCHEDULER_ENABLED` | `true` | Celery worker and beat in the dev container when `REDIS_URL` is set |

Do not commit secrets. Example values only in `.env.local`.

## Public vs internal URLs

| Use | URL |
| --- | --- |
| Browser, OAuth metadata, JWT `iss` | `http://localhost:8001` (identity), `http://localhost:8002` (storage API) |
| JWKS fetch, MCP internal APIs, service webhooks | `http://identity:8000`, `http://storage:8000`, `http://email:8000` |

Keep **`IDENTITY_ISSUER`** on the public identity origin. Point **`IDENTITY_JWKS_URL`** and **`IDENTITY_SERVICE_URL`** at the internal identity host so the container never calls `localhost` for identity.

## Standalone vs stack

This repository's own [`docker-compose.yml`](../docker-compose.yml) still maps port **8001** and targets the production image for a single-service smoke test. The Shellui dev stack uses port **8002** and the **`dev`** target instead.

Full variable reference: [Configuration](configuration.md).

## Related

- [Run storage-service](getting-started.md)
- [JWT and claim trust](authentication.md)
