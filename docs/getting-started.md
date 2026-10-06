---
description: Run storage-service locally with Docker Compose or uv, point it at identity-service, and upload a file.
---

# Run storage-service

This page takes you from a clone to a stored file. You start storage-service, point it at identity-service, then upload into the company bucket.

Run identity-service first, on port 8000. storage-service checks the JWTs identity-service issues. The identity handbook is on [docs.shellui.com/identity](https://docs.shellui.com/identity/).

## Start with Docker Compose

Docker Compose builds the image, maps port 8001 to Gunicorn on port 8000, and stores SQLite plus blobs in the `storage-service-data` volume. You need Docker and Git:

```bash
git clone https://github.com/shellui/storage-service.git
cd storage-service
cp .env.example .env
docker compose up --build
```

Set `SECRET_KEY` in `.env` before you start. Generate one with:

```bash
python - <<'PY'
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())
PY
```

`.env.example` sets `DEBUG=true` and `IDENTITY_SERVICE_URL=http://localhost:8000`. Compose passes `DEBUG` through, so this stack stays in local mode. The image itself defaults to `DEBUG=false` when you run it without that variable.

From inside Compose, identity-service on the host is `http://host.docker.internal:8000`. The Compose file uses that host when `IDENTITY_SERVICE_URL` is unset. If `.env` still says `localhost`, change it to `host.docker.internal` or the container cannot reach identity-service.

The API is at [http://localhost:8001/storage/v1/health](http://localhost:8001/storage/v1/health). Stop the stack with `docker compose down`. The named volume keeps the database and uploaded files.

## Start from a checkout

Use this path when you are changing the Python code. You need [uv](https://docs.astral.sh/uv/) and Node.js 22:

```bash
uv sync
cp .env.example .env
npm ci
npm run build:css
uv run python manage.py migrate
uv run python manage.py runserver 8001
```

`npm run build:css` writes the landing-page stylesheet. With `DEBUG=true`, `runserver` runs that build once at startup, and runs `npm ci` if `node_modules` is missing. When you edit `templates/` or the Tailwind sources, run `npm run watch:css` in a second terminal.

## Create the first admin user

With `DEBUG=true` and an empty user table, [http://localhost:8001/](http://localhost:8001/) shows a one-time form for the first Django superuser. After that, the same URL is the landing page, with links to Swagger, ReDoc, and Django admin.

In production (`DEBUG=false`), create the superuser from the shell:

```bash
uv run python manage.py createsuperuser
```

Or set `SETUP_TOKEN` and open `/?setup_token=your_setup_token_here` once. The form is refused when the token does not match.

## Upload a file

Put an access token from identity-service in `ACCESS_TOKEN`, then send the bytes. The company bucket is created on this call if it does not exist yet:

```bash
curl -fsS -X POST \
  "http://localhost:8001/storage/v1/object/company/docs/readme.md" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: text/markdown" \
  --data-binary @readme.md
```

`POST` fails with `resource_already_exists` when that path is taken. `PUT` overwrites it. Read the file back with `GET` on the same path and the same header.

The token must include a numeric `company_id`. Without it the call is rejected. Claim details are in [JWT and claim trust](authentication.md).

## Open Django admin

Sign in at [http://localhost:8001/admin/](http://localhost:8001/admin/). The statistics page is [http://localhost:8001/admin/statistics/](http://localhost:8001/admin/statistics/).

That dashboard is cross-tenant. It lists every company's buckets, objects, and quotas:

| Section | Contents |
| --- | --- |
| Overview cards | Object count, document count and size, buckets, uploads in 24 hours and 7 days |
| Daily chart | Uploads. The admin index uses 14 days. `/admin/statistics/` uses 30 days |
| MIME families | Images, text and Markdown, office and PDF, video, and the other families the dashboard groups |
| By company | Usage per company and bucket |
| Quotas | Used bytes against the limit |
| Recent uploads | Latest files: 8 on the admin index, 50 on the statistics page |

Deleting a file or a bucket here calls the same delete path as the API: the blob is removed, quota usage goes down, and `storage.object.deleted` is emitted for each file. The REST API still refuses to create or delete the company bucket. See [Security hardening](security.md) before you expose `/admin/` on a public host.

## Run it in production

The image defaults to `DEBUG=false`. It will not start until `IDENTITY_ISSUER` and `IDENTITY_AUDIENCE` are set. Pin the identity JSON Web Key Set (JWKS) with `IDENTITY_JWKS` or `IDENTITY_JWKS_FILE` so the process does not fetch identity-service on each refresh. Use a pinned tag of `shellui/storage-service`.

Before the first request, finish these steps:

1. Set `POSTGRES_DATABASE_URL` if you do not want SQLite on the `/app/data` volume.
2. Set `STORAGE_BACKEND=s3` when clients should receive signed object-storage URLs. The filesystem backend's sign route is not cryptographic.
3. Set `REDIS_URL` when `GUNICORN_WORKERS` is greater than 1, so the cache is shared.
4. Schedule `retry_webhooks` and `purge_expired_data`. The container does not run them. See [Maintenance jobs](maintenance-jobs.md).
5. Run [tools/prod-config-check.sh](../tools/prod-config-check.sh) against the storage API host, for example `https://storage.shellui.com`, not against the Files site at `files.shellui.com`.

Every variable is in [Configuration](configuration.md). Production defaults for HTTPS, CORS, and admin are in [Security hardening](security.md). Image tags and the Coolify notes are in [PUBLISH.md](../PUBLISH.md).
