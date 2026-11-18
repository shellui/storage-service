# Run storage-service

storage-service stores company files for a Shellui app and serves them at `/storage/v1/`. You call the same paths as Supabase Storage. Use this page to run the `shellui/storage-service` image.

## What is inside the image

The entrypoint starts as root, prepares `/app/data`, and runs the app as `appuser`.

| Item | Value |
| --- | --- |
| Base | `python:3.14-slim` |
| Listen port | `8000` |
| Entrypoint | `/app/tools/docker-entrypoint.sh` |
| App processes | `appuser` |
| Volume | `/app/data` (SQLite and filesystem blobs) |

Node.js 22 builds the CSS during the image build, and the final image includes that file. The default command is `web`: migrate, then Gunicorn and the scheduler. The image sets `DEBUG=false` and `STORAGE_BACKEND=filesystem`.

## Start a container

Set `IDENTITY_SERVICE_URL`, `IDENTITY_ISSUER`, and `IDENTITY_AUDIENCE` from identity-service. Set `REDIS_URL` to a Redis URL the container can reach. Replace `your_secret_key_here` with a key of at least 50 characters. An empty `POSTGRES_DATABASE_URL` uses SQLite on the volume.

This command maps port 8000 and stores data in a named volume:

```bash
docker run --rm -p 8000:8000 \
  -v storage-data:/app/data \
  -e SECRET_KEY=your_secret_key_here \
  -e DEBUG=false \
  -e ALLOWED_HOSTS=storage.example.com \
  -e CSRF_TRUSTED_ORIGINS=https://storage.example.com \
  -e IDENTITY_SERVICE_URL=https://id.example.com \
  -e IDENTITY_ISSUER=https://id.example.com \
  -e IDENTITY_AUDIENCE=your_jwt_audience_here \
  -e REDIS_URL=redis://your_redis_host_here:6379/0 \
  -e POSTGRES_DATABASE_URL= \
  shellui/storage-service:0.8.0
```

This Compose file starts Redis in the same project and stores data in `storage-data`:

```yaml
services:
  storage-service:
    image: shellui/storage-service:0.8.0
    ports:
      - "8000:8000"
    environment:
      SECRET_KEY: your_secret_key_here
      DEBUG: "false"
      ALLOWED_HOSTS: storage.example.com
      CSRF_TRUSTED_ORIGINS: https://storage.example.com
      IDENTITY_SERVICE_URL: https://id.example.com
      IDENTITY_ISSUER: https://id.example.com
      IDENTITY_AUDIENCE: your_jwt_audience_here
      REDIS_URL: redis://redis:6379/0
      POSTGRES_DATABASE_URL: ""
    volumes:
      - storage-data:/app/data
    depends_on:
      - redis
  redis:
    image: redis:8-alpine
volumes:
  storage-data:
```

The app redirects HTTP to HTTPS. `GET /health/live` stays on HTTP and skips Django host checks. Set `ALLOWED_HOSTS` to `localhost`, and set `SECURE_SSL_REDIRECT=false`, for an HTTP trial on your machine.

## Required environment variables

`config/env_registry.py` requires these when `DEBUG=false`. The image already sets that. Match issuer and audience to the JSON Web Token (JWT) claims that identity-service signs.

| Variable | Example | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | `your_secret_key_here` | Signs sessions and cross-site request forgery (CSRF) tokens, at least 50 characters |
| `DEBUG` | `false` | Production mode (the image default) |
| `ALLOWED_HOSTS` | `storage.example.com` | Public host names, comma-separated, no scheme |
| `CSRF_TRUSTED_ORIGINS` | `https://storage.example.com` | Full HTTPS origin for Django admin CSRF checks |
| `IDENTITY_SERVICE_URL` | `https://id.example.com` | identity-service origin for server-side calls |
| `IDENTITY_ISSUER` | `https://id.example.com` | Must match identity-service `JWT_ISSUER` |
| `IDENTITY_AUDIENCE` | `your_jwt_audience_here` | Must match identity-service `JWT_AUDIENCE` |
| `REDIS_URL` | `redis://redis:6379/0` | Shared cache and job broker |
| `POSTGRES_DATABASE_URL` | empty | PostgreSQL URL, or empty for SQLite |

For every other variable, read the [configuration reference](https://docs.shellui.com/storage/configuration). That page covers S3, quotas, Shellui Actions webhooks, and JSON Web Key Set (JWKS) pinning.

## Image tags

A GitHub release pushes a linux/amd64 and linux/arm64 index. A manual workflow dispatch pushes the same tags. A stable semver tag, such as `v0.8.0`, becomes `latest` when it is the highest stable tag.

A release tag maps to these image tags:

| Tag | When |
| --- | --- |
| `0.8.0` | Release tag `v0.8.0`, leading `v` removed |
| `0.8` | Major and minor from that same tag |
| `latest` | Stable three-part tag, such as `0.8.0`, when that version is the highest stable tag |

## Health check

The image health check calls `GET /health/live` on port 8000. The body is `ok`, with no token, database, or Redis. `GET /storage/v1/health` returns `status` and `version`.

## Project links

Source, handbook, changelog, license, and the Shellui site:

- **Source**: [shellui/storage-service](https://github.com/shellui/storage-service)
- **Handbook**: [storage-service docs](https://docs.shellui.com/storage)
- **Changelog**: [CHANGELOG.md](https://github.com/shellui/storage-service/blob/main/CHANGELOG.md)
- **License**: [MIT](https://github.com/shellui/storage-service/blob/main/LICENSE)
- **Shellui**: [shellui.com](https://shellui.com)
