# storage-service

File storage for Shellui apps, with a Supabase-compatible API.

[![CI](https://github.com/shellui/storage-service/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/shellui/storage-service/actions/workflows/ci.yml)
[![Docker Hub](https://img.shields.io/docker/v/shellui/storage-service?sort=semver&label=docker)](https://hub.docker.com/r/shellui/storage-service)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

storage-service stores company files under `/storage/v1/*`, in the same shape as Supabase Storage. It verifies JWTs from [identity-service](https://github.com/shellui/identity-service) and keeps blobs on S3 (AWS, MinIO, R2) or the local filesystem. Each company gets one bucket with access grants, share links, quotas and WebDAV. The [files](https://github.com/shellui/files) app is its user interface.

## Get started

You need Docker and Git, and an [identity-service](https://github.com/shellui/identity-service) running on port 8000.

```bash
git clone https://github.com/shellui/storage-service.git
cd storage-service
cp .env.example .env   # then set SECRET_KEY
docker compose up --build
```

The API runs on [http://localhost:8001](http://localhost:8001). `/api/docs/` is the OpenAPI reference and `/admin/` is Django admin. The full setup is in [Run storage-service](docs/getting-started.md).

Point a Shellui app at it:

```ts
storage: {
  url: 'http://localhost:8001',
}
```

## Configuration

For production, `python manage.py generate_env --host storage.example.com` prints the required settings with a fresh `SECRET_KEY`.

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Django secret, 50+ characters when `DEBUG=false` |
| `IDENTITY_SERVICE_URL` | identity-service base URL. In production, pin `IDENTITY_JWKS` instead |
| `IDENTITY_ISSUER`, `IDENTITY_AUDIENCE` | Must match identity `JWT_ISSUER` and `JWT_AUDIENCE` |
| `REDIS_URL` | Required when `DEBUG=false`. Cache and scheduled jobs |
| `STORAGE_BACKEND` | `filesystem` (default) or `s3` |

Every setting is in [Configuration](docs/configuration.md).

## Documentation

The handbook lives in [`docs/`](docs/index.md) and is published at [docs.shellui.com/storage](https://docs.shellui.com/storage).

- [Buckets and objects](docs/buckets-and-objects.md), [downloads](docs/downloads.md) and [quotas](docs/quotas.md)
- [Access grants](docs/access.md) and [share links](docs/sharing.md)
- [Clients and WebDAV](docs/clients.md) and the [API](docs/api.md)
- [JWT authentication](docs/authentication.md) and [security](docs/security.md)
- [Webhooks](docs/actions.md), [email](docs/email.md), [event log](docs/event-log.md) and [maintenance jobs](docs/maintenance-jobs.md)

## Development

```bash
uv sync
uv run python manage.py migrate
uv run python manage.py runserver 8001
uv run python manage.py test
```

To preview the docs site, clone [shellui/shellui](https://github.com/shellui/shellui) next to this repository and run `DOCS_SERVICES=storage pnpm docs:start` there. See [Build the docs site](https://github.com/shellui/shellui/blob/main/docs/docs-site.md).

Releases go to Docker Hub as `shellui/storage-service`. The checklist is in [PUBLISH.md](PUBLISH.md) and changes are in [CHANGELOG.md](CHANGELOG.md).

## Contributing

Open an issue or a pull request against `develop`. CI runs the tests, a dependency audit, a secret scan, a link check and the docs build. Coding agents start with [AGENTS.md](AGENTS.md).

## Shellui projects

| Project | What it does |
| --- | --- |
| [shellui](https://github.com/shellui/shellui) | The shell, CLI and SDK |
| [admin](https://github.com/shellui/admin) | Administration app inside the shell |
| [files](https://github.com/shellui/files) | File explorer for storage-service |
| [identity-service](https://github.com/shellui/identity-service) | Sign-in, companies and tokens |
| [storage-service](https://github.com/shellui/storage-service) | File storage |
| [hosting-service](https://github.com/shellui/hosting-service) | Deploys and serves Shellui apps |
| [email-service](https://github.com/shellui/email-service) | Templates and sends email |
| [skills](https://github.com/shellui/skills) | Agent Skills for coding agents |
| [playground](https://github.com/shellui/playground) | Live demo of the shell |

## License

[MIT](LICENSE)
