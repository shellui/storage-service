# storage-service documentation

Welcome to the `storage-service` documentation.

This backend provides Supabase-compatible object storage under `/storage/v1/*` using Django, authenticated with JWTs from identity-service.

The published site is [https://storage.docs.shellui.com](https://storage.docs.shellui.com).

## Quick links

- Project setup and **logs**: see `README.md`.
- **[Production security](security.md)** — CORS, JWT iss/aud, signed URLs, admin isolation, TLS.
- **[Authentication (JWKS)](authentication.md)** — verifying identity-service tokens.
- **[Quotas](quotas.md)** — company totals and optional per-user limits.
- **[Metrics (Prometheus)](metrics.md)** — `GET /storage/v1/metrics` and `/metrics/all`.
- **[Downloads](downloads.md)** — Django streaming and optional signed URLs.
- **[Third-party clients](clients.md)** — connecting WebDAV or S3-compatible apps.
- **[Access control](access.md)** — one company bucket, access grants, connector mounts.
- **[Share links](sharing.md)** — time- or download-limited capability URLs.
- **[Signals](signals.md)** — reacting to uploads (e.g. Markdown).
- **[Shellui Actions](actions.md)** — outbound webhooks on `storage.*` events.
- **[Email notifications](email.md)** - forward the same events to email-service when a service key is set.
- **[Event log](event-log.md)** — stored `storage.*` events, retention, and the hourly purge job.
- **[Admin statistics](admin.md)** — Django admin dashboard for uploads and documents.
