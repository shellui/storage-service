# storage-service documentation

Welcome to the `storage-service` documentation.

This backend provides Supabase-compatible object storage under `/storage/v1/*` using Django, authenticated with JWTs from identity-service.

## Quick links

- Project setup: see `README.md`.
- **[Authentication (JWKS)](authentication.md)** — verifying identity-service tokens.
- **[Quotas](quotas.md)** — company totals and optional per-user limits.
- **[Downloads](downloads.md)** — signed redirects, `X-Accel-Redirect`, and streaming.
- **[Third-party clients](clients.md)** — connecting WebDAV or S3-compatible apps.
- **[Access control](access.md)** — one company bucket, access grants, connector mounts.
- **[Share links](sharing.md)** — time- or download-limited capability URLs.
- **[Signals](signals.md)** — reacting to uploads (e.g. Markdown).
- **[Admin statistics](admin.md)** — Django admin dashboard for uploads and documents.
