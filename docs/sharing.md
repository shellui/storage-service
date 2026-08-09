# Share links

Capability URLs let anyone with the link download **one file** without signing in. They are **not** a public file browser and are **not** registered in a public directory — only the creator (and company owners/staff) can list or revoke them.

## Limits

Each link must have at least one of:

- **`expires_at`** — absolute ISO-8601 end time  
- **`max_downloads`** — positive integer cap  

Both may be set. The link becomes inactive when expired, exhausted, or revoked (`410 share_inactive`).

## REST

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/storage/v1/share/{bucket}/{*path}` | JWT (write on object) | Create link; response includes `token` once |
| `GET` | `/storage/v1/share/{bucket}/{*path}` | JWT (write on object) | List links for that object (creator / owners) |
| `GET` | `/storage/v1/share/link/{token}` | None | Download the file |
| `DELETE` | `/storage/v1/share/link/{token}` | JWT (creator or owner/staff) | Revoke |

Create body example:

```json
{
  "expires_at": "2026-12-31T23:59:59Z",
  "max_downloads": 5,
  "notes": "External review"
}
```

Response includes `token` and `path_url` (`/storage/v1/share/link/{token}`). The frontend should build the absolute URL and send it out-of-band (email, chat). Do not scrape or publish a gallery of active tokens.

## vs signed URLs

| | Share link | `POST /object/sign/...` |
|--|------------|-------------------------|
| Audience | Anyone with the token | Usually short-lived S3/media URL for an already-authorized client |
| Download cap | Yes | No |
| Revocation registry | Yes (`ObjectShareLink`) | Relies on expiry only |
| Auth to redeem | None | None (URL secret) |

Prefer share links for human sharing; keep signed URLs for app-side download offload.
