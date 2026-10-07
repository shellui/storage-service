---
description: Create a secret link that downloads one file without a JWT, with an expiry or a download cap.
---

# Share links

A share link downloads one file for anyone who has the token. It is not a public folder, and it is not listed for anonymous callers. The creator, a company owner, or staff can list and revoke the links for that object.

Use a link when the recipient has no Shellui account. Use an [access grant](access.md) when they do.

## What you must set

Each link needs at least one limit:

- `expires_at`: an absolute ISO 8601 end time
- `max_downloads`: a positive integer

You may set both. The link is inactive when it is past `expires_at`, when `download_count` has reached `max_downloads`, or when `revoked_at` is set. Redeeming an inactive link returns 410 `share_inactive`.

## REST

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/storage/v1/share/{bucket}/{path}` | JWT, write on the object | Create a link. `token` is returned once |
| `GET` | `/storage/v1/share/{bucket}/{path}` | JWT, write on the object | List links for that object |
| `GET` | `/storage/v1/share/link/{token}` | None | Download the file |
| `DELETE` | `/storage/v1/share/link/{token}` | JWT, creator or owner or staff | Revoke |

Create body:

```json
{
  "expires_at": "2026-12-31T23:59:59Z",
  "max_downloads": 5,
  "notes": "External review"
}
```

The response includes `token` and `path_url` (`/storage/v1/share/link/{token}`). Build the absolute URL on your host and send it yourself. The download streams through Django, the same way an authenticated `GET` does.

Deleting the object deletes its links.

## Share links and signed URLs

| | Share link | `POST /storage/v1/object/sign/…` |
| --- | --- | --- |
| Who can fetch | Anyone with the token | Whoever has the URL |
| Download cap | Yes | No |
| Revocation | Yes, on the `ObjectShareLink` row | Expiry only |
| Auth to redeem | None | None |

Prefer a share link when a person should receive the file. Prefer a signed URL when an already authorized client should fetch bytes from S3. Signed URL rules are in [Downloads and signed URLs](downloads.md).
