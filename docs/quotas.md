---
description: Company and per-user byte caps, how usage is counted, and who can change the limits.
---

# Quotas

Each company has a byte cap. An optional per-user cap sits inside it. Uploads and copies check both before they write, and return 413 when the new object would not fit.

## Company quota

The first storage use creates a `CompanyQuota` row:

- `max_bytes` starts at `DEFAULT_COMPANY_QUOTA_BYTES` (default `10G`). A stored `max_bytes` of 0 does not enforce a company cap
- `used_bytes` moves on upload, overwrite, copy, and delete
- `max_bytes_per_user` is an optional default for every user in the company. Null or `0` turns that default off

`GET /storage/v1/quota` returns the caller's company usage and, when a per-user cap applies, that user's usage. `remaining_bytes` is the gap between max and used. For a user with no cap, `remaining_bytes` is null.

## Per-user quota

A `UserQuota` row overrides `max_bytes_per_user` for one identity user id inside the company. Without a row, the company default applies. With neither a row nor a company default, that user has no personal cap and only the company total applies.

`used_bytes` on the per-user row moves when a cap applies to that account.

## Change the caps

`PUT` requires staff, or a company owner for their own `company_id`. Staff may pass another company id. A company owner who names a different company receives 403.

```http
PUT /storage/v1/quota/company/10
Authorization: Bearer your_access_token_here
Content-Type: application/json

{"max_bytes": 10737418240, "max_bytes_per_user": 1073741824}
```

`10737418240` is `10G`. `1073741824` is `1G`. Omit a field to leave it unchanged. Set `max_bytes_per_user` to null to clear the company default.

```http
PUT /storage/v1/quota/company/10/user/42
Authorization: Bearer your_access_token_here
Content-Type: application/json

{"max_bytes": 524288000}
```

`524288000` is 500 MB (`500` × 1024²). Django admin can edit the same rows.

## What fails an upload

`assert_can_store` runs before the blob is written. The response is HTTP 413:

| `error` | Cause |
| --- | --- |
| `company_quota_exceeded` | Company `used_bytes` plus the new size would pass `max_bytes` |
| `user_quota_exceeded` | The per-user cap would be passed |
| `payload_too_large` | The body is over `MAX_UPLOAD_BYTES` or the bucket file size limit |

Delete and overwrite adjust `used_bytes` by the size removed and the size added. A failed upload does not increase usage.
