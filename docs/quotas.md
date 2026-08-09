# Quotas

## Company quota

Every company gets a `CompanyQuota` row (auto-created on first use):

- `max_bytes` — hard total for the company (default from `DEFAULT_COMPANY_QUOTA_BYTES`, e.g. `10G`)
- `used_bytes` — maintained on upload / delete / copy
- `max_bytes_per_user` — optional default per-user cap (`null` / `0` = off)

## Per-user quota

Optional `UserQuota` rows override the company default for a specific user:

- `max_bytes` — that user's cap within the company
- `used_bytes` — tracked when a limit applies

## APIs

```http
GET /storage/v1/quota
Authorization: Bearer …

PUT /storage/v1/quota/company/{company_id}
Authorization: Bearer …   # staff or company owner
{ "max_bytes": 10737418240, "max_bytes_per_user": 1073741824 }

PUT /storage/v1/quota/company/{company_id}/user/{user_id}
{ "max_bytes": 524288000 }
```

Django admin can also edit quota rows after the one-time superuser setup.

## Enforcement

Uploads and copies call `assert_can_store` before writing blobs. Overflow returns HTTP `413` with `company_quota_exceeded` or `user_quota_exceeded`.
