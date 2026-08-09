# Access control

## v1 model (enforced)

Storage no longer allows creating arbitrary buckets. Listing buckets auto-provisions:

| Bucket | Name | Who can access |
|--------|------|----------------|
| Company private | `company` | Every member of the JWT `company_id` |
| User private | `user-<user_id>` | Only that user (same company) |
| Connector (future) | e.g. `sharepoint` | Reserved — hidden / denied in v1 |

- Public buckets and anonymous public downloads are **disabled**.
- Creating, updating, or deleting system buckets via the API returns `403`.
- Object list/download/upload/delete all go through `get_accessible_bucket`.

API responses include an `access` object (`audience`, `readers`, `writers`, `description`) so the Files UI can show who can see each bucket and file.

## Future sharing (`StorageAccessGrant`)

The `StorageAccessGrant` model is the planned invite / provide / block layer:

- **Subject:** user, group, or company
- **Resource:** bucket, folder prefix, or object
- **Permission:** read, write, admin
- **Effect:** allow or deny

When enabled, evaluation should be: deny grants → allow grants → bucket-kind defaults.
Not enforced in v1.
