---
description: How grants decide who can read, write, or administer a folder or file inside the company bucket.
---

# Access grants

New files are private to the person who uploaded them. An access grant then allows or denies someone else, or the whole company, on a bucket, a folder, or one file.

Grants apply inside the caller's `company_id`. Another company's paths are not visible. Anonymous access is a [share link](sharing.md), not a grant.

## What a grant stores

A grant is a `StorageAccessGrant` row. The API still sends `resource_id` as a path. The row stores a foreign key, so a rename keeps the grant and a delete removes it.

| Field | Values |
| --- | --- |
| Subject | `user`, `group`, or `company`. `group` is stored and not evaluated |
| Resource | `bucket` (no object), `folder` (the `.emptyFolderPlaceholder` marker), or `object` (the file) |
| Permission | `read`, `write`, or `admin`. `admin` includes `write`. `write` includes `read` |
| Effect | `allow` or `deny` |

`subject_id` is the identity user id or the company id, as a string. `expires_at` is optional. Deleting the file, the folder marker, or the bucket deletes its grants. Renaming a folder updates the marker path. The foreign key stays, so later reads show the new path.

## Private by default

On upload, an empty-folder create, or WebDAV `MKCOL`:

1. If an ancestor folder already has grants, a new folder copies that parent folder's grants. A new file inherits them by path and does not copy extra rows.
2. Otherwise the service writes two grants on the new resource: `deny` plus `read` for `subject_type=company`, and `allow` plus `admin` for the creating user.

The company deny blocks everyone else. The creator's admin grant is what lets them share later. To open a private folder to the company, add an `allow` for the company or remove the automatic `deny`.

You cannot open a nested file or folder to the company while an ancestor folder is still private. The API returns 400 `parent_folder_private`. Open the parent first.

## How a check is decided

The check uses the most specific matching grants, then falls back to the bucket kind:

1. Specificity is object, then a deeper folder, then a folder, then the bucket. Within one resource, a user subject beats a group subject, which beats a company subject.
2. Among the grants at that specificity, `deny` wins. Otherwise `allow` wins.
3. With no deciding grant, company buckets follow the kind default: members can browse, and new paths stay private until a grant says otherwise. A connector bucket is read-only for company members.

Denying `read` blocks every use of that path. Denying `write` blocks write and admin, and leaves read. A user `allow` on a folder overrides a company `deny` on that same folder.

List rows include a path-aware `access` summary:

| `audience` | Meaning |
| --- | --- |
| `company` or `connector` | Bucket defaults. No matching grants on that path |
| `restricted` | Company-wide read is denied. Only grant subjects can access the path |
| `limited` | Company defaults still apply, and grants refine the path |

Restricted rows may include `allowed_user_ids`, `allowed_group_ids`, and `grant_count`.

## REST

Owners and staff see every grant in the company. Other callers see grants they created or that target them. `GET` with `include_effective=1` and a `resource_id` also returns `private_ancestor`, the nearest private parent folder.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/storage/v1/access/grant` | List grants |
| `POST` | `/storage/v1/access/grant` | Create a grant |
| `DELETE` | `/storage/v1/access/grant/{id}` | Revoke a grant |

Creating a `deny`, or granting `admin`, requires a company owner, staff, or someone who already has admin on that path. Creating a folder grant on a path with no marker yet creates the `.emptyFolderPlaceholder` first.

This body lets user `42` write under `hr/`:

```json
{
  "bucket": "company",
  "subject_type": "user",
  "subject_id": "42",
  "resource_type": "folder",
  "resource_id": "hr",
  "permission": "write",
  "effect": "allow"
}
```

Send it as `POST /storage/v1/access/grant` with `Authorization: Bearer your_access_token_here`.
