# Access control

## Model

Storage provisions **one system bucket per company** (`company`). Who can see or change folders and files inside it is controlled by **access grants**, on top of kind defaults.

| Bucket | Name | Default access |
|--------|------|----------------|
| Company | `company` | Bucket is open to members for browsing; **new folders/files are private to their creator** until shared via grants. Nested items inherit the parent folder's grants. |
| Connector (future) | e.g. `sharepoint` | Company members **read-only** when the mount exists |

- Creating, updating, or deleting buckets via the API returns `403`.
- Anonymous “public bucket” downloads stay disabled — use [share links](sharing.md) instead.
- Object list/download/upload/delete go through bucket ACL **and** path-level grants.

API bucket responses include an `access` object (`audience`, `shareable`, `grants_enabled`, `can_write`, …) for the Files UI.

Object **list** rows include a path-aware `access` summary:

| `audience` | Meaning |
|------------|---------|
| `company` / `connector` | Bucket defaults (no matching grants on that path) |
| `restricted` | Company-wide read is denied; only grant subjects can access |
| `limited` | Company defaults still apply, but grants refine the path |

Restricted rows may also include `allowed_user_ids`, `allowed_group_ids`, and `grant_count`.

## Private by default

On **create** (upload, empty-folder placeholder, or WebDAV `MKCOL`):

1. If any **ancestor folder** already has grants:
   - **New folder** → copy that parent folder's grants onto the new path (so it matches the parent in listings and the Permissions UI)
   - **New file** → inherit via path matching (no extra grants)
2. Otherwise create automatic grants on the new resource:
   - `deny` + `read` for `subject_type=company` (blocks company-wide access)
   - `allow` + `admin` for the creating user (so they can share later)

Empty-folder uploads use the Supabase placeholder path `…/.emptyFolderPlaceholder` and attach folder grants to the parent path.

To share, create additional `allow` grants (user / group / company) via the API. To open a private folder to the whole company, add an `allow` for the company or remove the auto `deny`.

**Nested under a private parent:** you cannot open a subfolder/file to the whole company while an ancestor folder remains private (`400 parent_folder_private`). Open (or share) the parent first.

## Access grants (`StorageAccessGrant`)

Grants are the invite / provide / block layer. They are stored with **foreign keys**, not path strings:

| Field | Values |
|-------|--------|
| Subject | `user`, `group` (stored; not evaluated until identity exposes groups), `company` |
| Resource | `bucket` (`object` is null), `folder` (FK to `…/.emptyFolderPlaceholder`), `object` (FK to the file) |
| Permission | `read`, `write`, `admin` |
| Effect | `allow`, `deny` |

`bucket` is always set (defaults to `company` on create). Deleting a file, folder marker, or bucket **cascades** its grants. Folder rename updates the marker's `name`; the FK stays put, so `resource_id` in the API follows the new path.

The REST payload still uses `resource_id` as a path (or bucket name). Creating a folder grant on a path that has no marker yet creates `…/.emptyFolderPlaceholder` first.

Folders were originally virtual prefixes with no row unless a placeholder existed, which is why grants started as `bucket_name` + `resource_id` strings. Binding folder grants to the placeholder object is what makes cascade-on-delete and rename-without-rewrite work.

### Evaluation order

1. Consider matching grants at the **highest specificity** (object › deeper folder › folder › bucket; then user › group › company)  
2. Among those: **deny** wins, else **allow**  
3. If no deciding grant, fall back to bucket-kind defaults  

Permission strength: `admin` ⊃ `write` ⊃ `read`. Denying `read` blocks everything; denying `write` blocks write/admin only.

A more specific `allow` for a user therefore overrides a broader `deny` for the whole company on the same folder.

### REST

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/storage/v1/access/grant` | List grants (owners/staff see all; others see grants they created or that target them). Add `include_effective=1` with a `resource_id` to also get `private_ancestor` (nearest private parent folder). |
| `POST` | `/storage/v1/access/grant` | Create grant |
| `DELETE` | `/storage/v1/access/grant/{id}` | Revoke grant |

Example — allow user `42` to edit `hr/`:

```json
POST /storage/v1/access/grant
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

Creating **deny** grants (or granting `admin`) requires company owner, staff, or path admin.

## Connectors (Dropbox / SharePoint)

Connector buckets are reserved mounts (`kind=connector`, `connector_provider=…`). When present they appear in the bucket list as **read-only** for company members. Sync/proxy implementation will come later; writes remain denied unless a future grant model says otherwise.

## Capability share links

For people **outside** the company (or without an account), create a secret [share link](sharing.md) with an expiry and/or download cap. Those links are not listed publicly and do not require registration.
