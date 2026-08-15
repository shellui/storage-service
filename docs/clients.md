# Third-party clients (WebDAV & S3)

You can browse and sync files with any compatible **WebDAV** or **S3** client. ShellUI does not endorse a particular app — use whatever your team already prefers.

## WebDAV (recommended for ShellUI)

Goes through `storage-service` — **quotas, MIME rules, and upload signals apply**.

Typical settings:

| Field | Value |
|-------|-------|
| Protocol | WebDAV (HTTPS), or HTTP for local development |
| Server | your storage host (e.g. `localhost` or `storage.example.com`) |
| Port | `8001` locally, or your TLS port in production |
| Path | `/dav` |
| Username | any string (often the user email) |
| Password | identity-service **access JWT** |

Layout: `/dav/{bucket}/folder/file.ext` — typically `/dav/company/…` (one company bucket; access grants apply).

The company bucket is auto-provisioned. `MKCOL` creates virtual folders (prefix-based, with the same `.emptyFolderPlaceholder` marker as REST) that are **private to the creator** by default (nested folders inherit parent grants). PROPFIND/GET/PUT honor the same path grants as the REST API — private folders return `403` for other users, and company-open files appear in listings.

Examples (non-exhaustive, not recommendations): the WebDAV support built into some desktop OSes, command-line sync tools, and file managers that offer a WebDAV or S3 plugin.

## Native S3 (when `STORAGE_BACKEND=s3`)

Point an S3-compatible client at your bucket (AWS, MinIO, R2, …):

| Field | Value |
|-------|-------|
| Protocol | Amazon S3 / S3-compatible |
| Endpoint | your `AWS_S3_ENDPOINT_URL` (or the AWS regional endpoint) |
| Access Key ID | `AWS_ACCESS_KEY_ID` |
| Secret Access Key | `AWS_SECRET_ACCESS_KEY` |

**Trade-off:** direct S3 bypasses ShellUI quotas and Django signals. Prefer WebDAV when those matter; use S3 for bulk or operational access to the raw store.

Auth for WebDAV is the same JWT-as-password (or `Authorization: Bearer`) pattern described in [authentication.md](authentication.md).
