# Downloads

Authenticated `GET /storage/v1/object/{bucket}/{path}` always **streams bytes through Django** (`FileResponse`). The Files UI can open files same-origin with `Authorization` — no S3 CORS and no nginx `X-Accel-Redirect`.

Anonymous downloads use [share links](sharing.md) (`GET /storage/v1/share/link/{token}`), which stream the same way.

## Headers

| Header | Value |
|--------|--------|
| `Content-Type` | Object MIME type |
| `Content-Disposition` | `inline` (or `attachment` when downloading as a file) |
| `Content-Length` | Object size |
| `ETag` | Content hash when stored |
| `Cache-Control` | `private, no-store` |

## Signed URLs

`POST /storage/v1/object/sign/{bucket}/{path}` still returns a time-limited URL (S3 query-string auth, or the media URL on filesystem). That is optional for clients that fetch the bucket directly. Object `GET` does not redirect to it.

```bash
STORAGE_BACKEND=s3
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_STORAGE_BUCKET_NAME=shellui
AWS_S3_ENDPOINT_URL=http://minio:9000   # omit for AWS
AWS_S3_ADDRESSING_STYLE=path            # path for MinIO; virtual for AWS
SIGNED_URL_EXPIRES=3600
```
