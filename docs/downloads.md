# Downloads

Django always authorizes the request. Bytes can be served three ways.

Anonymous downloads use [share links](sharing.md) (`GET /storage/v1/share/link/{token}`), not public buckets. Authenticated downloads and short-lived signed URLs are unchanged below.

## Modes (`DOWNLOAD_MODE`)

| Value | Behavior |
|-------|----------|
| `auto` | filesystem or S3 **with nginx** → `xaccel`; without nginx (`runserver`) → `stream` so the Files UI can open files same-origin |
| `redirect` | HTTP 302 to a signed / CDN URL (needs S3 CORS; the browser must be allowed to fetch the bucket) |
| `xaccel` | Empty body + `X-Accel-Redirect` for nginx (disk or S3) |
| `stream` | `FileResponse` through Django |

**Recommendation:** keep `auto`. The Docker image includes nginx, so downloads stay same-origin. `manage.py runserver` streams through Django. Use `DOWNLOAD_MODE=redirect` only when you have configured S3 CORS and want the client to fetch the bucket directly.

## Docker image (nginx + Gunicorn)

The image runs nginx on port **8000** and Gunicorn on `127.0.0.1:8001`. Django authorizes; nginx serves the bytes:

| Backend | `X-Accel-Redirect` | nginx |
|---------|--------------------|-------|
| filesystem | `/protected/<storage_key>` | `alias $MEDIA_ROOT/objects/` |
| S3 | `/protected-s3/<storage_key>?<signed query>` | `proxy_pass` to `$AWS_S3_ENDPOINT_URL` / AWS (same `AWS_*` as Django) |

| Env | Docker default |
|-----|----------------|
| `DOWNLOAD_MODE` | `auto` |
| `X_ACCEL_REDIRECT_ENABLED` | `true` |
| `X_ACCEL_REDIRECT_PREFIX` | `/protected/` |
| `MEDIA_ROOT` | `/app/data/media` |
| `STORAGE_BACKEND` | `filesystem` or `s3` |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Django signs S3 GETs |
| `AWS_STORAGE_BUCKET_NAME` | Django + nginx |
| `AWS_S3_ENDPOINT_URL` | MinIO/R2 origin (e.g. `http://minio:9000`); omit for AWS |
| `AWS_S3_ADDRESSING_STYLE` | `path` if endpoint is set, else `virtual` |
| `NGINX_RESOLVER` | `127.0.0.11 8.8.8.8` (Docker DNS) |

Do **not** set `X_ACCEL_REDIRECT_ENABLED=true` with `manage.py runserver` — there is no nginx, so the client receives an empty body.

## NGINX (if you run your own proxy)

The image already has this location. If you put **another** nginx in front, either leave X-Accel-Redirect to the in-container nginx, or replicate:

```nginx
# Public app
location / {
    proxy_pass http://127.0.0.1:8001;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Authorization $http_authorization;
}

# Internal only — Django sets X-Accel-Redirect: /protected/<storage_key>
location /protected/ {
    internal;
    alias /app/data/media/objects/;
}
```

## S3

Same env vars as Django. Nginx in the image proxies to the bucket (so browsers do not need to reach MinIO).

```bash
STORAGE_BACKEND=s3
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_STORAGE_BUCKET_NAME=shellui
AWS_S3_ENDPOINT_URL=http://minio:9000   # omit for AWS
AWS_S3_ADDRESSING_STYLE=path            # path for MinIO; virtual for AWS
DOWNLOAD_MODE=auto                      # xaccel via nginx when it is in the image
SIGNED_URL_EXPIRES=3600
```

`DOWNLOAD_MODE=redirect` sends the client a 302 to a signed URL instead (use when the browser can reach S3). Signed URL API: `POST /storage/v1/object/sign/{bucket}/{path}`.
