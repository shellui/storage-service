# Downloads

Django always authorizes the request. Bytes can be served three ways.

Anonymous downloads use [share links](sharing.md) (`GET /storage/v1/share/link/{token}`), not public buckets. Authenticated downloads and short-lived signed URLs are unchanged below.

## Modes (`DOWNLOAD_MODE`)

| Value | Behavior |
|-------|----------|
| `auto` | S3 → `redirect`; filesystem + `X_ACCEL_REDIRECT_ENABLED` → `xaccel`; else `stream` |
| `redirect` | HTTP 302 to a signed / CDN URL (ideal for S3/MinIO; **works without nginx**) |
| `xaccel` | Empty body + `X-Accel-Redirect` for nginx |
| `stream` | `FileResponse` through Gunicorn |

**Recommendation:** keep `auto`. Prefer **signed redirects** for S3 so app workers never touch file bytes. Use **X-Accel-Redirect** when blobs live on local disk behind nginx. Fall back to **stream** for local development without a reverse proxy.

## NGINX example (filesystem + xaccel)

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

Env:

```bash
DOWNLOAD_MODE=xaccel
X_ACCEL_REDIRECT_ENABLED=true
X_ACCEL_REDIRECT_PREFIX=/protected/
```

## S3 without nginx

```bash
STORAGE_BACKEND=s3
DOWNLOAD_MODE=redirect   # or auto
SIGNED_URL_EXPIRES=3600
```

`GET /storage/v1/object/...` returns `302` to a time-limited URL. Signed URL API: `POST /storage/v1/object/sign/{bucket}/{path}`.
