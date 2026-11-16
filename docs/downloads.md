---
description: How object GET streams bytes through Django, and when a signed URL is cryptographic.
---

# Downloads and signed URLs

Authenticated downloads always stream through Django. A signed URL is a separate, optional pointer at the blob. This page is both paths.

You need read access on the object, from bucket defaults or an [access grant](access.md). Someone without a token uses a [share link](sharing.md), which streams the same way.

## Stream a file

`GET /storage/v1/object/{bucket}/{path}` returns a `FileResponse`. The Files UI can open the file on the storage host with the `Authorization` header. The response does not redirect to S3, and it does not use `X-Accel-Redirect`.

The same bytes are available at `/storage/v1/object/authenticated/{bucket}/{path}`.

| Header | Value |
| --- | --- |
| `Content-Type` | Allowlisted type, or `text/plain` / `application/octet-stream` for every other type |
| `Content-Disposition` | `inline` for an allowlisted type. `attachment` for every other type, and when `download` is set |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `sandbox; default-src 'none'` |
| `Content-Length` | Object size |
| `ETag` | Quoted content hash when one is stored |
| `Cache-Control` | `private, no-store` |

Inline types are common raster images, PDF, `text/plain`, audio, and video. HTML, SVG, script, XML, and any other type are attachments. The stored bytes stay the same. The browser on the storage host does not run them as a page. Raster images and PDF use that same CSP. The viewer displays the response body and does not need extra sources.

`Content-Disposition` sends an ASCII `filename` and `filename*=UTF-8''…`. Quotes, backslashes, and newlines in the name stay inside that header.

`download` with an empty value, `true`, or `1` uses the object's file name. Any other `download` value is sent as the file name. The parameter does not change the content type. The response also sets `last_accessed_at` on the row.

`GET /storage/v1/object/public/…` does not serve bytes. It returns 403 `public_download_disabled`.

## Signed URLs

`POST /storage/v1/object/sign/{bucket}/{path}` returns a time-limited URL. Object `GET` does not redirect to it. You can also `POST /storage/v1/object/sign/{bucket}` with the path in the body.

The body field is `expiresIn` or `expires_in`, in seconds. The value is capped at `SIGNED_URL_EXPIRES` (default `3600`). A larger number is reduced. The minimum used is 1 second.

| Backend | URL | Use |
| --- | --- | --- |
| `STORAGE_BACKEND=s3` | Pre-signed URL with query-string authentication | Clients that should fetch from object storage |
| `filesystem` | Plain `/media/objects/…` path. Not signed | Local development. Do not publish `/media/` |

On S3, anyone who holds the URL can fetch the object until it expires. There is no download counter and no revoke short of waiting for expiry. For a link you can revoke, use [Share links](sharing.md).

Filesystem signed URLs are ordinary media paths. If that path is reachable, knowing or guessing it is enough. Production installs that need signed URLs set `STORAGE_BACKEND=s3` and leave `/media/` off the public host. See [Security hardening](security.md).
