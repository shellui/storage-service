---
description: Mount the company bucket with a WebDAV client, and what a raw S3 client skips.
---

# WebDAV

WebDAV exposes the company bucket to a file client. Requests go through storage-service, so quotas, MIME rules, access grants, and upload signals apply.

The routes exist when `WEBDAV_ENABLED` is true (the default). The prefix is `WEBDAV_PATH_PREFIX` (default `/dav`).

## Client settings

| Field | Value |
| --- | --- |
| Protocol | WebDAV over HTTPS, or HTTP for local development |
| Server | The storage host, for example `localhost` or `storage.example.com` |
| Port | `8001` locally, or the TLS port in production |
| Path | `/dav` |
| Username | Any string. An email address is a common choice |
| Password | The identity-service access JWT |

You can also send `Authorization: Bearer your_access_token_here` instead of Basic auth. The username is not checked. The password, or the bearer token, is.

Paths look like `/dav/company/folder/file.ext`. The company bucket is created on first use. `MKCOL` creates a folder with the same `.emptyFolderPlaceholder` marker as the REST API, private to the creator unless a parent folder already has grants. `PROPFIND`, `GET`, and `PUT` use the same path checks as `/storage/v1/`. Another user's private folder is 403.

A desktop file manager, an OS WebDAV mount, or a sync tool can use these settings. Shellui does not require a specific client.

## Direct S3

When `STORAGE_BACKEND=s3`, an S3 client can use `AWS_S3_ENDPOINT_URL`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` on `AWS_STORAGE_BUCKET_NAME`.

That client talks to object storage, not to storage-service. Quotas, grants, share links, and `storage.object.uploaded` do not run. Use it for operator access to the raw bucket. Use WebDAV or `/storage/v1/` when those checks should apply.

JWT checks for both WebDAV and the REST API are in [JWT and claim trust](authentication.md).
