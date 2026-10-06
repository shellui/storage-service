---
title: storage-service
sidebar_label: Overview
description: storage-service stores files for a Shellui company and serves them through /storage/v1/. This page is the map of the handbook.
---

# storage-service

storage-service stores files for a Shellui company and serves them through `/storage/v1/`. You upload an object, then download it with a JWT or a share link.

## What storage-service is

storage-service is the Shellui file API. It keeps one bucket per company, stores the bytes in S3 or on the local filesystem, and records who may read or change each path. The same process serves the API, Django admin, WebDAV, and OpenAPI.

It is a Django app, published as the `shellui/storage-service` Docker image. It checks JSON Web Tokens (JWTs) issued by identity-service. It does not sign people in itself.

Routes follow the Supabase Storage path shape (`/storage/v1/object/…`, `/storage/v1/bucket`). The optional `apikey` header is accepted and ignored. The Bearer JWT is what authorizes the call.

## Who it is for

Use it when a Shellui app needs company files: the Files UI, a script, or a WebDAV client. Company owners set quotas and Shellui Actions webhook rules. Operators run the process, the database, the blob store, and two cron jobs.

Your product stays in the shell. storage-service does not replace identity-service, hosting-service, or email-service.

## What it stores and serves

Each company has one system bucket named `company`. The first request that needs it creates that bucket. You do not create extra buckets through the API.

A file is a `StorageObject`: a path such as `docs/report.pdf`, a size, a MIME type, an owner, and a blob key in the backend. Folders are prefixes. An empty folder is a marker object named `.emptyFolderPlaceholder`.

The default blob backend is the local filesystem. Set `STORAGE_BACKEND=s3` to use an S3-compatible bucket (AWS, MinIO, Cloudflare R2, OVH, and others). Downloads of objects you are allowed to read stream through Django. Anonymous public buckets are off.

## How it fits with identity, hosting, and email

identity-service signs people in and issues the Bearer JWT you send on API calls. storage-service has no user table. `company_id`, `user_id`, and staff flags come from that token. See [JWT and claim trust](authentication.md).

hosting-service stores deployment archives in its own filesystem or bucket. storage-service does not receive those archives and does not call hosting-service.

storage-service does not send email. A share link is a URL you send yourself. Company owners attach HTTPS endpoints with Shellui Actions webhooks, and every storage event is stored in the event log. Mail stays with email-service and identity-service.

## Upload and download flow

A signed-in caller with `company_id` in the token uses the company bucket:

1. The first request provisions the `company` bucket and emits `storage.bucket.created`.
2. `POST` or `PUT /storage/v1/object/company/{path}` writes the bytes. A new file is private to the creator until you share it.
3. `GET` on that path streams the bytes when the caller may read it. `Cache-Control` is `private, no-store`.
4. A share link (`/storage/v1/share/link/{token}`) lets someone without a token download that one file until the link expires, hits its download cap, or you revoke it.

WebDAV at `/dav/company/…` uses the same quotas, grants, and upload signals. A direct S3 client pointed at the raw bucket does not.

## Access and tenancy

Every object row stores `company_id` from the JWT. You only see that company's bucket. There is no hosting-style waitlist: a token with `company_id` can use storage, inside the quota.

New files and folders are private to the creator. [Access grants](access.md) then allow or deny a user, or the whole company, on a folder or a file. Nested paths inherit the parent folder's grants.

Staff and company owners change quotas and read Shellui Actions routes. Other members use the files their grants allow.

## Webhooks and the event log

Provisioning the company bucket, uploading or overwriting a file, and deleting a file each write an event. Folder placeholder objects are omitted. Matching Shellui Actions webhook rules receive a signed POST. Delivery is at-least-once. `manage.py retry_webhooks` retries failures. There is no separate actions service.

The event log keeps those events for `EVENT_LOG_RETENTION_DAYS` (default 7). storage-service does not email anyone when they happen.

## Configure and run

Copy [`.env.example`](../.env.example) to `.env`, set `SECRET_KEY`, point `IDENTITY_SERVICE_URL` at identity-service, and run migrations. Docker Compose is the local path in [Run storage-service](getting-started.md).

The container runs database migrations, then Gunicorn. It does not run Celery, and it does not schedule jobs. You run `retry_webhooks` every minute and `purge_expired_data` every hour. Redis is optional. Set `REDIS_URL` when more than one Gunicorn worker should share the cache.

## Where to go next

Pick the row that matches what you are doing:

| You want to | Start with |
| --- | --- |
| Run it locally | [Run storage-service](getting-started.md) |
| Set environment variables | [Configuration](configuration.md) |
| See how files and folders are stored | [Buckets, folders, and files](buckets-and-objects.md) |
| Share a folder inside the company | [Access grants](access.md) |
| Send one file to someone without an account | [Share links](sharing.md) |
| Set a company or per-user cap | [Quotas](quotas.md) |
| Stream a download or sign an S3 URL | [Downloads and signed URLs](downloads.md) |
| Mount the bucket in a file client | [WebDAV](clients.md) |
| See which JWT claims are trusted | [JWT and claim trust](authentication.md) |
| Call an HTTPS endpoint on upload | [Webhooks](actions.md) and [n8n](n8n.md) |
| Read past storage events | [Event log](event-log.md) |
| Lock down a production install | [Security hardening](security.md) |
| Schedule retries and retention | [Maintenance jobs](maintenance-jobs.md) |
| Browse the HTTP API | [API reference](api.md) |

Source and the changelog are on [GitHub](https://github.com/shellui/storage-service). These pages are built from `docs/` by [shellui/shellui](https://github.com/shellui/shellui) and published on [docs.shellui.com](https://docs.shellui.com) at `docs.shellui.com/storage`.
