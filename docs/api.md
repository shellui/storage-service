---
description: Where the OpenAPI docs are served, and the route groups under /storage/v1/ and /api/v1/actions/.
---

# API reference

Each running storage-service serves its own HTTP reference. This page lists where that reference lives and groups the routes. Request and response fields are on the live schema, which matches the code you deployed.

## Interactive docs

| Page | Path |
| --- | --- |
| Swagger UI | `/api/docs/` |
| ReDoc | `/api/docs/redoc/` |
| OpenAPI schema | `/api/schema/` |

Open Swagger inside the Shellui shell and the shell access token is applied for you. Otherwise choose **Authorize** and paste `Bearer your_access_token_here`, or the raw JWT.

`GET /storage/v1/health` does not require a token. It returns `status` and `version`. A valid Bearer token also returns `storage_backend`, `identity_jwks_source`, and `identity_jwks_url`. Every other `/storage/v1/` route expects `Authorization: Bearer your_access_token_here` from identity-service, except a share-link download and the disabled public object route.

## Route groups

Paths below are on the storage host, for example `http://localhost:8001`.

| Group | Paths |
| --- | --- |
| Health | `GET /storage/v1/health` |
| Buckets | `GET /storage/v1/bucket`, `GET /storage/v1/bucket/{name}`. Create, update, and delete return 403 |
| Access grants | `GET` and `POST /storage/v1/access/grant`, `DELETE /storage/v1/access/grant/{id}` |
| Share links | `POST` and `GET /storage/v1/share/{bucket}/{path}`, `GET` and `DELETE /storage/v1/share/link/{token}` |
| Upload and download | `POST`, `PUT`, `GET`, and `DELETE /storage/v1/object/{bucket}/{path}` |
| By id | `GET /storage/v1/object/id/{uuid}` |
| List | `POST /storage/v1/object/list/{bucket}` |
| Folder prefix | `GET`, `POST`, and `DELETE /storage/v1/object/prefix/{bucket}` |
| Delete many | `DELETE /storage/v1/object/{bucket}` |
| Move and copy | `POST /storage/v1/object/move`, `POST /storage/v1/object/copy` |
| Sign URL | `POST /storage/v1/object/sign/{bucket}/{path}` |
| Quota | `GET /storage/v1/quota`, `PUT /storage/v1/quota/company/{company_id}`, `PUT …/user/{user_id}` |
| Stats | `GET /storage/v1/stats` |
| Metrics | `GET /storage/v1/metrics`, `GET /storage/v1/metrics/all` |
| Shellui Actions | `/api/v1/actions/events`, `/rules`, `/deliveries` |
| Event log | `GET /api/v1/actions/event-log` (`scope=platform` is staff only) |
| Scheduled jobs | `GET /api/v1/scheduled-jobs` (staff only) |
| WebDAV | `/dav/{bucket}/…` when `WEBDAV_ENABLED` is true |

`{name}` and `{bucket}` are bucket slugs. The company bucket slug is `company`. `{path}` is the object path inside the bucket.

## Who can call them

Company members with `company_id` in the token use that company's bucket. Grants decide which paths they can read or change. See [Access grants](access.md) and [Buckets, folders, and files](buckets-and-objects.md).

| Route | Who |
| --- | --- |
| `GET /storage/v1/stats` | The caller's company. Staff receive every company |
| `GET /storage/v1/quota` | The caller's company |
| `PUT /storage/v1/quota/…` | Staff, or a company owner for their own company id |
| `GET /storage/v1/metrics` | Staff or a company owner. Company id comes from the token. A `company_id` query parameter is 400. Scheduled-job metrics are omitted |
| `GET /storage/v1/metrics/all` | Staff, or a personal access token with the `pat_agm` claim. Includes `shellui_storage_scheduled_job_*` |
| `GET /api/v1/scheduled-jobs` | Staff only. Company owners receive 403 |
| `/api/v1/actions/*` | Staff, or a company owner scoped to the token `company_id` |

## Metrics

Metrics responses are Prometheus text, not JSON. Gauges are labeled with `company_id` and named:

- `shellui_storage_objects_total`
- `shellui_storage_bytes_total`
- `shellui_storage_buckets_total`
- `shellui_storage_documents_total`
- `shellui_storage_document_bytes`
- `shellui_storage_uploads_24h`, `shellui_storage_uploads_7d`, `shellui_storage_uploads_30d`
- `shellui_storage_bytes_7d`
- `shellui_storage_quota_used_bytes`, `shellui_storage_quota_max_bytes`

Document counts use the same MIME families as the Django admin statistics page.

`GET /storage/v1/metrics/all` also appends the scheduler gauges (`shellui_storage_scheduled_job_*` and `shellui_storage_scheduler_*`). `GET /storage/v1/metrics` does not. Names and alert examples are in [Scheduled jobs](maintenance-jobs.md).

Error JSON on `/storage/v1/` uses `statusCode`, `error`, and `message`. Responses include `X-Request-ID`.
