---
description: The EventLog table for every storage event, how long rows are kept, and the admin API that lists them.
---

# Event log

storage-service records every [catalog event](actions.md#event-catalog) in one table, `EventLog`, whether or not a webhook rule exists for it. The Shellui admin panel reads the same rows for **Storage > Log events**.

The same events can also be delivered as [webhooks](actions.md). Retention for both is the `purge_expired_data` scheduled job, described in [Scheduled jobs](maintenance-jobs.md).

## Row format

| Column | Content |
| --- | --- |
| `id` | Sequential id |
| `company_id` | Identity company id the event belongs to. Empty for staff-only platform events |
| `user_id` | Identity user id who uploaded, deleted, or provisioned the bucket, when known |
| `event_type` | Catalog event type |
| `data` | Event payload, compacted as described below |
| `created_at` | When the event happened |

`data` is the webhook payload with empty values removed (`null`, empty strings, empty lists, and `false`). `company_id` and `user_id` are removed from `data` because they are columns. `actor_email` is added when the request token carried an email.

storage-service has no user or company tables. Ids and emails come from the identity-service JWT. Upload and delete events name the caller on that request. Django admin deletes go through the same delete function, so they are logged too. Folder placeholders are not logged.

Two indexes serve listing, the retention check, and the purge: `(company_id, created_at)` and `(company_id, user_id, created_at)`.

## Retention

Retention is one setting for the whole service: `EVENT_LOG_RETENTION_DAYS` (default 7). Values below 1 are treated as 1.

The container runs `purge_expired_data` every hour, at minute 17, for at most 5 minutes. It deletes events older than the retention, together with delivered and dead webhook deliveries and scheduled job runs older than 7 days, in short batches:

```bash
python manage.py purge_expired_data
python manage.py purge_expired_data --dry-run
python manage.py purge_expired_data --max-seconds 300
```

`--dry-run` counts rows and deletes nothing. `--max-seconds 300` stops after 300s. The next run continues.

If the oldest event is older than the retention plus one day, the job is not keeping up. `GET /api/v1/actions/event-log/retention` then reports `stale_events: true`. The Shellui admin panel shows that flag.

## Admin API

Callers must be staff or a company owner, with a Bearer JWT from identity-service. Staff may pass any `company_id` query parameter. Company owners may omit it. The token company is used. Another company returns 403.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/actions/event-log` | Newest first, paginated |
| `GET` | `/api/v1/actions/event-log/{id}` | One event |
| `GET` | `/api/v1/actions/event-log/types` | Event types with `label` and `description` |
| `GET` | `/api/v1/actions/event-log/retention` | `data_retention_days`, `oldest_event_at`, `stale_events` |

Filters on `GET /api/v1/actions/event-log`:

| Parameter | Meaning |
| --- | --- |
| `event_type` | One registered type, or several separated by commas |
| `user_id` | Identity user id |
| `user` | Case-insensitive part of the actor email |
| `created_after` | ISO 8601 datetime, inclusive |
| `created_before` | ISO 8601 datetime, exclusive |
| `page`, `page_size` | Pagination. `page_size` up to 100, default 20 |
| `scope` | `company` (default) or `platform` |

An unknown `event_type` is 400. Rows have this shape:

```json
{
  "id": 311,
  "company_id": 1,
  "created_at": "2026-10-02T09:14:03.120Z",
  "event_type": "storage.object.uploaded",
  "label": "Object uploaded",
  "user_id": 42,
  "user_email": "ada@example.com",
  "data": {
    "bucket_name": "company",
    "path": "reports/q3.pdf",
    "size": 48213,
    "mime_type": "application/pdf",
    "created": true,
    "actor_email": "ada@example.com"
  }
}
```

## Platform events (staff only)

`storage.scheduled_job.succeeded` and `storage.scheduled_job.failed` are written with `company_id` null. They are not webhook rules and they do not appear in `GET /api/v1/actions/event-log/types`.

Staff list them with `GET /api/v1/actions/event-log?scope=platform`. Company owners receive 403 for that scope. The default `scope=company` stays limited to the token company.

## Related

- [Webhooks](actions.md)
- [Scheduled jobs](maintenance-jobs.md)
