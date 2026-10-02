# Event log

storage-service records every [catalog event](actions.md#event-catalog-storage) in one table, `EventLog`, whether or not a webhook rule exists for it. The Shellui admin panel shows it under **Storage > Log events**.

---

## Row format

| Column | Content |
| ------ | ------- |
| `id` | Sequential id |
| `company_id` | Identity company id the event belongs to |
| `user_id` | Identity user id who triggered the event, when known |
| `event_type` | Catalog event type |
| `data` | Event payload, compacted (see below) |
| `created_at` | When the event happened |

To keep rows small, `data` is the webhook payload with:

- empty values (`null`, empty strings and lists, `false`) removed
- `company_id` and `user_id` removed, since they are columns
- `actor_email` added when the request token carried an email

storage-service has no user or company tables: ids come from the identity-service JWT.

The table has two indexes, `(company_id, created_at)` and `(company_id, user_id, created_at)`. They serve every listing, the retention check, and the purge.

## Retention

Retention is one setting for the whole service: `EVENT_LOG_RETENTION_DAYS` (default **7**).

Schedule `purge_expired_data` every hour. It deletes events older than the retention, together with delivered and dead webhook deliveries, in short batches:

```bash
python manage.py purge_expired_data
python manage.py purge_expired_data --dry-run           # count only
python manage.py purge_expired_data --max-seconds 300   # stop after 5 minutes, the next run continues
```

```cron
17 * * * * python manage.py purge_expired_data --max-seconds 300
```

If events older than retention + 1 day are still stored, the job is not running. The admin panel dashboard and the **Storage > Log events** page then show an error asking to configure it.

## Admin REST API

Bearer JWT from identity-service. Callers must be Django staff or a company owner. `company_id` defaults to the token company.

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET` | `/api/v1/actions/event-log` | Event log, newest first, paginated |
| `GET` | `/api/v1/actions/event-log/<id>` | One event |
| `GET` | `/api/v1/actions/event-log/types` | Event types with `label` and `description` |
| `GET` | `/api/v1/actions/event-log/retention` | `data_retention_days`, `oldest_event_at`, `stale_events` |

`GET /api/v1/actions/event-log` filters:

| Parameter | Meaning |
| --------- | ------- |
| `event_type` | One type, or several separated by commas |
| `user_id` | Identity user id |
| `user` | Case-insensitive part of the actor email |
| `created_after` | ISO 8601 datetime, inclusive |
| `created_before` | ISO 8601 datetime, exclusive |
| `page`, `page_size` | Pagination, `page_size` up to 100 (default 20) |

Rows have the same shape as identity-service `GET /api/v1/events`:

```json
{
  "id": 311,
  "company_id": 1,
  "created_at": "2026-10-02T09:14:03.120Z",
  "event_type": "storage.object.uploaded",
  "label": "Object uploaded",
  "user_id": 42,
  "user_email": "ada@acme.com",
  "data": {
    "object_id": "550e8400-e29b-41d4-a716-446655440000",
    "bucket_name": "company",
    "bucket_kind": "company",
    "path": "reports/q3.pdf",
    "size": 48213,
    "mime_type": "application/pdf",
    "version": 1,
    "created": true,
    "actor_email": "ada@acme.com"
  }
}
```

## Related docs

- [Shellui Actions](actions.md)
