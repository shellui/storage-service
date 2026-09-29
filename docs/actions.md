# Shellui Actions (outbound webhooks)

Company owners and Django staff can configure **webhook Shellui Actions rules** that fire when storage domain events occur. Rules are managed through the **Shellui admin API** at `/api/v1/actions/*` (same JWT and `company_id` query pattern as identity-service).

Storage-service delivers webhooks directly from its own database outbox. There is no central actions service, message bus, or Celery worker.

## Event catalog (`storage.*`)

| Event type | When it fires |
| ---------- | ------------- |
| `storage.bucket.created` | The system company bucket is provisioned for a company |
| `storage.object.uploaded` | A file is uploaded or overwritten (REST or WebDAV). Folder placeholders are omitted. |
| `storage.object.deleted` | An object and its blob are removed |

Payloads include object metadata only. They never include file contents, presigned URLs, or storage backend keys.

## Retries

After each commit, the service attempts delivery once off the request thread (short HTTP timeout). Failed rows retry with backoff **30s × 2^(attempt−1)**, capped at **1 hour**, up to **8** attempts, then status **`dead`**.

Run a cron job every minute:

```cron
* * * * * python manage.py retry_webhooks
```

Options: `--batch-size 50`, `--max-seconds 50`, `--concurrency 4`, `--dry-run`.

## Admin REST API

| Method | Path |
| ------ | ---- |
| `GET` | `/api/v1/actions/events` |
| `GET` / `POST` | `/api/v1/actions/rules` |
| `GET` / `PATCH` / `DELETE` | `/api/v1/actions/rules/<id>` |
| `POST` | `/api/v1/actions/rules/<id>/send-test` |
| `GET` | `/api/v1/actions/deliveries` |
| `GET` | `/api/v1/actions/deliveries/<uuid>` |
| `POST` | `/api/v1/actions/deliveries/<uuid>/requeue` |

Auth: Bearer JWT from identity-service. Callers must be staff or company owner. Pass `company_id` as a query parameter (defaults to the token `company_id` for owners).

See identity-service [actions.md](https://github.com/shellui/identity-service/blob/develop/docs/actions.md) for envelope shape and signature headers (`webhook-id`, `webhook-timestamp`, `webhook-signature`).
