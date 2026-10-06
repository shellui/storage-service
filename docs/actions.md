---
description: Shellui Actions webhook rules for storage events, the admin API, signing, and retries.
---

# Storage webhooks

Company owners and staff can POST a signed JSON body to an HTTPS endpoint when a storage event happens. Each Shellui Actions rule maps one catalog event, such as `storage.object.uploaded`, to one webhook URL.

storage-service delivers those webhooks itself. There is no central actions service and no message bus.

## How a delivery runs

Domain code calls `emit_event` inside the database transaction that changed the object:

1. The event is written to the [event log](event-log.md), whether or not a rule matches.
2. Each enabled webhook rule for that company and event type gets an outbox row in the same transaction.
3. After commit, a background thread POSTs the envelope. The API response does not wait for your server.
4. Each try is stored as a delivery attempt. Further tries come from `manage.py retry_webhooks`.

Delivery does not need Celery or Redis. The default HTTP timeout is 5s (`ACTIONS_WEBHOOK_TIMEOUT_SECONDS`). Delivery is at-least-once. Retries reuse the envelope `id`, which is also the `webhook-id` header. Dedupe on that value.

Post-commit dispatch uses `ACTIONS_WEBHOOK_DISPATCH_WORKERS` threads (default 4). A WebDAV sync can emit many `storage.object.uploaded` events close together. Order is not guaranteed.

The n8n setup, including a signature check, is in [n8n](n8n.md). Scheduling the retry command is in [Maintenance jobs](maintenance-jobs.md).

## Event catalog

Payloads carry object metadata. They do not include file bytes, pre-signed URLs, or storage backend keys. Folder placeholder objects (`.emptyFolderPlaceholder`) do not emit upload or delete events.

| Event type | When it fires |
| --- | --- |
| `storage.bucket.created` | The company bucket is created on first use. The actor is the caller who triggered that request |
| `storage.object.uploaded` | A file is uploaded or overwritten (REST, WebDAV, or an internal write). `created` is false on overwrite |
| `storage.object.deleted` | An object row and its blob are removed, including a delete from Django admin |

The body is UTF-8 JSON with sorted keys and non-ASCII characters left as characters (`ensure_ascii=false`). Verify the signature over the raw body bytes, not over a re-serialized object.

Extra headers: `X-Shellui-Event`, `X-Shellui-Delivery-Attempt`. Signing secrets are plain text or Standard Webhooks `whsec_` plus base64. Shellui decodes the `whsec_` suffix and uses those bytes as the HMAC key.

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "storage.object.uploaded",
  "time": "2026-10-06T08:00:00+00:00",
  "company": {"id": 10, "slug": "", "name": ""},
  "data": {
    "object_id": "660e8400-e29b-41d4-a716-446655440001",
    "bucket_name": "company",
    "bucket_kind": "company",
    "path": "docs/report.pdf",
    "size": 4096,
    "mime_type": "application/pdf",
    "version": 1,
    "created": true
  }
}
```

`company.slug` and `company.name` are empty. storage-service has no company table, so the envelope carries the numeric id only. When the request had an authenticated user, the envelope also includes `actor` with `user_id` and, when present, `email` and `username`.

The `id` above is a sample. A real delivery uses a new id, and the same id again on every retry of that delivery.

## Admin API

Paths match identity-service. Authorize with a Bearer JWT. Staff may pass any `company_id` query parameter. Company owners may omit it, and the token `company_id` is used. Another company returns 403. Anyone else receives 403.

- `GET /api/v1/actions/events`: catalog, including a `sample_envelope` for each type
- `GET` and `POST /api/v1/actions/rules`: list or create webhook rules. Create returns `secret` once when one was generated
- `GET`, `PATCH`, and `DELETE /api/v1/actions/rules/{id}`
- `POST /api/v1/actions/rules/{id}/rotate-secret`: new signing secret, returned once
- `POST /api/v1/actions/rules/{id}/send-test`
- `GET /api/v1/actions/deliveries`: paginated delivery log
- `GET /api/v1/actions/deliveries/{uuid}`: one delivery and its attempts
- `POST /api/v1/actions/deliveries/{uuid}/requeue`

Later reads of a rule expose `has_secret` and `secret_hint` (the last four characters), not the secret. Omit `secret` on create and storage-service generates a `whsec_` value.

## Retries

Backoff is `30s * 2^(n-1)`, capped at 1 hour, with at most 8 attempts (`ACTIONS_OUTBOX_MAX_ATTEMPTS`).

| Result | Retry? |
| --- | --- |
| 2xx | No. The delivery is delivered |
| 404, 408, 409, 425, 429 | Yes. 404 covers an inactive n8n workflow |
| 400, 401, 403, 405, 410, 413, 422 | No. The delivery is dead |
| Other 4xx | Yes |
| 5xx, timeouts, connection errors | Yes |
| 429 or 503 with `Retry-After` | Yes. The delay is the larger of the backoff and `Retry-After`, still capped at 1 hour |

```bash
python manage.py retry_webhooks --batch-size 50 --max-seconds 50 --concurrency 4
```

Example cron, every minute:

```cron
* * * * * cd /app && python manage.py retry_webhooks
```

Run that command from cron, a sidecar, or your platform scheduler. The storage-service container does not run it for you. Delivered and dead deliveries are deleted after `EVENT_LOG_RETENTION_DAYS` by `purge_expired_data`. See [Maintenance jobs](maintenance-jobs.md).

Webhook URLs that resolve to a private or loopback address are blocked unless the rule has **allow private URLs** (staff) or `ACTIONS_WEBHOOK_ALLOW_PRIVATE` is true. When that variable is unset, it stays false, including while `DEBUG=true`. Changing a rule URL clears **allow private URLs** unless a superuser sets it again.
