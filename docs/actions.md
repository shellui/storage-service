# Shellui Actions (outbound webhooks)

Company owners and Django staff can configure **webhook Shellui Actions rules** that fire when storage domain events occur. Rules are managed through the **Shellui admin API** at `/api/v1/actions/*` (same JWT and `company_id` query pattern as identity-service).

Storage-service delivers webhooks directly from its own database outbox. There is no central actions service, message bus, or Celery worker.

The same outbox forwards events to email-service when `EMAIL_SERVICE_API_KEY` is set. That path is not a webhook rule. See [email.md](email.md).

For **n8n**, see [n8n.md](n8n.md).

## Event catalog (`storage.*`)

| Event type | When it fires |
| ---------- | ------------- |
| `storage.bucket.created` | The system company bucket is provisioned for a company |
| `storage.object.uploaded` | A file is uploaded or overwritten (REST or WebDAV). Folder placeholders are omitted. |
| `storage.object.deleted` | An object and its blob are removed |

Payloads include object metadata only. They never include file contents, presigned URLs, or storage backend keys.

## Signing and body

- JSON body: UTF-8, compact keys, `ensure_ascii=False` (non-ASCII paths such as `résumé.pdf` stay unescaped).
- Verifiers must HMAC the **raw request body bytes**.
- Signing secret: plain string or Standard Webhooks `whsec_<base64>` (base64 decodes to the HMAC key). New rules can omit `secret` on create to auto-generate `whsec_…`. The plaintext `secret` is returned **only** on `POST /api/v1/actions/rules` (create) and `POST /api/v1/actions/rules/<id>/rotate-secret`. Other responses expose `config.has_secret` and `config.secret_hint` (last four characters).
- Headers: `webhook-id` (stable across retries), `webhook-timestamp`, `webhook-signature` (`v1,<base64>`), `X-Shellui-Event`, `X-Shellui-Delivery-Attempt`.

Default webhook HTTP timeout: **5 seconds** (`ACTIONS_WEBHOOK_TIMEOUT_SECONDS`).

## Retries

After each commit, the service attempts delivery once off the request thread. Failed rows retry with backoff **30s × 2^(attempt−1)**, capped at **1 hour**, up to **8** attempts, then status **`dead`**.

| HTTP result | Behavior |
| ----------- | -------- |
| 2xx | Delivered |
| 404, 408, 409, 425, 429, other retryable 4xx, 5xx, timeouts, connection errors | Retry |
| 400, 401, 403, 405, 410, 413, 422 | Dead (no retry) |
| 429 / 503 with `Retry-After` | Next attempt uses `Retry-After` (capped at 1h) |

Post-commit dispatch is bounded by `ACTIONS_WEBHOOK_DISPATCH_WORKERS` (default 4). Large WebDAV syncs can emit many events; delivery is at-least-once with no ordering guarantee (see [n8n.md](n8n.md)).

Run a cron job every minute. It retries webhook deliveries and email-service forwards:

```cron
* * * * * python manage.py retry_webhooks
```

Options: `--batch-size 50`, `--max-seconds 50`, `--concurrency 4`, `--dry-run`.

Delivered and dead deliveries are deleted after `EVENT_LOG_RETENTION_DAYS` by the hourly `purge_expired_data` job (see [event-log.md](event-log.md#retention)).

## Event log

Every catalog event is also stored in the event log, with or without a matching rule. See [event-log.md](event-log.md).

## Admin REST API

| Method | Path |
| ------ | ---- |
| `GET` | `/api/v1/actions/events` |
| `GET` / `POST` | `/api/v1/actions/rules` |
| `GET` / `PATCH` / `DELETE` | `/api/v1/actions/rules/<id>` |
| `POST` | `/api/v1/actions/rules/<id>/send-test` |
| `POST` | `/api/v1/actions/rules/<id>/rotate-secret` |
| `GET` | `/api/v1/actions/deliveries` |
| `GET` | `/api/v1/actions/deliveries/<uuid>` |
| `POST` | `/api/v1/actions/deliveries/<uuid>/requeue` |

Auth: Bearer JWT from identity-service. Callers must be staff or company owner. Pass `company_id` as a query parameter (defaults to the token `company_id` for owners).

See identity-service [actions.md](https://github.com/shellui/identity-service/blob/develop/docs/actions.md) for shared envelope conventions.
