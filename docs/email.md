# Email notifications

storage-service can forward each `storage.*` event to email-service. A company email rule there decides whether to send mail. Forwarding runs only when `EMAIL_SERVICE_API_KEY` is set. With no key, storage-service does not call email-service, and uploads, deletes, and Shellui Actions webhooks behave as they do today.

## What gets forwarded

Every catalog event that storage-service already emits for webhooks is posted to `POST /api/v1/events`:

- `storage.bucket.created`
- `storage.object.uploaded`
- `storage.object.deleted`

Folder placeholders stay omitted, the same as webhooks. email-service applies the company rule. Storage events default to off in the email catalog, so a company gets mail only after it enables the rule. A disabled rule returns `skipped_reason: rule_disabled`. storage-service treats that response as delivered and does not post the event again.

Webhook rules stay on Shellui Actions, and n8n workflows keep using those signed POSTs. See [actions.md](actions.md) and [n8n.md](n8n.md).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` | Origin only. storage-service appends `/api/v1/events`. |
| `EMAIL_SERVICE_API_KEY` | empty | Service key from email-service. Prefix `esk_`. Sent as `Authorization: Bearer`. |

Leave `EMAIL_SERVICE_API_KEY` empty to keep forwarding off. Issue the key for service name `storage`, lane `transactional`, and template prefix `storage.`. The key is not written to logs.

`EMAIL_SERVICE_URL` is the origin, with no path. `https://email.shellui.com/api/v1` is not a valid value.

## Request body

storage-service posts the event it already recorded, plus recipient hints from the actor on the request:

```json
{
  "service": "storage",
  "event_type": "storage.object.uploaded",
  "company_id": 42,
  "idempotency_key": "550e8400-e29b-41d4-a716-446655440000",
  "payload": {
    "company_name": "Acme",
    "bucket_name": "company",
    "path": "docs/report.pdf",
    "mime_type": "application/pdf"
  },
  "recipients": [
    {"email": "ada@acme.com", "user_id": 7}
  ]
}
```

`payload` is the webhook object metadata. `company_name` is added when the emitter passes a company name. storage-service has no company table, so the field is absent unless that name was supplied. The suggested templates substitute "your company" when it is missing.

`recipients` holds the actor when the token includes an email address. That is the hint email-service uses when the rule's `recipient_mode` is `hints`. A company that wants a fixed list sets `static` recipients on the rule. email-service then ignores this hint.

`idempotency_key` is the outbox row id. Retries send the same key and the same body. `language` is omitted, so email-service uses the rule language, then `en`.

## Retries

The HTTP call runs after the database commit, off the request thread. Failures stay on the Shellui Actions outbox. The cron you already run for webhooks retries them:

```cron
* * * * * python manage.py retry_webhooks
```

| Result | What storage-service does |
| --- | --- |
| 2xx | Delivered. A disabled rule counts as delivered. |
| 409 `lane_paused`, 408, 425, 429, 5xx, connection errors | Retry with the same idempotency key. 429 and 503 honor `Retry-After`, capped at 1 hour. |
| 400, 401, 403, 404, 422, other 4xx, other 409 | Dead. The body is not posted again. |

HTTP 404 is dead for an email forward (`unknown_event` and `not_found` are not transient). Shellui Actions webhooks still retry 404 when an n8n workflow is inactive. Backoff matches webhooks: **30s × 2^(attempt−1)**, capped at **1 hour**, up to **8** attempts. The timeout is `ACTIONS_WEBHOOK_TIMEOUT_SECONDS` (default 5 seconds).

`purge_expired_data` deletes finished email rows with finished webhook deliveries after `EVENT_LOG_RETENTION_DAYS`. See [event-log.md](event-log.md).

## Try it locally

1. Run email-service and create a service key for `storage` (`allowed_lanes`: `transactional`, `allowed_template_prefixes`: `storage.`).
2. Set `EMAIL_SERVICE_URL` to that origin (for example `http://localhost:8002`) and set `EMAIL_SERVICE_API_KEY`.
3. Restart storage-service and keep `python manage.py retry_webhooks` on a one-minute cron if you want retries without waiting for the in-process attempt.
4. Upload a file with a user token that includes `email`.
5. Enable the `storage.object.uploaded` rule for that company when you want a message queued. With the catalog default, email-service accepts the event and skips it.
