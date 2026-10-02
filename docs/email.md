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

`payload` is the webhook object metadata. `company_name` is optional. storage-service sends it only when the emitter already has a company name. email-service otherwise uses a name stored from an earlier call, the company provider `from_name` when that name is not `Shellui`, or the template default (`your company`).

`recipients` holds the actor when the token includes an email address. That is the hint email-service uses when the rule's `recipient_mode` is `hints`. A company that wants a fixed list sets `static` recipients on the rule. email-service then ignores this hint. An empty `recipients` list, including a token with no email, returns `202` and `skipped_reason: no_recipients`. That response is finished.

`idempotency_key` is the outbox row id. Retries send the same key and the same body. `language` is omitted, so email-service uses the rule language, then `en`.

## Retries

The HTTP call runs after the database commit, off the request thread. Failures stay on the Shellui Actions outbox. The cron you already run for webhooks retries them:

```cron
* * * * * python manage.py retry_webhooks
```

| Result | What storage-service does |
| --- | --- |
| 2xx | Delivered. `skipped_reason` of `rule_disabled` or `no_recipients` is finished. |
| 404, 408, 409, 425, 429, other 4xx, 5xx, timeouts, connection errors | Retry with the same idempotency key and the same body. |
| 400, 401, 403, 405, 410, 413, 422 | Dead. That body is not posted again. |

HTTP 404 is retried, the same as a Shellui Actions webhook. Backoff is **30s × 2^(attempt−1)**, capped at **1 hour**, up to **8** attempts. `429` and `503` honor `Retry-After`, still capped at 1 hour. The timeout is `ACTIONS_WEBHOOK_TIMEOUT_SECONDS` (default 5 seconds).

`purge_expired_data` deletes finished email rows with finished webhook deliveries after `EVENT_LOG_RETENTION_DAYS`. See [event-log.md](event-log.md).

## Try it locally

1. Run email-service and create a service key for `storage` (`allowed_lanes`: `transactional`, `allowed_template_prefixes`: `storage.`).
2. Set `EMAIL_SERVICE_URL` to `http://localhost:8003` and set `EMAIL_SERVICE_API_KEY`. In Docker Compose the container uses `http://host.docker.internal:8003`.
3. Restart storage-service and keep `python manage.py retry_webhooks` on a one-minute cron if you want retries without waiting for the in-process attempt.
4. Upload a file with a user token that includes `email`.
5. Enable the `storage.object.uploaded` rule for that company when you want a message queued. With the catalog default, email-service accepts the event and skips it.
