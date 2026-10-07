---
description: Forward storage events to email-service so a company rule can send mail. The email body omits sign-in links, tokens, signed URLs, and secret-shaped fields.
---

# Email notifications

storage-service posts each catalog event to [email-service](https://github.com/shellui/email-service) when `EMAIL_SERVICE_API_KEY` is set. email-service sends mail only when that company has an enabled rule for the event. With the key unset, storage-service does not call email-service.

[Shellui Actions](actions.md) webhooks are a separate path. A webhook rule does not send mail, and mail does not require a webhook rule. Webhook envelopes, signing, and retries stay the same as identity-service and hosting-service.

## Events that are forwarded

storage-service posts every catalog event it already emits for webhooks. Folder placeholder objects (`.emptyFolderPlaceholder`) stay omitted. Catalog defaults in email-service do not send mail by themselves. A company receives mail only after it creates a rule there.

| Event type | When it is posted |
| --- | --- |
| `storage.bucket.created` | The company bucket is created on first use |
| `storage.object.uploaded` | A file is uploaded or overwritten |
| `storage.object.deleted` | An object row and its blob are removed |

storage-service does not store those email rules. A disabled rule returns `skipped_reason: rule_disabled`. storage-service treats that response as delivered and does not post the event again.

## Configuration

Set both variables on the storage-service process. Names match the [email-service integration contract](https://github.com/shellui/email-service/blob/main/docs/integration.md).

| Variable | Default | Purpose |
| --- | --- | --- |
| `EMAIL_SERVICE_URL` | `https://email.shellui.com` | Origin only. storage-service appends `/api/v1/events` |
| `EMAIL_SERVICE_API_KEY` | empty | Service key with prefix `esk_`. Sent as `Authorization: Bearer` |
| `EMAIL_SERVICE_ALLOW_PRIVATE` | `false` | Allow a URL that resolves to a private or loopback address. Set this for an internal email-service URL |

Issue the key in email-service for service `storage`, lane `transactional`, and template prefix `storage.`. Store it in the storage-service secret store. An empty key disables forwarding, including when the URL stays at the default. The key is not written to logs.

`EMAIL_SERVICE_URL` is the origin, with no path. `https://email.shellui.com/api/v1` is not a valid value.

Local email-service:

```bash
EMAIL_SERVICE_URL=http://localhost:8003
EMAIL_SERVICE_ALLOW_PRIVATE=true
EMAIL_SERVICE_API_KEY=esk_your_service_key_here
```

`localhost` is a loopback address, and `host.docker.internal` (the Compose default) resolves to a private address. Leave `EMAIL_SERVICE_ALLOW_PRIVATE` unset when the URL is public. The POST uses the same address check as a Shellui Actions webhook, and it does not follow redirects.

Docker Compose passes the same variables through. Inside Compose the default origin is `http://host.docker.internal:8003`, so set `EMAIL_SERVICE_ALLOW_PRIVATE=true` there. The full list is in [Configuration](configuration.md).

## Request body

The forward runs after the database commit, on the same worker pool as webhook delivery. The API response does not wait for email-service.

`POST /api/v1/events` sends the storage event data and one recipient hint. The hint is the acting user's email and user id, when the JWT included them. The body omits `language` so the company rule can choose it.

The email copy and the webhook envelope drop sign-in links, tokens, signed URLs, and secret-shaped fields before they are stored. Dropped keys include `magic_link_url`, `token`, `password`, `api_key`, `secret`, `signed_url`, and any `*_token` or `*_secret` name. A value that is a sign-in URL or a signed URL is dropped too, including a `magic-link` path, a share-link path, or a query parameter such as `token`, `signature`, or `X-Amz-Signature`. The event log stores the same reduced object.

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

`payload` is the webhook `data` object after that omission. `company_name` is included only when the emitter already has a company name. email-service otherwise uses a name stored from an earlier call, or the template default.

When the JWT has no email, `recipients` is `[]`. email-service answers `202` with `skipped_reason: no_recipients`. storage-service treats that response as delivered. `202` with `skipped_reason: no_rule` or `rule_disabled` is delivered too.

`idempotency_key` is the outbox row id. Retries send this stored body again, including the same key. The API key is not written into the outbox row or into logs.

The Shellui Actions deliveries API lists webhook rows only. Email rows stay on the outbox until `retry_webhooks` finishes them.

## Retries

`python manage.py retry_webhooks` retries email rows with webhook rows. The in-container scheduler runs that command every minute. See [Scheduled jobs](maintenance-jobs.md). Backoff is `30s * 2^(n-1)`, capped at 1 hour, for 8 attempts. HTTP timeout is `ACTIONS_WEBHOOK_TIMEOUT_SECONDS` (default 5s).

| Result | What storage-service does |
| --- | --- |
| 2xx | Delivered. `skipped_reason` of `rule_disabled`, `no_rule`, or `no_recipients` is finished |
| 404, 408, 409, 425, 429, other 4xx not listed below, 5xx, timeouts, connection errors | Retry with the same body and `idempotency_key` |
| 429 or 503 with `Retry-After` | Retry. The wait is `Retry-After`, capped at 1 hour |
| 400, 401, 403, 405, 410, 413, 422 | Dead. That body is not sent again |

`404` retries, the same way a Shellui Actions webhook retries an inactive n8n workflow. See [n8n](n8n.md).

A post made by the scheduled job sends `X-Request-ID: sjr-{run_id}`.

Finished rows are deleted with webhook deliveries after `EVENT_LOG_RETENTION_DAYS`.
