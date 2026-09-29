# Using Shellui webhooks with n8n

Shellui storage-service can POST signed JSON to an **n8n Webhook** node when storage events happen. This guide matches identity-service and hosting-service Shellui Actions behavior so you can reuse the same n8n workflow patterns.

---

## Before you start

1. Create a Shellui Actions webhook rule in the Shellui admin app (or `POST /api/v1/actions/rules` on storage-service).
2. Copy the **production** Webhook URL from n8n when the workflow is **active**.
3. Set the rule signing secret to the value n8n shows (or a `whsec_…` secret you generate). Plain text and `whsec_<base64>` both work.
4. Optional: set **Authorization** on the rule if the Webhook node uses Header Auth or Basic Auth.

Default HTTP timeout from Shellui is **5 seconds** (`ACTIONS_WEBHOOK_TIMEOUT_SECONDS`). In the Webhook node, set **Respond** to **Immediately** so n8n answers before your workflow finishes.

---

## n8n Webhook node

| Setting | Value |
| ------- | ----- |
| HTTP Method | POST |
| Path | Your choice (production URL includes the path) |
| Authentication | None (signature is enough) or Header Auth / Basic Auth matching the rule **Authorization** field |
| Respond | **Immediately** |

**Production vs test URL:** Shellui always POSTs to the URL saved on the rule. Use the production URL when the workflow is active. n8n returns **404** when the workflow is inactive or you use **Listen for test event** without listening; Shellui **retries** 404 (see retries below).

---

## Delivery semantics (storage bursts)

- **At-least-once:** Dedupe on header `webhook-id` (same as envelope `id`).
- **No ordering guarantee:** WebDAV syncs can emit many `storage.object.uploaded` events in a short window.
- **Bounded dispatch:** Post-commit delivery uses a small thread pool (`ACTIONS_WEBHOOK_DISPATCH_WORKERS`, default 4). Retries use `retry_webhooks` with `--batch-size`, `--max-seconds`, and `--concurrency` limits.
- **Same envelope id on retries:** `webhook-id` stays stable; `X-Shellui-Delivery-Attempt` increments.

---

## HTTP headers

| Header | Meaning |
| ------ | ------- |
| `Content-Type` | `application/json; charset=utf-8` |
| `webhook-id` | Event id (stable across retries) |
| `webhook-timestamp` | Unix seconds when signed |
| `webhook-signature` | `v1,<base64>` HMAC-SHA256 |
| `X-Shellui-Event` | Event type (e.g. `storage.object.uploaded`) |
| `X-Shellui-Delivery-Attempt` | Attempt number (1 on first try) |

Verify the **raw request body bytes**, not a pretty-printed re-encoding.

---

## Retry behavior (n8n-friendly)

| HTTP result | Shellui behavior |
| ----------- | ---------------- |
| 2xx | Delivered |
| **404**, 408, 409, 425, 429, other retryable 4xx, 5xx, timeouts, connection errors | Failed, scheduled retry (backoff 30s × 2^(n−1), max 1h, up to 8 attempts) |
| **400**, **401**, **403**, **405**, **410**, **413**, **422** | **Dead** (no retry) |
| 429 / 503 with `Retry-After` | Next attempt respects `Retry-After` (seconds or HTTP date), capped at 1h |

---

## Verify signature in n8n (Code node)

Add a **Code** node after the Webhook node. Mode: **Run Once for All Items**. Language: **JavaScript**.

```javascript
const crypto = require('crypto');

const secret = $env.SHELLUI_WEBHOOK_SECRET; // whsec_… or plain string
const rawBody = $json.body ?? JSON.stringify($json);
const bodyBuffer = Buffer.isBuffer(rawBody)
  ? rawBody
  : Buffer.from(String(rawBody), 'utf8');

const webhookId = $json.headers['webhook-id'];
const timestamp = $json.headers['webhook-timestamp'];
const signature = ($json.headers['webhook-signature'] || '').split(',')[1];

const ts = parseInt(timestamp, 10);
if (!Number.isFinite(ts) || Math.abs(Math.floor(Date.now() / 1000) - ts) > 300) {
  throw new Error('Webhook timestamp outside 5 minute window');
}

function hmacKey(secret) {
  if (secret.startsWith('whsec_')) {
    return Buffer.from(secret.slice(6), 'base64');
  }
  return Buffer.from(secret, 'utf8');
}

const signed = `${webhookId}.${timestamp}.`;
const expected = crypto
  .createHmac('sha256', hmacKey(secret))
  .update(Buffer.concat([Buffer.from(signed, 'utf8'), bodyBuffer]))
  .digest('base64');

if (expected !== signature) {
  throw new Error('Invalid webhook signature');
}

// Dedupe: store webhookId in n8n static data or an external store
return $input.all();
```

Configure the Webhook node to pass **Raw Body** when your n8n version supports it so the Code node sees exact bytes.

---

## Verify signature in Node.js (plain crypto)

```javascript
import crypto from 'node:crypto';

export function verifyShelluiWebhook({
  secret,
  rawBody,
  webhookId,
  webhookTimestamp,
  webhookSignature,
  maxSkewSeconds = 300,
}) {
  const ts = Number(webhookTimestamp);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(ts) || Math.abs(now - ts) > maxSkewSeconds) {
    return false;
  }
  const sig = String(webhookSignature || '').replace(/^v1,/, '');
  const key = secret.startsWith('whsec_')
    ? Buffer.from(secret.slice(6), 'base64')
    : Buffer.from(secret, 'utf8');
  const prefix = Buffer.from(`${webhookId}.${webhookTimestamp}.`, 'utf8');
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
  const expected = crypto.createHmac('sha256', key).update(Buffer.concat([prefix, body])).digest('base64');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
}
```

---

## Self-hosted n8n on a private network

Shellui blocks private IP webhook targets by default (SSRF protection). Options:

- Deploy n8n on a public HTTPS URL, or
- Set `ACTIONS_WEBHOOK_ALLOW_PRIVATE=true` for the whole deployment, or
- Staff can enable **allow private URLs** on a single rule in the admin API.

---

## Admin workflow

1. **Send test event** (`POST /api/v1/actions/rules/<id>/send-test`): posts a sample envelope (no outbox row). In n8n, use **Listen for test event** on the Webhook node first.
2. **Delivery log** (`GET /api/v1/actions/deliveries`): inspect attempts and errors (404 while inactive is normal).
3. **Requeue** (`POST /api/v1/actions/deliveries/<uuid>/requeue`): reset a dead or failed row to pending for the next `retry_webhooks` run.

---

## Example storage envelopes

**`storage.object.uploaded`**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "storage.object.uploaded",
  "time": "2026-09-29T08:00:00+00:00",
  "company": { "id": 10, "slug": "", "name": "" },
  "data": {
    "object_id": "550e8400-e29b-41d4-a716-446655440001",
    "bucket_name": "company",
    "bucket_kind": "company",
    "path": "docs/résumé.pdf",
    "size": 4096,
    "mime_type": "application/pdf",
    "version": 1,
    "created": true
  }
}
```

**`storage.object.deleted`**

```json
{
  "id": "660e8400-e29b-41d4-a716-446655440000",
  "type": "storage.object.deleted",
  "time": "2026-09-29T08:01:00+00:00",
  "company": { "id": 10, "slug": "", "name": "" },
  "data": {
    "bucket_name": "company",
    "path": "docs/résumé.pdf",
    "size": 4096,
    "mime_type": "application/pdf"
  }
}
```

**`storage.bucket.created`**

```json
{
  "id": "770e8400-e29b-41d4-a716-446655440000",
  "type": "storage.bucket.created",
  "time": "2026-09-29T08:00:00+00:00",
  "company": { "id": 10, "slug": "", "name": "" },
  "data": {
    "bucket_id": "880e8400-e29b-41d4-a716-446655440001",
    "bucket_name": "company",
    "bucket_kind": "company"
  }
}
```

See also [actions.md](actions.md) for rule API and cron setup.
