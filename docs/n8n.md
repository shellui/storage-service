---
description: Receive storage webhooks in n8n, verify the signature, and handle retries.
---

# Using Shellui webhooks with n8n

Shellui storage can POST signed JSON to an n8n **Webhook** node when a storage event fires. The signing format matches identity-service and hosting-service Shellui Actions.

Webhook rules do not send mail. Mail is a separate forward to email-service, described in [Email notifications](email.md), and it uses the same `retry_webhooks` command.

## Checklist

1. Add a **Webhook** node (POST). Set **Respond** to **Immediately** so Shellui gets a 2xx before the workflow finishes.
2. Copy the **Production URL**, or the **Test URL** while you are building. Activate the workflow before you use the production URL.
3. In Shellui admin, create a Shellui Actions rule: event type, webhook URL, and signing secret (`whsec_…` or plain text).
4. Optional: set **Authorization** on the rule when the node uses Header Auth or Basic Auth.
5. Verify the signature on the raw body. Dedupe on `webhook-id`. That id stays the same across retries.
6. Use **Send test event** in admin while n8n is on **Listen for test event**.

The default timeout is 5s (`ACTIONS_WEBHOOK_TIMEOUT_SECONDS`). Respond immediately in n8n so the first attempt fits in that budget.

A WebDAV sync can emit many `storage.object.uploaded` events in one burst. Delivery is at-least-once and not ordered. Dedupe on `webhook-id` so a retry does not run the rest of the workflow twice. The first attempt already left the API thread. Later attempts come from `retry_webhooks`. See [Scheduled jobs](maintenance-jobs.md).

## Webhook node setup

| Setting | Value |
| --- | --- |
| HTTP Method | POST |
| Path | Default or custom |
| Respond | **Immediately** |
| Authentication | None on the node if you verify HMAC in a Code node. Or use **Header Auth** / **Basic Auth** and paste the same value into the rule **Authorization** field |

n8n shows a test URL while the editor listens once. **Send test event** works with that URL when n8n is listening. For live storage events, activate the workflow and use the production URL.

An inactive workflow, or a test URL that is not listening, returns HTTP 404. Shellui treats 404 as retryable, the same as an offline endpoint. Activate the workflow or fix the URL, then use the delivery log and **Requeue**.

## Signing secret format

Shellui accepts two secret forms:

- **Standard Webhooks:** `whsec_` plus base64-encoded random bytes. Use 32 random bytes. Shellui decodes the suffix and uses those bytes as the HMAC key.
- **Plain text:** any string. The UTF-8 bytes are the HMAC key.

Generate a compatible secret in the storage-service environment:

```python
from apps.actions.webhook_signing import generate_webhook_signing_secret
print(generate_webhook_signing_secret())
```

Shellui generates a `whsec_` secret when you create a rule without one. The create and rotate-secret responses return the full `secret` once. Later reads expose `has_secret` and `secret_hint` (the last four characters) only.

The reference verifier is [verify-shellui-webhook.mjs](examples/verify-shellui-webhook.mjs). Run it with Node.js. Store the same secret in n8n and on the Shellui Actions rule.

## Request headers

| Header | Meaning |
| --- | --- |
| `Content-Type` | `application/json; charset=utf-8` |
| `webhook-id` | Same as envelope `id`. Stable across retries |
| `webhook-timestamp` | Unix seconds when the request was signed |
| `webhook-signature` | `v1,` plus base64 HMAC-SHA256 |
| `X-Shellui-Event` | Event type, for example `storage.object.uploaded` |
| `X-Shellui-Delivery-Attempt` | Attempt number. `1` on the first try |
| `Authorization` | Optional. Copied from the rule |

The body is compact JSON with sorted keys, UTF-8, and non-ASCII characters left as characters. A path such as `docs/résumé.pdf` stays unescaped. Verifiers must use the raw request body bytes.

Signed content is `{webhook-id}.{webhook-timestamp}.{raw body}`.

## Verify the signature in a Code node

Add a **Code** node directly after the Webhook node. Mode: **Run Once for All Items**. Language: **JavaScript**.

The node reads `SHELLUI_WEBHOOK_SECRET` from the n8n environment. It rejects a missing header, a timestamp older than 300s, and a signature that does not match. Configure the Webhook node to pass the raw body as binary when your n8n version can. Otherwise the Code node must see the same bytes Shellui signed.

```javascript
const crypto = require('crypto');
const MAX_AGE_SECONDS = 300;
const secret = $env.SHELLUI_WEBHOOK_SECRET;
const item = $input.first();
const headers = item.json.headers || {};
const msgId = headers['webhook-id'];
const msgTs = headers['webhook-timestamp'];
const msgSig = String(headers['webhook-signature'] || '');
```

Paste the next lines into the same Code node. They turn a `whsec_` secret into key bytes, then compare the digest. `body` must be the raw payload, not `JSON.stringify` of a parsed object:

```javascript
function signingKey(value) {
  if (value.startsWith('whsec_')) {
    return Buffer.from(value.slice('whsec_'.length), 'base64');
  }
  return Buffer.from(value, 'utf8');
}
const body = item.binary?.data
  ? Buffer.from(item.binary.data.data, 'base64')
  : Buffer.from(item.json.body ?? '', 'utf8');
const now = Math.floor(Date.now() / 1000);
const age = Math.abs(now - parseInt(msgTs, 10));
if (!msgId || !msgTs || !msgSig || Number.isNaN(age) || age > MAX_AGE_SECONDS) {
  throw new Error('Missing or expired webhook signature headers');
}
const signed = `${msgId}.${msgTs}.${body.toString('utf8')}`;
const digest = crypto.createHmac('sha256', signingKey(secret))
  .update(signed, 'utf8')
  .digest('base64');
const provided = msgSig.split(' ')[0];
if (provided !== `v1,${digest}`) {
  throw new Error('Invalid webhook signature');
}
return [{
  json: {verified: true, event: headers['x-shellui-event'], webhook_id: msgId},
}];
```

Store `webhook_id` so a retry does not run the rest of the workflow twice. [verify-shellui-webhook.mjs](examples/verify-shellui-webhook.mjs) compares the digest in constant time. Prefer that file when you are not inside n8n.

## Retry behavior

| HTTP result | Outbox |
| --- | --- |
| 2xx | Delivered |
| 404, 408, 409, 425, 429, and other 4xx not listed below | Retry with backoff |
| 400, 401, 403, 405, 410, 413, 422 | Dead. Fix the rule or the workflow, then requeue |
| 5xx, timeouts, connection errors | Retry |
| 429 or 503 with `Retry-After` | Next attempt respects the header, max 1 hour |

Backoff is `30s * 2^(n-1)`, capped at 1 hour, up to 8 attempts. The container runs `retry_webhooks` every minute. See [Scheduled jobs](maintenance-jobs.md).

## Self-hosted n8n on a private network

Shellui blocks private and localhost webhook URLs (SSRF protection). For n8n on a private address or a Docker DNS name:

- Staff can enable **allow private URLs** on that rule, or
- Set `ACTIONS_WEBHOOK_ALLOW_PRIVATE=true`

Unset, that variable stays false even when `DEBUG=true`. A local storage-service does not allow private webhook URLs until you set the variable or the rule flag. Leave the variable off in production unless you accept the risk of the service calling internal addresses.

## Example envelopes

`storage.object.uploaded`:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "storage.object.uploaded",
  "time": "2026-10-06T08:00:00+00:00",
  "company": {"id": 10, "slug": "", "name": ""},
  "data": {
    "bucket_name": "company",
    "path": "docs/résumé.pdf",
    "size": 4096,
    "mime_type": "application/pdf",
    "created": true
  }
}
```

`storage.object.deleted` uses the same envelope shape with `type` set to `storage.object.deleted` and `data` limited to `bucket_name`, `path`, `size`, and `mime_type`. `storage.bucket.created` sends `bucket_id`, `bucket_name`, and `bucket_kind`.

The full catalog is in [Webhooks](actions.md).

## What to do in admin

1. **Send test event** on a rule while the n8n test URL is listening.
2. Open **Deliveries** for status, attempts, and errors.
3. **Requeue** a dead or failed row after n8n is fixed (workflow active, URL correct, auth aligned).

API paths and the retry command are in [Webhooks](actions.md).
