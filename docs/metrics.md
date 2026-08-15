# Accessing storage metrics

The service exposes **Prometheus-compatible** metrics over HTTP:

| Endpoint | Scope |
| -------- | ----- |
| `GET /storage/v1/metrics` | Metrics for **one company** |
| `GET /storage/v1/metrics/all` | Metrics **across all companies** (privileged) |

Both endpoints accept a **Bearer token** issued by identity-service (session JWT or personal access token). Responses are **plain text** (OpenMetrics/Prometheus exposition), not JSON.

---

## Company metrics — `GET /storage/v1/metrics`

- **Authorization:** `Bearer <JWT or PAT>` — the token **must** include a `company_id` claim; that company is the only scope for this endpoint.
- **Do not** pass `company_id` in the query string (or body); it is rejected with `400`.

**Who may call:** Django `is_staff`, or a user who is an **owner** of that company (`user_metadata.is_company_owner`).

The exposition contains only that tenant’s series (`company_id` label). Other companies never appear in the dump.

---

## Global metrics — `GET /storage/v1/metrics/all`

- **Authorization:** `Bearer <JWT or PAT>`
- **Who may call:**
  - Django **staff** (`user_metadata.is_staff`), or
  - A **personal access token** created with **`access_global_metrics`** by staff (JWT claim `pat_agm: true`).

Example:

```bash
curl -sS 'http://localhost:8001/storage/v1/metrics' \
  -H 'Authorization: Bearer <JWT or PAT>'

curl -sS 'http://localhost:8001/storage/v1/metrics/all' \
  -H 'Authorization: Bearer <JWT or PAT>'
```

---

## Series

Gauges are labeled with `company_id`:

| Metric | Meaning |
| ------ | ------- |
| `shellui_storage_objects_total` | Stored objects |
| `shellui_storage_bytes_total` | Stored bytes |
| `shellui_storage_buckets_total` | Buckets |
| `shellui_storage_documents_total` | Document-like objects |
| `shellui_storage_document_bytes` | Bytes in document-like objects |
| `shellui_storage_uploads_24h` | Objects created in the last 24 hours |
| `shellui_storage_uploads_7d` | Objects created in the last 7 days |
| `shellui_storage_uploads_30d` | Objects created in the last 30 days |
| `shellui_storage_bytes_7d` | Bytes uploaded in the last 7 days |
| `shellui_storage_quota_used_bytes` | Company quota used |
| `shellui_storage_quota_max_bytes` | Company quota limit |

For OpenAPI details, open **`/api/docs/`**.
