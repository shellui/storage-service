---
description: Cron commands for webhook retries and event-log retention. storage-service does not run Celery.
---

# Maintenance jobs

storage-service does not run a scheduler. The Docker entrypoint migrates the database and starts Gunicorn. Webhook retries and data retention run only when you schedule them.

There is no Celery worker, no beat process, and no in-container cron. Redis is an optional shared cache. It is not a job broker here.

Run the commands with the same environment as the web process: same database, same `EVENT_LOG_RETENTION_DAYS`, same network access to webhook URLs. On Docker, exec into the storage-service container or run a sidecar from the same image.

## Retry webhook deliveries

`retry_webhooks` sends outbox rows that are due. The first attempt already ran after the database commit. This command covers later attempts. Backoff and which HTTP statuses are retried are in [Webhooks](actions.md).

Run it every minute:

```bash
python manage.py retry_webhooks --batch-size 50 --max-seconds 50 --concurrency 4
```

```cron
* * * * * cd /app && python manage.py retry_webhooks
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--batch-size` | `50` | Maximum rows claimed in one run |
| `--max-seconds` | `50` | Stop after this many seconds |
| `--concurrency` | `4` | Parallel HTTP calls |
| `--dry-run` | off | Claim rows and skip HTTP |

Keep `--max-seconds` under the cron interval so two runs do not pile up. A row stays leased for `ACTIONS_WEBHOOK_RETRY_LEASE_SECONDS` (default 120) while a run holds it.

## Purge the event log and old deliveries

`purge_expired_data` deletes event-log rows older than `EVENT_LOG_RETENTION_DAYS` (default 7). It also deletes webhook deliveries that are already delivered or dead and older than that window. Pending deliveries are kept.

Run it every hour:

```bash
python manage.py purge_expired_data --max-seconds 300
```

```cron
17 * * * * cd /app && python manage.py purge_expired_data --max-seconds 300
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--batch-size` | `2000` | Rows deleted per statement |
| `--max-seconds` | `0` | Stop after this many seconds. `0` means no limit. The next run continues |
| `--dry-run` | off | Count matching rows and delete nothing |

If the oldest event is older than the retention plus one day, the job is not keeping up. `GET /api/v1/actions/event-log/retention` then reports `stale_events`. See [Event log](event-log.md).

## What you do not schedule

Nothing else in this service expires on a timer. Share links are checked when someone redeems them. Preview-style app expiry belongs to hosting-service, not here.

Confirm both cron lines after deploy. [tools/prod-config-check.sh](../tools/prod-config-check.sh) checks the live storage API configuration. It does not prove that your scheduler is firing. The retention endpoint does.
