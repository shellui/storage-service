"""HTTP retry classification and Retry-After handling for webhook delivery."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

# Permanent failures: do not retry (dead on first failure).
PERMANENT_HTTP_STATUSES = frozenset({400, 401, 403, 405, 410, 413, 422})

# Explicitly retryable 4xx (404 = inactive n8n workflow or test URL not listening).
RETRYABLE_HTTP_STATUSES = frozenset({404, 408, 409, 425, 429})

MAX_BACKOFF_SECONDS = 3600


def is_permanent_http_status(status: int | None) -> bool:
    if status is None:
        return False
    if status in PERMANENT_HTTP_STATUSES:
        return True
    if status in RETRYABLE_HTTP_STATUSES:
        return False
    if 500 <= status < 600:
        return False
    if 400 <= status < 500:
        # Other 4xx (402, 406, 407, 411, 412, 414-421, 423-424, 426-428, 431, 451, …) retry.
        return False
    return False


def parse_retry_after_header(value: str | None, *, now: datetime | None = None) -> int | None:
    """
    Parse ``Retry-After`` (delay seconds or HTTP date). Returns seconds to wait, or None.
    """
    if not value or not str(value).strip():
        return None
    raw = str(value).strip()
    if raw.isdigit():
        seconds = int(raw)
        return max(0, seconds) if seconds >= 0 else None
    try:
        target = parsedate_to_datetime(raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if target.tzinfo is None:
        target = target.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    delta = (target - now).total_seconds()
    return max(0, int(delta))


def compute_retry_delay_seconds(
    *,
    attempt_number: int,
    http_status: int | None,
    retry_after_seconds: int | None,
    base_backoff_seconds: int,
) -> int:
    """
    Next wait before retry: honor Retry-After on 429/503, else exponential backoff.
    Always capped at ``MAX_BACKOFF_SECONDS`` (1 hour).
    """
    delay = base_backoff_seconds
    if http_status in (429, 503) and retry_after_seconds is not None:
        delay = max(delay, retry_after_seconds)
    return min(MAX_BACKOFF_SECONDS, max(1, int(delay)))
