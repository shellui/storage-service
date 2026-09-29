"""HTTP retry vs permanent failure rules for webhook delivery."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

# Dead on first failure (no retry).
PERMANENT_HTTP_STATUSES = frozenset({400, 401, 403, 405, 410, 413, 422})

# Explicitly retryable client errors (n8n inactive workflow often returns 404).
RETRYABLE_HTTP_STATUSES = frozenset({404, 408, 409, 425, 429})


def is_permanent_http_status(status: int | None) -> bool:
    if status is None:
        return False
    if status >= 500:
        return False
    if status in RETRYABLE_HTTP_STATUSES:
        return False
    if status in PERMANENT_HTTP_STATUSES:
        return True
    if 400 <= status < 500:
        # Other 4xx: retry (conservative for automation endpoints).
        return False
    return False


def parse_retry_after_seconds(header_value: str | None, *, now: datetime | None = None) -> int | None:
    """Parse ``Retry-After`` as delay-seconds or HTTP-date."""
    if not header_value or not str(header_value).strip():
        return None
    raw = str(header_value).strip()
    try:
        seconds = int(raw)
        return max(0, seconds)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = now or datetime.now(timezone.utc)
        return max(0, int((dt - now).total_seconds()))
    except (TypeError, ValueError, OverflowError):
        return None


def next_attempt_delay_seconds(
    *,
    attempt_number: int,
    http_status: int | None,
    retry_after_seconds: int | None,
    backoff_seconds: int,
    max_backoff_seconds: int = 3600,
) -> int:
    """Combine exponential backoff with ``Retry-After`` on 429/503."""
    base = min(max_backoff_seconds, backoff_seconds)
    if http_status in (429, 503) and retry_after_seconds is not None:
        return min(max_backoff_seconds, max(base, retry_after_seconds))
    return base
