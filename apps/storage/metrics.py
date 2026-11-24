"""Storage figures as OpenTelemetry observable gauges.

Each instrument keeps the ``company_id`` attribute the Prometheus series used.
Values come from the database when the meter collects. Export is process-wide
(the old per-tenant ``/metrics`` scrape is gone).
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta
from typing import Any

from django.db.models import Count, Sum
from django.utils import timezone

from .models import Bucket, CompanyQuota, StorageObject
from .stats import document_q

# Prometheus name -> field on the snapshot. The OpenTelemetry name drops
# ``_total`` and turns underscores into dots.
STORAGE_GAUGES: tuple[tuple[str, str, str, str], ...] = (
    ('shellui_storage_objects_total', 'objects_total', '1', 'Stored objects for a company.'),
    ('shellui_storage_bytes_total', 'bytes_total', 'By', 'Total stored bytes for a company.'),
    ('shellui_storage_buckets_total', 'buckets_total', '1', 'Buckets for a company.'),
    ('shellui_storage_documents_total', 'documents_total', '1', 'Document-like objects for a company.'),
    ('shellui_storage_document_bytes', 'document_bytes', 'By', 'Bytes in document-like objects for a company.'),
    ('shellui_storage_uploads_24h', 'uploads_24h', '1', 'Objects created in the last 24 hours.'),
    ('shellui_storage_uploads_7d', 'uploads_7d', '1', 'Objects created in the last 7 days.'),
    ('shellui_storage_uploads_30d', 'uploads_30d', '1', 'Objects created in the last 30 days.'),
    ('shellui_storage_bytes_7d', 'bytes_7d', 'By', 'Bytes uploaded in the last 7 days.'),
    (
        'shellui_storage_quota_used_bytes',
        'quota_used_bytes',
        'By',
        'Company quota used bytes.',
    ),
    (
        'shellui_storage_quota_max_bytes',
        'quota_max_bytes',
        'By',
        'Company quota max bytes.',
    ),
)

logger = logging.getLogger(__name__)

_cache_lock = threading.Lock()
_cache_at = 0.0
_cache_value: list[tuple[str, dict[str, int]]] | None = None
_CACHE_TTL = 5.0
_registered: tuple[Any, ...] | None = None


def clear_storage_metric_cache() -> None:
    global _cache_at, _cache_value
    with _cache_lock:
        _cache_at = 0.0
        _cache_value = None


def _company_ids() -> list[int]:
    ids: set[int] = set()
    ids.update(Bucket.objects.values_list('company_id', flat=True))
    ids.update(StorageObject.objects.values_list('company_id', flat=True))
    ids.update(CompanyQuota.objects.values_list('company_id', flat=True))
    return sorted(ids)


def _snapshot(company_id: int) -> dict[str, int]:
    objects = StorageObject.objects.filter(company_id=company_id)
    totals = objects.aggregate(object_count=Count('id'), total_bytes=Sum('size'))
    doc_agg = objects.filter(document_q()).aggregate(count=Count('id'), bytes=Sum('size'))
    now = timezone.now()
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)
    quota = CompanyQuota.objects.filter(company_id=company_id).first()
    return {
        'objects_total': totals['object_count'] or 0,
        'bytes_total': totals['total_bytes'] or 0,
        'buckets_total': Bucket.objects.filter(company_id=company_id).count(),
        'documents_total': doc_agg['count'] or 0,
        'document_bytes': doc_agg['bytes'] or 0,
        'uploads_24h': objects.filter(created_at__gte=day_ago).count(),
        'uploads_7d': objects.filter(created_at__gte=week_ago).count(),
        'uploads_30d': objects.filter(created_at__gte=month_ago).count(),
        'bytes_7d': objects.filter(created_at__gte=week_ago).aggregate(total=Sum('size'))['total'] or 0,
        'quota_used_bytes': quota.used_bytes if quota else 0,
        'quota_max_bytes': quota.max_bytes if quota else 0,
    }


def _snapshots() -> list[tuple[str, dict[str, int]]]:
    global _cache_at, _cache_value
    now = time.monotonic()
    with _cache_lock:
        if _cache_value is not None and now - _cache_at < _CACHE_TTL:
            return _cache_value
    loaded = [(str(company_id), _snapshot(company_id)) for company_id in _company_ids()]
    with _cache_lock:
        _cache_at = time.monotonic()
        _cache_value = loaded
    return loaded


def register_storage_metrics(meter) -> None:
    """Create one observable gauge per storage figure. Safe to call once per provider."""
    global _registered
    token = id(meter)
    if _registered == token:
        return
    from opentelemetry.metrics import Observation
    from shellui_django.telemetry import canonical_metric_name

    def _observe(field: str):
        def callback(_options):
            try:
                rows = _snapshots()
            except Exception:
                logger.exception('storage telemetry: failed to read storage gauges')
                return []
            return [Observation(snap[field], {'company_id': company_id}) for company_id, snap in rows]

        return callback

    for prometheus_name, field, unit, description in STORAGE_GAUGES:
        meter.create_observable_gauge(
            canonical_metric_name(prometheus_name),
            callbacks=[_observe(field)],
            unit=unit,
            description=description,
        )
    _registered = token
