"""Prometheus-style metrics for storage-service.

Exposition is JWT-protected (see StorageMetricsView / StorageGlobalMetricsView).
Company-scoped `/metrics` uses a fresh registry so other tenants never appear
in the text dump.
"""

from __future__ import annotations

from datetime import timedelta

from django.db.models import Count, Sum
from django.utils import timezone
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest

from .models import Bucket, CompanyQuota, StorageObject
from .stats import document_q

_LABELS = ('company_id',)


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


def _bind_gauges(registry: CollectorRegistry) -> dict[str, Gauge]:
    return {
        'objects_total': Gauge(
            'shellui_storage_objects_total',
            'Stored objects for a company.',
            _LABELS,
            registry=registry,
        ),
        'bytes_total': Gauge(
            'shellui_storage_bytes_total',
            'Total stored bytes for a company.',
            _LABELS,
            registry=registry,
        ),
        'buckets_total': Gauge(
            'shellui_storage_buckets_total',
            'Buckets for a company.',
            _LABELS,
            registry=registry,
        ),
        'documents_total': Gauge(
            'shellui_storage_documents_total',
            'Document-like objects for a company.',
            _LABELS,
            registry=registry,
        ),
        'document_bytes': Gauge(
            'shellui_storage_document_bytes',
            'Bytes in document-like objects for a company.',
            _LABELS,
            registry=registry,
        ),
        'uploads_24h': Gauge(
            'shellui_storage_uploads_24h',
            'Objects created in the last 24 hours.',
            _LABELS,
            registry=registry,
        ),
        'uploads_7d': Gauge(
            'shellui_storage_uploads_7d',
            'Objects created in the last 7 days.',
            _LABELS,
            registry=registry,
        ),
        'uploads_30d': Gauge(
            'shellui_storage_uploads_30d',
            'Objects created in the last 30 days.',
            _LABELS,
            registry=registry,
        ),
        'bytes_7d': Gauge(
            'shellui_storage_bytes_7d',
            'Bytes uploaded in the last 7 days.',
            _LABELS,
            registry=registry,
        ),
        'quota_used_bytes': Gauge(
            'shellui_storage_quota_used_bytes',
            'Company quota used bytes.',
            _LABELS,
            registry=registry,
        ),
        'quota_max_bytes': Gauge(
            'shellui_storage_quota_max_bytes',
            'Company quota max bytes.',
            _LABELS,
            registry=registry,
        ),
    }


def _set_company(gauges: dict[str, Gauge], company_id: int) -> None:
    cid = str(company_id)
    snap = _snapshot(company_id)
    for name, gauge in gauges.items():
        gauge.labels(company_id=cid).set(snap[name])


def metrics_http_body(company_id: int | None = None) -> bytes:
    """Serialize Prometheus text. When ``company_id`` is set, only that tenant is included."""
    registry = CollectorRegistry()
    gauges = _bind_gauges(registry)
    if company_id is None:
        for cid in _company_ids():
            _set_company(gauges, cid)
    else:
        _set_company(gauges, company_id)
    return generate_latest(registry)


METRICS_CONTENT_TYPE = CONTENT_TYPE_LATEST
