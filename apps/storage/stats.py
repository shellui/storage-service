"""Aggregated storage statistics for Django admin and the REST stats API."""

from __future__ import annotations

from datetime import timedelta
from functools import reduce
from operator import or_
from typing import Any

from django.db.models import Count, Q, Sum
from django.db.models.functions import TruncDate
from django.utils import timezone

from .models import Bucket, CompanyQuota, StorageObject

DOCUMENT_MIME_PREFIXES = (
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats',
    'application/vnd.ms-',
    'application/rtf',
    'text/',
    'application/json',
    'application/xml',
    'application/yaml',
    'application/toml',
    'application/epub',
)


def human_bytes(n: int | None) -> str:
    value = float(n or 0)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if abs(value) < 1024 or unit == 'TiB':
            if unit == 'B':
                return f'{int(value)} {unit}'
            return f'{value:.1f} {unit}'
        value /= 1024
    return f'{int(n or 0)} B'


def _mime_family(mime: str) -> str:
    mime = (mime or 'application/octet-stream').lower()
    if mime.startswith('image/'):
        return 'Images'
    if mime.startswith('video/'):
        return 'Video'
    if mime.startswith('audio/'):
        return 'Audio'
    if mime in {'text/markdown', 'text/x-markdown'} or mime.startswith('text/'):
        return 'Text / Markdown'
    if (
        mime == 'application/pdf'
        or 'document' in mime
        or 'msword' in mime
        or 'officedocument' in mime
    ):
        return 'Office / PDF'
    if mime.startswith('application/json') or mime in {
        'application/yaml',
        'application/toml',
        'application/xml',
    }:
        return 'Data'
    return 'Other'


def document_q() -> Q:
    return reduce(or_, (Q(mime_type__istartswith=prefix) for prefix in DOCUMENT_MIME_PREFIXES))


def _is_document(mime: str) -> bool:
    mime = (mime or '').lower()
    return any(mime.startswith(prefix) for prefix in DOCUMENT_MIME_PREFIXES)


def _iso(value) -> str | None:
    if value is None:
        return None
    if hasattr(value, 'isoformat'):
        return value.isoformat().replace('+00:00', 'Z')
    return str(value)


def build_storage_stats(
    *,
    recent_limit: int = 25,
    days: int = 14,
    company_id: int | None = None,
) -> dict[str, Any]:
    """
    Aggregate upload statistics.

    When ``company_id`` is set, all metrics are scoped to that company
    (typical for non-staff admin users).
    """
    now = timezone.now()
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)
    series_start = now - timedelta(days=days)

    objects = StorageObject.objects.all()
    buckets = Bucket.objects.all()
    quotas_qs = CompanyQuota.objects.all()
    if company_id is not None:
        objects = objects.filter(company_id=company_id)
        buckets = buckets.filter(company_id=company_id)
        quotas_qs = quotas_qs.filter(company_id=company_id)

    totals = objects.aggregate(object_count=Count('id'), total_bytes=Sum('size'))
    object_count = totals['object_count'] or 0
    total_bytes = totals['total_bytes'] or 0

    doc_agg = objects.filter(document_q()).aggregate(count=Count('id'), bytes=Sum('size'))

    by_company = list(
        objects.values('company_id')
        .annotate(object_count=Count('id'), total_bytes=Sum('size'))
        .order_by('-total_bytes')[:20]
    )
    for row in by_company:
        row['total_bytes_display'] = human_bytes(row['total_bytes'])

    by_bucket = list(
        objects.values('bucket__name', 'bucket__company_id')
        .annotate(object_count=Count('id'), total_bytes=Sum('size'))
        .order_by('-total_bytes')[:20]
    )
    for row in by_bucket:
        row['total_bytes_display'] = human_bytes(row['total_bytes'])
        row['label'] = f"{row['bucket__company_id']}/{row['bucket__name']}"

    by_mime_raw = list(
        objects.values('mime_type')
        .annotate(object_count=Count('id'), total_bytes=Sum('size'))
        .order_by('-object_count')
    )
    family_map: dict[str, dict[str, int]] = {}
    for row in by_mime_raw:
        family = _mime_family(row['mime_type'])
        entry = family_map.setdefault(family, {'object_count': 0, 'total_bytes': 0})
        entry['object_count'] += row['object_count']
        entry['total_bytes'] += row['total_bytes'] or 0
    by_family = [
        {
            'family': name,
            'object_count': data['object_count'],
            'total_bytes': data['total_bytes'],
            'total_bytes_display': human_bytes(data['total_bytes']),
        }
        for name, data in sorted(
            family_map.items(), key=lambda item: item[1]['object_count'], reverse=True
        )
    ]
    for row in by_mime_raw:
        row['total_bytes_display'] = human_bytes(row['total_bytes'])
    top_mime = by_mime_raw[:15]

    uploads_24h = objects.filter(created_at__gte=day_ago).count()
    uploads_7d = objects.filter(created_at__gte=week_ago).count()
    uploads_30d = objects.filter(created_at__gte=month_ago).count()
    bytes_7d = objects.filter(created_at__gte=week_ago).aggregate(total=Sum('size'))['total'] or 0

    daily = list(
        objects.filter(created_at__gte=series_start)
        .annotate(day=TruncDate('created_at'))
        .values('day')
        .annotate(object_count=Count('id'), total_bytes=Sum('size'))
        .order_by('day')
    )
    daily_by_key = {row['day']: row for row in daily}
    daily_series = []
    for offset in range(days, -1, -1):
        day = (now - timedelta(days=offset)).date()
        row = daily_by_key.get(day)
        count = row['object_count'] if row else 0
        daily_series.append(
            {
                'day': day.isoformat(),
                'object_count': count,
                'total_bytes': row['total_bytes'] if row else 0,
                'total_bytes_display': human_bytes(row['total_bytes'] if row else 0),
            }
        )
    max_daily = max((row['object_count'] for row in daily_series), default=0) or 1
    for row in daily_series:
        row['bar_pct'] = round(100 * row['object_count'] / max_daily)

    quotas = []
    for quota in quotas_qs.order_by('company_id'):
        pct = 0.0
        if quota.max_bytes:
            pct = min(100.0, 100.0 * quota.used_bytes / quota.max_bytes)
        quotas.append(
            {
                'company_id': quota.company_id,
                'used_bytes': quota.used_bytes,
                'max_bytes': quota.max_bytes,
                'used_display': human_bytes(quota.used_bytes),
                'max_display': human_bytes(quota.max_bytes),
                'pct': round(pct, 1),
            }
        )

    recent = list(objects.select_related('bucket').order_by('-created_at')[:recent_limit])
    recent_rows = [
        {
            'id': str(obj.id),
            'name': obj.name,
            'basename': obj.basename,
            'bucket': obj.bucket.name,
            'company_id': obj.company_id,
            'owner_id': obj.owner_id,
            'mime_type': obj.mime_type,
            'size': obj.size,
            'size_display': human_bytes(obj.size),
            'created_at': _iso(obj.created_at),
            'is_document': _is_document(obj.mime_type),
        }
        for obj in recent
    ]

    return {
        'scope_company_id': company_id,
        'object_count': object_count,
        'total_bytes': total_bytes,
        'total_bytes_display': human_bytes(total_bytes),
        'bucket_count': buckets.count(),
        'company_count': objects.values('company_id').distinct().count(),
        'document_count': doc_agg['count'] or 0,
        'document_bytes': doc_agg['bytes'] or 0,
        'document_bytes_display': human_bytes(doc_agg['bytes'] or 0),
        'uploads_24h': uploads_24h,
        'uploads_7d': uploads_7d,
        'uploads_30d': uploads_30d,
        'bytes_7d': bytes_7d,
        'bytes_7d_display': human_bytes(bytes_7d),
        'by_company': by_company,
        'by_bucket': by_bucket,
        'by_mime': top_mime,
        'by_family': by_family,
        'quotas': quotas,
        'daily_series': daily_series,
        'recent': recent_rows,
        'generated_at': _iso(now),
    }
