"""Quota enforcement for company totals and optional per-user caps."""

from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings
from django.db import transaction
from django.db.models import F

from .models import CompanyQuota, UserQuota


class QuotaExceeded(Exception):
    def __init__(self, message: str, *, code: str = 'quota_exceeded'):
        super().__init__(message)
        self.code = code


@dataclass
class QuotaSnapshot:
    company_id: int
    company_max: int
    company_used: int
    user_id: int | None
    user_max: int | None
    user_used: int


def get_or_create_company_quota(company_id: int) -> CompanyQuota:
    quota, _created = CompanyQuota.objects.get_or_create(
        company_id=company_id,
        defaults={
            'max_bytes': settings.DEFAULT_COMPANY_QUOTA_BYTES,
            'max_bytes_per_user': settings.DEFAULT_USER_QUOTA_BYTES or None,
            'used_bytes': 0,
        },
    )
    return quota


def resolve_user_limit(company_quota: CompanyQuota, user_id: int | None) -> tuple[int | None, UserQuota | None]:
    if user_id is None:
        return None, None
    try:
        user_quota = UserQuota.objects.get(company_id=company_quota.company_id, user_id=user_id)
        return user_quota.max_bytes, user_quota
    except UserQuota.DoesNotExist:
        pass
    default = company_quota.max_bytes_per_user
    if default is None or default <= 0:
        return None, None
    return default, None


def snapshot(company_id: int, user_id: int | None = None) -> QuotaSnapshot:
    company = get_or_create_company_quota(company_id)
    user_max, user_row = resolve_user_limit(company, user_id)
    user_used = user_row.used_bytes if user_row else 0
    if user_row is None and user_id is not None and user_max:
        # No UserQuota row yet — usage tracked only after first upload adjustment.
        user_used = 0
    return QuotaSnapshot(
        company_id=company_id,
        company_max=company.max_bytes,
        company_used=company.used_bytes,
        user_id=user_id,
        user_max=user_max,
        user_used=user_used,
    )


def assert_can_store(
    *,
    company_id: int,
    user_id: int | None,
    additional_bytes: int,
    replacing_bytes: int = 0,
) -> None:
    """Raise QuotaExceeded if adding ``additional_bytes`` (net of replacement) would overflow."""
    if additional_bytes < 0:
        raise ValueError('additional_bytes must be >= 0')
    delta = additional_bytes - replacing_bytes
    if delta <= 0:
        return

    company = get_or_create_company_quota(company_id)
    if company.max_bytes and company.used_bytes + delta > company.max_bytes:
        raise QuotaExceeded(
            f'Company quota exceeded ({company.used_bytes + delta} > {company.max_bytes} bytes).',
            code='company_quota_exceeded',
        )

    user_max, user_row = resolve_user_limit(company, user_id)
    if user_max:
        used = user_row.used_bytes if user_row else 0
        if used + delta > user_max:
            raise QuotaExceeded(
                f'User quota exceeded ({used + delta} > {user_max} bytes).',
                code='user_quota_exceeded',
            )


@transaction.atomic
def apply_usage_delta(*, company_id: int, user_id: int | None, delta: int) -> None:
    """Adjust used_bytes counters. ``delta`` may be negative on delete."""
    if delta == 0:
        return

    company = get_or_create_company_quota(company_id)
    CompanyQuota.objects.filter(pk=company.pk).update(
        used_bytes=F('used_bytes') + delta,
    )
    # Clamp floor at 0
    CompanyQuota.objects.filter(pk=company.pk, used_bytes__lt=0).update(used_bytes=0)

    if user_id is None:
        return

    user_max, user_row = resolve_user_limit(company, user_id)
    if user_row is None:
        if user_max is None and delta <= 0:
            return
        # Create a tracking row when a per-user limit exists or we need to track usage.
        if user_max is None:
            # No limit configured — still track usage for reporting if row exists later.
            return
        user_row, _ = UserQuota.objects.get_or_create(
            company_id=company_id,
            user_id=user_id,
            defaults={'max_bytes': user_max, 'used_bytes': 0},
        )

    UserQuota.objects.filter(pk=user_row.pk).update(used_bytes=F('used_bytes') + delta)
    UserQuota.objects.filter(pk=user_row.pk, used_bytes__lt=0).update(used_bytes=0)
