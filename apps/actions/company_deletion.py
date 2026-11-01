"""Company deletion asked by identity-service.

identity-service posts ``/api/v1/internal/company-deletions`` with a short-lived assertion it
signs with its JWT key (audience ``shellui-company-deletion``, scope ``company.delete``). That
assertion is never accepted as a user token, and a user token is never accepted here.

The view only flags the company (``CompanyDeletion``). The Celery task
``actions.purge_deleted_companies`` runs every 60 seconds and deletes every row whose
``company_id`` matches, after removing the company's files from storage (S3 or disk). The
flag stays for ``SWEEP_WINDOW`` after the purge, so data written with a token issued just
before the deletion is swept too, then the flag itself is removed. Every step is idempotent.
"""

from __future__ import annotations

import logging
import time
from datetime import timedelta

import jwt
from django.apps import apps as django_apps
from django.conf import settings
from django.db import transaction
from django.db.models import ProtectedError
from django.utils import timezone

logger = logging.getLogger(__name__)

DELETION_AUDIENCE = 'shellui-company-deletion'
DELETION_SCOPE = 'company.delete'
MAX_LIFETIME = 120
SWEEP_WINDOW = timedelta(hours=1)


class DeletionAssertionError(Exception):
    pass


def verify_deletion_assertion(raw: str) -> int:
    """Return the company id from a valid identity-service deletion assertion."""
    from apps.authapi.jwks_client import get_jwks_client

    options = {'require': ['exp', 'iat', 'aud', 'company_id'], 'verify_iss': bool(settings.IDENTITY_ISSUER)}
    kwargs = {'audience': DELETION_AUDIENCE, 'options': options}
    if settings.IDENTITY_ISSUER:
        kwargs['issuer'] = settings.IDENTITY_ISSUER
    claims = None
    try:
        key = get_jwks_client().get_signing_key(raw)
        if key is not None:
            claims = jwt.decode(raw, key=key.key, algorithms=['RS256'], **kwargs)
    except Exception as exc:  # noqa: BLE001
        secret = getattr(settings, 'JWT_HS256_FALLBACK_SECRET', None)
        if not (secret and (settings.DEBUG or getattr(settings, 'ALLOW_JWT_HS256_FALLBACK', False))):
            raise DeletionAssertionError('Assertion was rejected.') from exc
        try:
            claims = jwt.decode(raw, key=secret, algorithms=['HS256'], **kwargs)
        except jwt.InvalidTokenError as inner:
            raise DeletionAssertionError('Assertion was rejected.') from inner
    if claims is None:
        raise DeletionAssertionError('Assertion was rejected.')
    if claims.get('scope') != DELETION_SCOPE:
        raise DeletionAssertionError('Assertion scope must be company.delete.')
    if int(claims['exp']) - int(claims['iat']) > MAX_LIFETIME:
        raise DeletionAssertionError('Assertion lifetime is too long.')
    company_id = claims.get('company_id')
    if not isinstance(company_id, int) or isinstance(company_id, bool) or company_id <= 0:
        raise DeletionAssertionError('Assertion has no valid company_id.')
    return company_id


def flag_company_deletion(company_id: int):
    from apps.actions.models import CompanyDeletion

    row, _ = CompanyDeletion.objects.get_or_create(company_id=company_id)
    if row.completed_at is not None:
        # Asked again: sweep once more and keep the flag a little longer.
        CompanyDeletion.objects.filter(pk=row.pk).update(completed_at=None)
    return row


def company_scoped_models() -> list:
    from apps.actions.models import CompanyDeletion

    found = []
    for model in django_apps.get_models():
        if not model.__module__.startswith('apps.') or model is CompanyDeletion:
            continue
        if model._meta.proxy or not model._meta.managed:
            continue
        if any(f.concrete and f.name == 'company_id' for f in model._meta.get_fields()):
            found.append(model)
    return found


def delete_company_rows(company_id: int) -> int:
    """Delete every row tied to ``company_id``. PROTECT order issues resolve over a few passes."""
    remaining = company_scoped_models()
    deleted = 0
    for _attempt in range(len(remaining) + 1):
        blocked = []
        for model in remaining:
            try:
                with transaction.atomic():
                    count, _ = model._base_manager.filter(company_id=company_id).delete()
                deleted += count
            except ProtectedError:
                blocked.append(model)
        if not blocked:
            return deleted
        remaining = blocked
    raise RuntimeError(f'Could not delete rows for company={company_id}: {[m.__name__ for m in remaining]}')


def _blob_hook():
    from django.utils.module_loading import import_string

    path = getattr(settings, 'COMPANY_DELETION_BLOB_HOOK', '')
    return import_string(path) if path else None


def purge_company(company_id: int) -> int:
    hook = _blob_hook()
    if hook is not None:
        hook(company_id)
    return delete_company_rows(company_id)


def purge_deleted_companies(*, max_seconds: float = 50, now=None) -> dict:
    from apps.actions.models import CompanyDeletion

    now = now or timezone.now()
    deadline = time.monotonic() + max_seconds
    purged = failed = released = 0
    for row in CompanyDeletion.objects.order_by('requested_at'):
        if time.monotonic() > deadline:
            break
        if row.completed_at is not None and row.completed_at < now - SWEEP_WINDOW:
            row.delete()
            released += 1
            continue
        try:
            purge_company(row.company_id)
        except Exception:
            logger.exception('company deletion: purge failed for company=%s, retrying next run', row.company_id)
            failed += 1
            continue
        if row.completed_at is None:
            CompanyDeletion.objects.filter(pk=row.pk).update(completed_at=now)
            purged += 1
    return {'purged': purged, 'failed': failed, 'released': released}
