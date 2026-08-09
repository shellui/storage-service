"""Capability share links for anonymous, time- or download-limited access."""

from __future__ import annotations

from datetime import datetime

from django.db import transaction
from django.db.models import F
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .access import assert_can_access_path, get_accessible_bucket
from .mime import safe_object_path
from .models import ObjectShareLink, StorageObject
from .services import StorageError


def _parse_expires_at(value) -> datetime | None:
    if value in (None, ''):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = parse_datetime(str(value))
        if dt is None:
            raise StorageError(
                'expires_at must be an ISO-8601 datetime.',
                status=400,
                code='invalid_expires_at',
            )
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    return dt


def serialize_share_link(link: ObjectShareLink, *, include_token: bool = False) -> dict:
    payload = {
        'id': str(link.id),
        'object_id': str(link.object_id),
        'bucket': link.object.bucket.name,
        'path': link.object.name,
        'company_id': link.company_id,
        'created_by_id': link.created_by_id,
        'expires_at': (
            link.expires_at.isoformat().replace('+00:00', 'Z') if link.expires_at else None
        ),
        'max_downloads': link.max_downloads,
        'download_count': link.download_count,
        'revoked_at': (
            link.revoked_at.isoformat().replace('+00:00', 'Z') if link.revoked_at else None
        ),
        'created_at': link.created_at.isoformat().replace('+00:00', 'Z'),
        'notes': link.notes or '',
        'active': link.is_active(),
        # Relative redeem path — frontend builds absolute URL. Never listed publicly.
        'path_url': f'/storage/v1/share/link/{link.token}',
    }
    if include_token:
        payload['token'] = link.token
    return payload


def create_share_link(
    *,
    principal,
    bucket_name: str,
    path: str,
    expires_at=None,
    max_downloads: int | None = None,
    notes: str = '',
) -> ObjectShareLink:
    bucket = get_accessible_bucket(principal, bucket_name)
    name = safe_object_path(path)
    obj = StorageObject.objects.filter(bucket=bucket, name=name).first()
    if not obj:
        raise StorageError('Object not found', status=404, code='object_not_found')

    # Creator must be able to read the object (and typically write to share it).
    assert_can_access_path(principal, bucket, name, write=True, object_id=str(obj.id))

    expires = _parse_expires_at(expires_at)
    if max_downloads is not None:
        max_downloads = int(max_downloads)
        if max_downloads < 1:
            raise StorageError(
                'max_downloads must be >= 1.',
                status=400,
                code='invalid_max_downloads',
            )

    if expires is None and max_downloads is None:
        raise StorageError(
            'Provide expires_at and/or max_downloads.',
            status=400,
            code='share_limit_required',
        )

    if expires is not None and expires <= timezone.now():
        raise StorageError(
            'expires_at must be in the future.',
            status=400,
            code='invalid_expires_at',
        )

    return ObjectShareLink.objects.create(
        object=obj,
        company_id=bucket.company_id,
        created_by_id=int(principal.user_id),
        expires_at=expires,
        max_downloads=max_downloads,
        notes=(notes or '')[:255],
    )


def list_share_links_for_object(*, principal, bucket_name: str, path: str) -> list[ObjectShareLink]:
    """List share links for an object. Not a public directory — requires write access."""
    bucket = get_accessible_bucket(principal, bucket_name)
    name = safe_object_path(path)
    obj = StorageObject.objects.filter(bucket=bucket, name=name).first()
    if not obj:
        raise StorageError('Object not found', status=404, code='object_not_found')
    assert_can_access_path(principal, bucket, name, write=True, object_id=str(obj.id))

    qs = ObjectShareLink.objects.filter(object=obj, company_id=bucket.company_id).select_related(
        'object', 'object__bucket'
    )
    # Creators see their links; company owners/staff see all for the object.
    if not (
        getattr(principal, 'is_company_owner', False) or getattr(principal, 'is_staff', False)
    ):
        qs = qs.filter(created_by_id=int(principal.user_id))
    return list(qs)


def revoke_share_link(*, principal, token: str) -> ObjectShareLink:
    try:
        link = ObjectShareLink.objects.select_related('object', 'object__bucket').get(token=token)
    except ObjectShareLink.DoesNotExist as exc:
        raise StorageError('Share link not found', status=404, code='share_not_found') from exc

    company_id = getattr(principal, 'company_id', None)
    if company_id is None or int(link.company_id) != int(company_id):
        raise StorageError('Share link not found', status=404, code='share_not_found')

    is_creator = int(link.created_by_id) == int(principal.user_id)
    is_admin = bool(
        getattr(principal, 'is_company_owner', False) or getattr(principal, 'is_staff', False)
    )
    if not (is_creator or is_admin):
        raise StorageError(
            'You cannot revoke this share link.',
            status=403,
            code='share_revoke_denied',
        )

    if link.revoked_at is None:
        link.revoked_at = timezone.now()
        link.save(update_fields=['revoked_at'])
    return link


@transaction.atomic
def redeem_share_link(token: str) -> tuple[ObjectShareLink, StorageObject]:
    """
    Validate a share token and consume one download if capped.

    No authentication required. Does not enumerate or advertise other links.
    """
    try:
        link = (
            ObjectShareLink.objects.select_for_update()
            .select_related('object', 'object__bucket')
            .get(token=token)
        )
    except ObjectShareLink.DoesNotExist as exc:
        raise StorageError('Share link not found', status=404, code='share_not_found') from exc

    if not link.is_active():
        raise StorageError(
            'Share link is expired, exhausted, or revoked.',
            status=410,
            code='share_inactive',
        )

    ObjectShareLink.objects.filter(pk=link.pk).update(download_count=F('download_count') + 1)
    link.refresh_from_db(fields=['download_count'])

    obj = link.object
    obj.last_accessed_at = timezone.now()
    obj.save(update_fields=['last_accessed_at'])
    return link, obj
