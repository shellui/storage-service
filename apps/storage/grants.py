"""CRUD helpers for StorageAccessGrant."""

from __future__ import annotations

import uuid
from datetime import datetime

from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .access import (
    COMPANY_BUCKET_NAME,
    assert_can_access_bucket,
    assert_can_access_path,
    assert_can_open_to_company,
    get_accessible_bucket,
    serialize_grant,
)
from .models import StorageAccessGrant, folder_placeholder_path
from .services import StorageError, ensure_folder_marker, require_company_id


def _resolve_object(bucket, resource_id: str):
    from .models import StorageObject

    try:
        uid = uuid.UUID(resource_id)
    except ValueError:
        uid = None
    if uid is not None:
        obj = StorageObject.objects.filter(bucket=bucket, id=uid).first()
        if obj:
            return obj
    obj = StorageObject.objects.filter(bucket=bucket, name=resource_id).first()
    if not obj:
        raise StorageError('Object not found', status=404, code='object_not_found')
    return obj


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


def _normalize_resource_id(resource_type: str, resource_id: str) -> str:
    rid = (resource_id or '').strip().strip('/')
    if resource_type == StorageAccessGrant.ResourceType.BUCKET and not rid:
        raise StorageError(
            'resource_id (bucket name) is required',
            status=400,
            code='invalid_resource',
        )
    if resource_type in {
        StorageAccessGrant.ResourceType.FOLDER,
        StorageAccessGrant.ResourceType.OBJECT,
    } and not rid:
        raise StorageError('resource_id is required', status=400, code='invalid_resource')
    return rid


def _is_company_admin(principal) -> bool:
    return bool(
        getattr(principal, 'is_company_owner', False) or getattr(principal, 'is_staff', False)
    )


def _assert_can_manage_resource(
    principal,
    *,
    bucket_name: str,
    resource_type: str,
    resource_path: str,
    admin: bool = False,
) -> None:
    # Owners/staff can always manage grants (needed after a company-wide deny).
    if _is_company_admin(principal):
        get_accessible_bucket(principal, bucket_name)
        return

    bucket = get_accessible_bucket(principal, bucket_name)
    if resource_type == StorageAccessGrant.ResourceType.BUCKET:
        assert_can_access_bucket(principal, bucket, write=not admin, admin=admin)
        return
    assert_can_access_path(principal, bucket, resource_path, write=not admin, admin=admin)


def create_grant(*, principal, data: dict) -> StorageAccessGrant:
    company_id = require_company_id(principal)
    subject_type = str(data.get('subject_type') or '').strip()
    subject_id = str(data.get('subject_id') or '').strip()
    resource_type = str(data.get('resource_type') or '').strip()
    resource_id = _normalize_resource_id(resource_type, str(data.get('resource_id') or ''))
    permission = str(data.get('permission') or StorageAccessGrant.Permission.READ).strip()
    effect = str(data.get('effect') or StorageAccessGrant.Effect.ALLOW).strip()
    notes = str(data.get('notes') or '')[:255]
    expires_at = _parse_expires_at(data.get('expires_at'))

    valid_subjects = {c.value for c in StorageAccessGrant.SubjectType}
    valid_resources = {c.value for c in StorageAccessGrant.ResourceType}
    valid_perms = {c.value for c in StorageAccessGrant.Permission}
    valid_effects = {c.value for c in StorageAccessGrant.Effect}

    if subject_type not in valid_subjects:
        raise StorageError('Invalid subject_type', status=400, code='invalid_subject_type')
    if not subject_id:
        raise StorageError('subject_id is required', status=400, code='invalid_subject_id')
    if resource_type not in valid_resources:
        raise StorageError('Invalid resource_type', status=400, code='invalid_resource_type')
    if permission not in valid_perms:
        raise StorageError('Invalid permission', status=400, code='invalid_permission')
    if effect not in valid_effects:
        raise StorageError('Invalid effect', status=400, code='invalid_effect')

    if resource_type == StorageAccessGrant.ResourceType.BUCKET:
        bucket_name = resource_id
    else:
        bucket_name = str(data.get('bucket') or COMPANY_BUCKET_NAME).strip() or COMPANY_BUCKET_NAME

    # Ensure the target bucket exists / is accessible at least for read.
    bucket = get_accessible_bucket(principal, bucket_name)

    need_admin = effect == StorageAccessGrant.Effect.DENY or permission == (
        StorageAccessGrant.Permission.ADMIN
    )
    _assert_can_manage_resource(
        principal,
        bucket_name=bucket_name,
        resource_type=resource_type,
        resource_path=resource_id,
        admin=need_admin,
    )

    # Company allow on a nested path would pierce a private parent folder.
    if (
        effect == StorageAccessGrant.Effect.ALLOW
        and subject_type == StorageAccessGrant.SubjectType.COMPANY
        and resource_type
        in {
            StorageAccessGrant.ResourceType.FOLDER,
            StorageAccessGrant.ResourceType.OBJECT,
        }
    ):
        assert_can_open_to_company(
            company_id=company_id,
            bucket_name=bucket_name,
            path=resource_id,
        )

    target = None
    if resource_type == StorageAccessGrant.ResourceType.OBJECT:
        target = _resolve_object(bucket, resource_id)
    elif resource_type == StorageAccessGrant.ResourceType.FOLDER:
        target = ensure_folder_marker(
            bucket,
            resource_id,
            owner_id=int(principal.user_id),
        )

    return StorageAccessGrant.objects.create(
        company_id=company_id,
        bucket=bucket,
        object=target,
        subject_type=subject_type,
        subject_id=subject_id,
        resource_type=resource_type,
        permission=permission,
        effect=effect,
        created_by_id=int(principal.user_id),
        expires_at=expires_at,
        notes=notes,
    )


def list_grants(
    *,
    principal,
    resource_type: str | None = None,
    resource_id: str | None = None,
    bucket: str | None = None,
) -> list[dict]:
    company_id = require_company_id(principal)
    qs = (
        StorageAccessGrant.objects.select_related('bucket', 'object')
        .filter(company_id=company_id)
        .order_by('-created_at')
    )
    if resource_type:
        qs = qs.filter(resource_type=resource_type)
    if bucket:
        qs = qs.filter(bucket__name=bucket)
    if resource_id:
        rid = resource_id.strip().strip('/')
        if resource_type == StorageAccessGrant.ResourceType.FOLDER:
            qs = qs.filter(object__name=folder_placeholder_path(rid))
        elif resource_type == StorageAccessGrant.ResourceType.OBJECT:
            object_q = Q(object__name=rid)
            try:
                object_q |= Q(object_id=uuid.UUID(rid))
            except ValueError:
                pass
            qs = qs.filter(object_q)
        elif resource_type == StorageAccessGrant.ResourceType.BUCKET:
            qs = qs.filter(bucket__name=rid, object__isnull=True)
        else:
            qs = qs.filter(
                Q(object__name=rid)
                | Q(object__name=folder_placeholder_path(rid))
                | Q(bucket__name=rid, object__isnull=True)
            )

    if not (
        getattr(principal, 'is_company_owner', False) or getattr(principal, 'is_staff', False)
    ):
        uid = str(int(principal.user_id))
        qs = qs.filter(
            Q(created_by_id=int(principal.user_id))
            | Q(subject_type=StorageAccessGrant.SubjectType.USER, subject_id=uid)
            | Q(
                subject_type=StorageAccessGrant.SubjectType.COMPANY,
                subject_id=str(company_id),
            )
        )
    return [serialize_grant(g) for g in qs]


def list_grants_effective(
    *,
    principal,
    resource_type: str | None = None,
    resource_id: str | None = None,
    bucket: str | None = None,
) -> dict:
    """
    List grants for a resource plus whether a private parent folder blocks
    opening this path to the company.
    """
    from .access import nearest_private_ancestor_folder

    company_id = require_company_id(principal)
    bucket_name = (bucket or COMPANY_BUCKET_NAME).strip() or COMPANY_BUCKET_NAME
    grants = list_grants(
        principal=principal,
        resource_type=resource_type,
        resource_id=resource_id,
        bucket=bucket,
    )
    private_ancestor = None
    path = (resource_id or '').strip().strip('/')
    if path:
        private_ancestor = nearest_private_ancestor_folder(
            company_id=company_id,
            bucket_name=bucket_name,
            path=path,
        )
    return {
        'grants': grants,
        'private_ancestor': private_ancestor,
    }


def delete_grant(*, principal, grant_id: str) -> None:
    company_id = require_company_id(principal)
    try:
        grant = StorageAccessGrant.objects.select_related('bucket', 'object').get(
            id=grant_id, company_id=company_id
        )
    except (StorageAccessGrant.DoesNotExist, ValueError) as exc:
        raise StorageError('Grant not found', status=404, code='grant_not_found') from exc

    is_admin = bool(
        getattr(principal, 'is_company_owner', False) or getattr(principal, 'is_staff', False)
    )
    is_creator = grant.created_by_id is not None and int(grant.created_by_id) == int(
        principal.user_id
    )
    if not (is_admin or is_creator):
        raise StorageError(
            'You cannot delete this grant.',
            status=403,
            code='grant_delete_denied',
        )

    bucket_name = grant.bucket.name
    resource_path = grant.resource_path()

    if not is_admin:
        _assert_can_manage_resource(
            principal,
            bucket_name=bucket_name,
            resource_type=grant.resource_type,
            resource_path=resource_path,
            admin=grant.effect == StorageAccessGrant.Effect.DENY,
        )

    # Removing a company deny (= "make public") under a private parent is a no-op
    # for other members and confuses the UI — require opening the parent first.
    if (
        grant.effect == StorageAccessGrant.Effect.DENY
        and grant.subject_type == StorageAccessGrant.SubjectType.COMPANY
        and grant.permission == StorageAccessGrant.Permission.READ
        and grant.resource_type
        in {
            StorageAccessGrant.ResourceType.FOLDER,
            StorageAccessGrant.ResourceType.OBJECT,
        }
    ):
        assert_can_open_to_company(
            company_id=company_id,
            bucket_name=bucket_name,
            path=resource_path,
        )

    grant.delete()
