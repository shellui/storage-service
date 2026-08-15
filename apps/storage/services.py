"""Core object/bucket operations shared by REST and WebDAV."""

from __future__ import annotations

import uuid
from typing import BinaryIO

from django.conf import settings
from django.core.files.base import ContentFile, File
from django.core.files.storage import default_storage
from django.db import transaction
from django.db.models import Count, Q, Sum
from django.utils import timezone

from .access import access_summary, path_access_summary
from .backends import build_storage_key, content_etag, delete_storage_key
from .mime import mime_allowed, normalize_mime_type, safe_object_path
from .models import Bucket, StorageAccessGrant, StorageObject
from .quotas import QuotaExceeded, assert_can_store, apply_usage_delta
from .signals import storage_object_deleted, storage_object_uploaded

FOLDER_PLACEHOLDER_NAME = '.emptyFolderPlaceholder'


class StorageError(Exception):
    def __init__(self, message: str, *, status: int = 400, code: str = 'storage_error'):
        super().__init__(message)
        self.status = status
        self.code = code


def require_company_id(principal) -> int:
    company_id = getattr(principal, 'company_id', None)
    if company_id is None:
        raise StorageError('JWT is missing company_id.', status=403, code='missing_company')
    return int(company_id)


def get_bucket_for_company(company_id: int, name: str) -> Bucket:
    """Internal lookup by company + name (no ACL). Prefer get_accessible_bucket in request paths."""
    try:
        return Bucket.objects.get(company_id=company_id, name=name)
    except Bucket.DoesNotExist as exc:
        raise StorageError('Bucket not found', status=404, code='bucket_not_found') from exc


def serialize_bucket(bucket: Bucket, *, principal=None) -> dict:
    from .access import access_summary, can_access_bucket, display_name_for_bucket

    access = access_summary(bucket)
    can_write = bool(principal and can_access_bucket(principal, bucket, write=True))
    return {
        'id': bucket.name,
        'name': bucket.name,
        'display_name': display_name_for_bucket(bucket),
        'kind': bucket.kind,
        'owner': str(bucket.owner_id) if bucket.owner_id else None,
        'public': False,
        'file_size_limit': bucket.file_size_limit,
        'allowed_mime_types': bucket.allowed_mime_types or None,
        'connector_provider': bucket.connector_provider or None,
        'access': {
            **access,
            'can_write': can_write if principal is not None else access['writers'] != 'none',
        },
        'created_at': bucket.created_at.isoformat().replace('+00:00', 'Z'),
        'updated_at': bucket.updated_at.isoformat().replace('+00:00', 'Z'),
    }


def serialize_object(
    obj: StorageObject,
    *,
    include_folder_placeholder: bool = False,
    access: dict | None = None,
    grants=None,
) -> dict:
    payload = {
        'id': str(obj.id),
        'name': obj.basename if include_folder_placeholder else obj.name,
        'bucket_id': obj.bucket.name,
        'owner': str(obj.owner_id) if obj.owner_id else None,
        'created_at': obj.created_at.isoformat().replace('+00:00', 'Z'),
        'updated_at': obj.updated_at.isoformat().replace('+00:00', 'Z'),
        'last_accessed_at': (
            obj.last_accessed_at.isoformat().replace('+00:00', 'Z') if obj.last_accessed_at else None
        ),
        'metadata': {
            'eTag': f'"{obj.etag}"' if obj.etag else None,
            'size': obj.size,
            'mimetype': obj.mime_type,
            'cacheControl': (obj.metadata or {}).get('cacheControl', 'max-age=3600'),
            'lastModified': obj.updated_at.isoformat().replace('+00:00', 'Z'),
            'contentLength': obj.size,
            'httpStatusCode': 200,
            **{k: v for k, v in (obj.metadata or {}).items() if k not in {'cacheControl'}},
        },
    }
    if access is not None:
        payload['access'] = access
    else:
        payload['access'] = path_access_summary(
            obj.bucket,
            path=obj.name,
            object_id=str(obj.id),
            grants=grants,
        )
    return payload


def list_objects(
    bucket: Bucket,
    *,
    prefix: str = '',
    limit: int = 100,
    offset: int = 0,
    search: str = '',
    sort_column: str = 'name',
    sort_order: str = 'asc',
    principal=None,
) -> list[dict]:
    """
    Supabase-compatible listing with folder placeholders.

    Returns files under ``prefix`` (non-recursive) plus synthetic folder entries
    (``id: null``) for immediate child directories.

    When ``principal`` is provided, entries the principal cannot read are omitted.
    """
    from .access import active_grants_for_company, can_access_path

    prefix = (prefix or '').strip('/')
    if prefix:
        prefix = prefix + '/'

    qs = StorageObject.objects.filter(bucket=bucket, name__startswith=prefix)
    if search:
        qs = qs.filter(name__icontains=search)

    files: list[StorageObject] = []
    folders: set[str] = set()
    folder_ids: dict[str, str] = {}

    for obj in qs.iterator(chunk_size=500):
        if principal is not None and not can_access_path(
            principal, bucket, obj.name, object_id=str(obj.id)
        ):
            continue
        rest = obj.name[len(prefix) :]
        if not rest:
            continue
        if '/' in rest:
            folder_name, remainder = rest.split('/', 1)
            folders.add(folder_name)
            if remainder == FOLDER_PLACEHOLDER_NAME:
                folder_ids[folder_name] = str(obj.id)
        else:
            files.append(obj)

    sort_column = sort_column if sort_column in {'name', 'updated_at', 'created_at'} else 'name'
    reverse = sort_order.lower() == 'desc'

    # One grant fetch for the whole listing — path_access_summary filters in memory.
    grants = active_grants_for_company(int(bucket.company_id))

    folder_entries = [
        {
            'id': None,
            'folder_id': folder_ids.get(name),
            'name': name,
            'bucket_id': bucket.name,
            'owner': None,
            'created_at': None,
            'updated_at': None,
            'last_accessed_at': None,
            'metadata': None,
            'access': path_access_summary(
                bucket,
                path=f'{prefix}{name}'.strip('/'),
                grants=grants,
            ),
        }
        for name in folders
    ]

    file_entries = [
        serialize_object(o, include_folder_placeholder=True, grants=grants) for o in files
    ]

    def sort_key(item):
        if sort_column == 'name':
            return (item.get('name') or '').lower()
        return item.get(sort_column) or ''

    folder_entries.sort(key=sort_key, reverse=reverse)
    file_entries.sort(key=sort_key, reverse=reverse)
    combined = folder_entries + file_entries
    return combined[offset : offset + limit]


def _read_upload_bytes(fileobj: BinaryIO | File, max_bytes: int) -> bytes:
    data = fileobj.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise StorageError(
            f'Upload exceeds maximum size of {max_bytes} bytes.',
            status=413,
            code='payload_too_large',
        )
    return data


@transaction.atomic
def upload_object(
    *,
    bucket: Bucket,
    path: str,
    fileobj: BinaryIO | File,
    owner_id: int | None,
    content_type: str | None = None,
    upsert: bool = False,
    metadata: dict | None = None,
    cache_control: str | None = None,
    request=None,
) -> StorageObject:
    object_name = safe_object_path(path)
    mime = normalize_mime_type(content_type, object_name)

    if not mime_allowed(mime, bucket.allowed_mime_types):
        raise StorageError(
            f'MIME type {mime!r} is not allowed for this bucket.',
            status=415,
            code='invalid_mime_type',
        )

    existing = StorageObject.objects.select_for_update().filter(bucket=bucket, name=object_name).first()
    if existing and not upsert:
        raise StorageError('The resource already exists', status=400, code='resource_already_exists')

    max_bytes = bucket.file_size_limit or settings.MAX_UPLOAD_BYTES
    max_bytes = min(max_bytes, settings.MAX_UPLOAD_BYTES)
    data = _read_upload_bytes(fileobj, max_bytes)
    size = len(data)

    replacing = existing.size if existing else 0
    try:
        assert_can_store(
            company_id=bucket.company_id,
            user_id=owner_id,
            additional_bytes=size,
            replacing_bytes=replacing,
        )
    except QuotaExceeded as exc:
        raise StorageError(str(exc), status=413, code=exc.code) from exc

    etag = content_etag(data)
    meta = dict(metadata or {})
    if cache_control:
        meta['cacheControl'] = cache_control

    if existing:
        old_key = existing.storage_key
        default_storage.save(old_key, ContentFile(data))
        delta = size - replacing
        existing.size = size
        existing.etag = etag
        existing.mime_type = mime
        existing.metadata = meta
        existing.version += 1
        existing.updated_at = timezone.now()
        if owner_id is not None:
            existing.owner_id = owner_id
        existing.save()
        apply_usage_delta(company_id=bucket.company_id, user_id=owner_id, delta=delta)
        storage_object_uploaded.send(
            sender=StorageObject,
            instance=existing,
            created=False,
            request=request,
        )
        return existing

    object_id = uuid.uuid4()
    storage_key = build_storage_key(
        company_id=bucket.company_id,
        bucket_name=bucket.name,
        object_name=object_name,
        object_id=object_id,
    )
    default_storage.save(storage_key, ContentFile(data))
    obj = StorageObject.objects.create(
        id=object_id,
        bucket=bucket,
        name=object_name,
        company_id=bucket.company_id,
        owner_id=owner_id,
        size=size,
        etag=etag,
        mime_type=mime,
        metadata=meta,
        storage_key=storage_key,
    )
    apply_usage_delta(company_id=bucket.company_id, user_id=owner_id, delta=size)
    from .access import apply_default_private_on_create

    apply_default_private_on_create(
        company_id=bucket.company_id,
        user_id=owner_id,
        bucket=bucket,
        path=object_name,
    )
    storage_object_uploaded.send(
        sender=StorageObject,
        instance=obj,
        created=True,
        request=request,
    )
    return obj


@transaction.atomic
def delete_object(obj: StorageObject, *, request=None) -> None:
    bucket_name = obj.bucket.name
    object_name = obj.name
    company_id = obj.company_id
    owner_id = obj.owner_id
    mime_type = obj.mime_type
    size = obj.size
    key = obj.storage_key
    obj.delete()
    delete_storage_key(key)
    apply_usage_delta(company_id=company_id, user_id=owner_id, delta=-size)
    storage_object_deleted.send(
        sender=StorageObject,
        bucket_name=bucket_name,
        object_name=object_name,
        company_id=company_id,
        owner_id=owner_id,
        mime_type=mime_type,
        size=size,
        request=request,
    )


@transaction.atomic
def delete_paths(bucket: Bucket, paths: list[str], *, request=None) -> list[str]:
    deleted: list[str] = []
    for raw in paths:
        try:
            name = safe_object_path(raw)
        except ValueError:
            continue
        obj = StorageObject.objects.filter(bucket=bucket, name=name).first()
        if not obj:
            continue
        delete_object(obj, request=request)
        deleted.append(name)
    return deleted


def resolve_item_by_id(principal, object_id: str) -> dict:
    """Resolve a file or folder from the stable picker id (object UUID)."""
    from .access import assert_can_access_path, display_name_for_bucket

    try:
        uid = uuid.UUID(str(object_id))
    except ValueError as exc:
        raise StorageError('Invalid object id', status=400, code='invalid_id') from exc

    obj = StorageObject.objects.select_related('bucket').filter(id=uid).first()
    if not obj:
        raise StorageError('Object not found', status=404, code='object_not_found')

    company_id = getattr(principal, 'company_id', None)
    if company_id is not None and int(obj.company_id) != int(company_id):
        raise StorageError('Object not found', status=404, code='object_not_found')

    assert_can_access_path(
        principal,
        obj.bucket,
        obj.name,
        object_id=str(obj.id),
    )

    name = obj.name
    is_placeholder = name == FOLDER_PLACEHOLDER_NAME or name.endswith(f'/{FOLDER_PLACEHOLDER_NAME}')
    if is_placeholder:
        folder_path = (
            '' if name == FOLDER_PLACEHOLDER_NAME else name[: -(len(FOLDER_PLACEHOLDER_NAME) + 1)]
        )
        folder_name = (
            folder_path.rsplit('/', 1)[-1] if folder_path else display_name_for_bucket(obj.bucket)
        )
        return {
            'id': str(obj.id),
            'bucket': obj.bucket.name,
            'path': folder_path,
            'name': folder_name,
            'type': 'folder',
        }
    return {
        'id': str(obj.id),
        'bucket': obj.bucket.name,
        'path': name,
        'name': obj.basename,
        'type': 'file',
    }


def _prefix_filter(folder_path: str) -> str:
    prefix = (folder_path or '').strip('/')
    if prefix:
        prefix = prefix + '/'
    return prefix


def objects_under_prefix(bucket: Bucket, folder_path: str):
    """All stored objects under a folder path (prefix), including placeholder markers."""
    return StorageObject.objects.filter(bucket=bucket, name__startswith=_prefix_filter(folder_path))


def summarize_prefix(bucket: Bucket, folder_path: str) -> dict:
    """
    Stats for objects under a folder prefix.

    ``file_count`` excludes empty-folder placeholders so the UI can report how many
    real files will be removed.
    """
    qs = objects_under_prefix(bucket, folder_path)
    totals = qs.aggregate(object_count=Count('id'), total_bytes=Sum('size'))
    object_count = totals['object_count'] or 0
    total_bytes = totals['total_bytes'] or 0
    placeholder_count = 0
    for name in qs.values_list('name', flat=True):
        if name == FOLDER_PLACEHOLDER_NAME or name.endswith(f'/{FOLDER_PLACEHOLDER_NAME}'):
            placeholder_count += 1
    file_count = max(0, object_count - placeholder_count)
    return {
        'prefix': (folder_path or '').strip('/'),
        'object_count': object_count,
        'file_count': file_count,
        'placeholder_count': placeholder_count,
        'total_bytes': total_bytes,
    }


@transaction.atomic
def delete_under_prefix(bucket: Bucket, folder_path: str, *, request=None) -> list[str]:
    """Delete every object under a folder prefix (recursive folder delete)."""
    objs = list(objects_under_prefix(bucket, folder_path))
    deleted: list[str] = []
    for obj in objs:
        name = obj.name
        delete_object(obj, request=request)
        deleted.append(name)
    return deleted


def _rewrite_grants_for_prefix_rename(
    *,
    company_id: int,
    bucket_name: str,
    old_prefix: str,
    new_prefix: str,
) -> int:
    """Update folder/object grants whose resource_id is the renamed prefix or under it."""
    old_prefix = (old_prefix or '').strip('/')
    new_prefix = (new_prefix or '').strip('/')
    if not old_prefix or old_prefix == new_prefix:
        return 0

    qs = StorageAccessGrant.objects.filter(
        company_id=company_id,
        resource_type__in={
            StorageAccessGrant.ResourceType.FOLDER,
            StorageAccessGrant.ResourceType.OBJECT,
        },
    ).filter(Q(bucket_name=bucket_name) | Q(bucket_name=''))

    updated = 0
    for grant in qs:
        rid = (grant.resource_id or '').strip().strip('/')
        if not rid:
            continue
        if rid == old_prefix:
            grant.resource_id = new_prefix
            grant.save(update_fields=['resource_id', 'updated_at'])
            updated += 1
        elif rid.startswith(old_prefix + '/'):
            grant.resource_id = new_prefix + rid[len(old_prefix) :]
            grant.save(update_fields=['resource_id', 'updated_at'])
            updated += 1
    return updated


@transaction.atomic
def rename_folder(
    *,
    bucket: Bucket,
    source_path: str,
    dest_path: str,
) -> dict:
    """
    Rename/move a virtual folder by rewriting every object name under the prefix.

    Also rewrites folder/object access grants that target the old prefix.
    """
    src = safe_object_path(source_path).strip('/')
    dst = safe_object_path(dest_path).strip('/')
    if not src or not dst:
        raise StorageError('from and to folder paths are required', status=400, code='invalid_prefix')
    if src == dst:
        return {'from': src, 'to': dst, 'moved': 0, 'grants_updated': 0}
    if dst.startswith(src + '/'):
        raise StorageError(
            'Cannot rename a folder into itself.',
            status=400,
            code='invalid_destination',
        )

    objs = list(objects_under_prefix(bucket, src).select_for_update().order_by('name'))
    if not objs:
        raise StorageError('Folder not found', status=404, code='folder_not_found')

    if objects_under_prefix(bucket, dst).exists() or StorageObject.objects.filter(
        bucket=bucket, name=dst
    ).exists():
        raise StorageError(
            'A folder or file already exists at the destination.',
            status=400,
            code='resource_already_exists',
        )

    # Rename deepest paths first so unique name constraints never collide mid-pass.
    objs.sort(key=lambda o: o.name.count('/'), reverse=True)

    moved: list[str] = []
    for obj in objs:
        if not obj.name.startswith(src + '/'):
            continue
        new_name = dst + obj.name[len(src) :]
        if StorageObject.objects.filter(bucket=bucket, name=new_name).exclude(pk=obj.pk).exists():
            raise StorageError(
                'A folder or file already exists at the destination.',
                status=400,
                code='resource_already_exists',
            )
        obj.name = new_name
        obj.updated_at = timezone.now()
        obj.save(update_fields=['name', 'updated_at'])
        moved.append(new_name)

    grants_updated = _rewrite_grants_for_prefix_rename(
        company_id=int(bucket.company_id),
        bucket_name=bucket.name,
        old_prefix=src,
        new_prefix=dst,
    )
    return {
        'from': src,
        'to': dst,
        'moved': len(moved),
        'grants_updated': grants_updated,
    }


@transaction.atomic
def move_object(
    *,
    bucket: Bucket,
    source_path: str,
    dest_bucket: Bucket,
    dest_path: str,
    request=None,
) -> StorageObject:
    source_name = safe_object_path(source_path)
    dest_name = safe_object_path(dest_path)
    obj = StorageObject.objects.select_for_update().filter(bucket=bucket, name=source_name).first()
    if not obj:
        raise StorageError('Object not found', status=404, code='object_not_found')
    if StorageObject.objects.filter(bucket=dest_bucket, name=dest_name).exists():
        raise StorageError('Destination already exists', status=400, code='resource_already_exists')

    if bucket.pk == dest_bucket.pk:
        obj.name = dest_name
        obj.updated_at = timezone.now()
        obj.save(update_fields=['name', 'updated_at'])
        return obj

    # Cross-bucket: adjust quotas if companies differ (they shouldn't in our tenancy model).
    if bucket.company_id != dest_bucket.company_id:
        raise StorageError('Cannot move across companies.', status=403, code='forbidden')

    obj.bucket = dest_bucket
    obj.name = dest_name
    obj.updated_at = timezone.now()
    obj.save(update_fields=['bucket', 'name', 'updated_at'])
    return obj


@transaction.atomic
def copy_object(
    *,
    bucket: Bucket,
    source_path: str,
    dest_bucket: Bucket,
    dest_path: str,
    owner_id: int | None,
    request=None,
) -> StorageObject:
    source_name = safe_object_path(source_path)
    dest_name = safe_object_path(dest_path)
    src = StorageObject.objects.filter(bucket=bucket, name=source_name).first()
    if not src:
        raise StorageError('Object not found', status=404, code='object_not_found')
    if StorageObject.objects.filter(bucket=dest_bucket, name=dest_name).exists():
        raise StorageError('Destination already exists', status=400, code='resource_already_exists')
    if bucket.company_id != dest_bucket.company_id:
        raise StorageError('Cannot copy across companies.', status=403, code='forbidden')

    try:
        assert_can_store(
            company_id=dest_bucket.company_id,
            user_id=owner_id,
            additional_bytes=src.size,
        )
    except QuotaExceeded as exc:
        raise StorageError(str(exc), status=413, code=exc.code) from exc

    with default_storage.open(src.storage_key, 'rb') as fh:
        data = fh.read()

    object_id = uuid.uuid4()
    storage_key = build_storage_key(
        company_id=dest_bucket.company_id,
        bucket_name=dest_bucket.name,
        object_name=dest_name,
        object_id=object_id,
    )
    default_storage.save(storage_key, ContentFile(data))
    obj = StorageObject.objects.create(
        id=object_id,
        bucket=dest_bucket,
        name=dest_name,
        company_id=dest_bucket.company_id,
        owner_id=owner_id if owner_id is not None else src.owner_id,
        size=src.size,
        etag=src.etag,
        mime_type=src.mime_type,
        metadata=dict(src.metadata or {}),
        storage_key=storage_key,
    )
    apply_usage_delta(company_id=dest_bucket.company_id, user_id=obj.owner_id, delta=src.size)
    from .access import apply_default_private_on_create

    apply_default_private_on_create(
        company_id=dest_bucket.company_id,
        user_id=obj.owner_id,
        bucket=dest_bucket,
        path=dest_name,
    )
    storage_object_uploaded.send(
        sender=StorageObject,
        instance=obj,
        created=True,
        request=request,
    )
    return obj


def create_bucket(
    *,
    company_id: int,
    name: str,
    public: bool = False,
    file_size_limit: int | None = None,
    allowed_mime_types: list | None = None,
    owner_id: int | None = None,
) -> Bucket:
    """
    Deprecated for API use. Arbitrary bucket creation is disabled.

    Prefer ``ensure_company_bucket`` / ``list_accessible_buckets``.
    """
    raise StorageError(
        'Creating custom buckets is disabled. Use the company bucket with access grants.',
        status=403,
        code='bucket_create_disabled',
    )
