"""Storage key helpers and backend introspection."""

from __future__ import annotations

import hashlib
import logging
import uuid
from pathlib import Path, PurePosixPath

from django.conf import settings
from django.core.files.storage import default_storage

logger = logging.getLogger(__name__)


def build_storage_key(*, company_id: int, bucket_name: str, object_name: str, object_id: uuid.UUID) -> str:
    """
    Physical key in S3 / filesystem.

    Layout: ``{prefix}/{company_id}/{bucket}/{uuid}/{basename}``
    Keeps user-facing paths in DB metadata while avoiding collisions on rename.
    """
    prefix = settings.STORAGE_KEY_PREFIX
    basename = PurePosixPath(object_name).name or 'blob'
    parts = [p for p in (prefix, str(company_id), bucket_name, str(object_id), basename) if p]
    return '/'.join(parts)


def content_etag(data: bytes) -> str:
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def stream_etag(fileobj, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
    digest = hashlib.md5(usedforsecurity=False)
    total = 0
    while True:
        chunk = fileobj.read(chunk_size)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    return digest.hexdigest(), total


def is_s3_backend() -> bool:
    return settings.STORAGE_BACKEND == 's3'


def storage_exists(key: str) -> bool:
    return default_storage.exists(key)


def delete_storage_key(key: str) -> None:
    """Delete a blob and prune empty parent directories on the filesystem backend."""
    if default_storage.exists(key):
        default_storage.delete(key)
    prune_empty_parent_dirs(key)


def prune_empty_parent_dirs(key: str) -> None:
    """
    After deleting ``key``, remove empty parent directories up to (but not including)
    the storage root. No-op for S3 (prefixes are virtual).
    """
    if is_s3_backend():
        return

    location = getattr(default_storage, 'location', None)
    if not location:
        return

    try:
        root = Path(location).resolve()
    except OSError:
        return

    # Walk from the deleted file's parent toward the storage root.
    current = (root / key).parent
    while True:
        try:
            resolved = current.resolve()
        except OSError:
            break
        try:
            resolved.relative_to(root)
        except ValueError:
            break
        if resolved == root:
            break
        try:
            if any(current.iterdir()):
                break
            current.rmdir()
        except OSError as exc:
            logger.debug('Could not prune empty dir %s: %s', current, exc)
            break
        current = current.parent
