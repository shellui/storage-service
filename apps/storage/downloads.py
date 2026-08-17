"""Build authenticated download responses.

Object bytes are always streamed through Django (``FileResponse``) so the
Files UI can open files same-origin with ``Authorization``. Signed URLs remain
available via ``POST /storage/v1/object/sign/...``.
"""

from __future__ import annotations

import mimetypes

from django.conf import settings
from django.core.files.storage import default_storage
from django.http import FileResponse, HttpResponse
from django.utils import timezone

from .backends import is_s3_backend
from .models import StorageObject


def build_download_response(
    obj: StorageObject,
    *,
    as_attachment: bool = False,
    filename: str | None = None,
) -> HttpResponse:
    StorageObject.objects.filter(pk=obj.pk).update(last_accessed_at=timezone.now())

    content_type = obj.mime_type or mimetypes.guess_type(obj.name)[0] or 'application/octet-stream'
    download_name = filename or obj.basename
    disposition_type = 'attachment' if as_attachment else 'inline'
    content_disposition = f'{disposition_type}; filename="{download_name}"'

    fh = default_storage.open(obj.storage_key, 'rb')
    response = FileResponse(fh, content_type=content_type)
    response['Content-Disposition'] = content_disposition
    response['Content-Length'] = str(obj.size)
    if obj.etag:
        response['ETag'] = f'"{obj.etag}"'
    # Do not cache authenticated downloads in the browser — expired JWTs must not
    # keep serving private objects from disk/memory cache.
    response['Cache-Control'] = 'private, no-store'
    return response


def build_signed_url(obj: StorageObject, expires_in: int | None = None) -> str:
    """Return a URL clients can use to fetch the object (signed when using S3)."""
    expires_in = expires_in or settings.SIGNED_URL_EXPIRES
    try:
        if is_s3_backend() and hasattr(default_storage, 'url'):
            try:
                return default_storage.url(obj.storage_key, expire=expires_in)
            except TypeError:
                return default_storage.url(obj.storage_key)
        return default_storage.url(obj.storage_key)
    except Exception:
        return ''
