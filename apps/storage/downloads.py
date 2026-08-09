"""
Download response builders.

Strategies (see settings.DOWNLOAD_MODE):

* **redirect** — HTTP 302 to a time-limited signed URL. Ideal for S3/MinIO; works
  without nginx and offloads bandwidth to the object store.
* **xaccel** — ``X-Accel-Redirect`` so nginx serves the file from an internal
  location (local disk or an nginx→S3 proxy). Django only authorizes.
* **stream** — ``FileResponse`` through Django/Gunicorn. Always available; uses
  app bandwidth and worker time.
* **auto** — S3 → redirect; filesystem + ``X_ACCEL_REDIRECT_ENABLED`` → xaccel;
  otherwise stream.
"""

from __future__ import annotations

import mimetypes

from django.conf import settings
from django.core.files.storage import default_storage
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from django.utils import timezone

from .backends import is_s3_backend
from .models import StorageObject


def resolve_download_mode() -> str:
    mode = settings.DOWNLOAD_MODE
    if mode != 'auto':
        return mode
    if is_s3_backend():
        return 'redirect'
    if settings.X_ACCEL_REDIRECT_ENABLED:
        return 'xaccel'
    return 'stream'


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

    mode = resolve_download_mode()

    if mode == 'redirect':
        try:
            url = default_storage.url(obj.storage_key)
        except Exception:
            url = None
        if url and not url.startswith(('/', settings.MEDIA_URL)):
            # Absolute signed / CDN URL — offload to the store.
            response = HttpResponseRedirect(url)
            response['Content-Disposition'] = content_disposition
            return response
        # Filesystem storage.url is relative — fall through to stream/xaccel.
        mode = 'xaccel' if settings.X_ACCEL_REDIRECT_ENABLED else 'stream'

    if mode == 'xaccel':
        prefix = settings.X_ACCEL_REDIRECT_PREFIX
        if not prefix.endswith('/'):
            prefix += '/'
        # Map storage_key onto the internal nginx location.
        # For filesystem backend, keys are relative to MEDIA_ROOT/objects/.
        redirect_path = prefix + obj.storage_key.lstrip('/')
        response = HttpResponse(content_type=content_type)
        response['X-Accel-Redirect'] = redirect_path
        response['Content-Disposition'] = content_disposition
        response['Content-Length'] = str(obj.size)
        if obj.etag:
            response['ETag'] = f'"{obj.etag}"'
        return response

    # stream
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
    # django-storages S3 respects querystring_expire on url(); filesystem returns media URL.
    try:
        if is_s3_backend() and hasattr(default_storage, 'url'):
            # storages 1.14: pass expire via parameter when supported
            try:
                return default_storage.url(obj.storage_key, expire=expires_in)
            except TypeError:
                return default_storage.url(obj.storage_key)
        return default_storage.url(obj.storage_key)
    except Exception:
        return ''
