"""Build responses that stream stored object bytes.

Authenticated downloads, the authenticated alias, share links, and WebDAV GET
all use ``build_download_response``. WebDAV HEAD uses
``apply_stored_file_headers`` so it advertises the same type and disposition
as the GET that follows. Signed URLs are not served here: S3 responds on its
own origin, and the filesystem backend only returns a ``/media/`` path.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from django.conf import settings
from django.core.files.storage import default_storage
from django.http import FileResponse, HttpResponse
from django.utils import timezone

from .backends import is_s3_backend
from .mime import guess_mime_type
from .models import StorageObject

# Raster images, PDF, plain text, and audio/video. SVG is not in this set.
_SAFE_INLINE_EXACT = frozenset({
    'image/png',
    'image/jpeg',
    'image/gif',
    'image/webp',
    'image/avif',
    'image/bmp',
    'image/apng',
    'image/x-icon',
    'image/vnd.microsoft.icon',
    'application/pdf',
    'text/plain',
})
_SAFE_INLINE_ALIASES = {
    'image/jpg': 'image/jpeg',
    'image/pjpeg': 'image/jpeg',
    'image/x-png': 'image/png',
    'image/x-ms-bmp': 'image/bmp',
    'image/x-bmp': 'image/bmp',
}
# Active types are never inlined, even if a later edit adds a broad prefix.
_ACTIVE_EXACT = frozenset({
    'text/html',
    'application/xhtml+xml',
    'image/svg+xml',
    'text/xml',
    'application/xml',
    'application/javascript',
    'text/javascript',
    'application/x-javascript',
    'text/ecmascript',
    'application/ecmascript',
})
_TOKEN = r"[0-9A-Za-z!#$%&'*+.^_`|~-]+"
_MIME_RE = re.compile(rf'{_TOKEN}/{_TOKEN}\Z')
# Browser viewers paint the response body itself. They do not need extra
# sources, so images and PDF use the same policy as every other file.
STORED_FILE_CSP = "sandbox; default-src 'none'"


def _mime_base(value: str | None) -> str:
    """Return a lowercase type/subtype, or '' when the value is not a MIME token."""
    if not value:
        return ''
    base = value.split(';', 1)[0].strip().lower()
    if not _MIME_RE.fullmatch(base):
        return ''
    return base


def _declared_mime(mime_type: str | None, object_name: str) -> str:
    # A present but malformed type is not guessed from the file name. Guessing
    # could turn header junk into an inline image type.
    if mime_type is not None and str(mime_type).strip() != '':
        return _mime_base(mime_type) or 'application/octet-stream'
    guessed = _mime_base(guess_mime_type(object_name, fallback=''))
    return guessed or 'application/octet-stream'


def _is_safe_inline(base: str) -> bool:
    if base in _ACTIVE_EXACT:
        return False
    if any(marker in base for marker in ('html', 'xml', 'svg', 'javascript', 'ecmascript')):
        return False
    canonical = _SAFE_INLINE_ALIASES.get(base, base)
    if canonical in _SAFE_INLINE_EXACT:
        return True
    if base.startswith('audio/') or base.startswith('video/'):
        return True
    return False


def _served_content_type(base: str, *, safe: bool) -> str:
    if safe:
        return _SAFE_INLINE_ALIASES.get(base, base)
    textual = (
        base.startswith('text/')
        or base.endswith('+xml')
        or base.endswith('+json')
        or base.endswith('/xml')
        or base.endswith('/json')
        or 'javascript' in base
        or 'ecmascript' in base
        or base in _ACTIVE_EXACT
    )
    if textual:
        return 'text/plain; charset=utf-8'
    return 'application/octet-stream'


def content_disposition_value(disposition: str, filename: str | None) -> str:
    """RFC 6266 ``Content-Disposition`` with an ASCII fallback and ``filename*``.

    Quotes and backslashes are escaped in the quoted ``filename``. Control
    characters, including CR and LF, are replaced there and percent-encoded
    in ``filename*`` so they cannot start a new header.
    """
    if disposition not in ('inline', 'attachment'):
        disposition = 'attachment'
    name = filename if isinstance(filename, str) else ''
    if name.strip() == '':
        name = 'download'

    fallback_chars: list[str] = []
    for char in name:
        code = ord(char)
        if char in ('\\', '"'):
            fallback_chars.append(char)
        elif 32 <= code <= 126:
            fallback_chars.append(char)
        else:
            fallback_chars.append('_')
    fallback = ''.join(fallback_chars).replace('\\', '\\\\').replace('"', '\\"')
    if fallback.strip() == '':
        fallback = 'download'
    encoded = quote(name, safe='', encoding='utf-8', errors='strict')
    return (
        f"{disposition}; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"
    )


def resolve_stored_file_response(
    mime_type: str | None,
    *,
    filename: str | None,
    as_attachment: bool = False,
    object_name: str | None = None,
) -> tuple[str, str]:
    """Return ``(Content-Type, Content-Disposition)`` for stored bytes.

    Types outside the inline allowlist are attachments. Their content type is
    ``text/plain`` or ``application/octet-stream``, not the stored type.
    ``object_name`` is only used to guess a type when ``mime_type`` is empty.
    The ``download`` name never changes the type.
    """
    base = _declared_mime(mime_type, object_name or filename or '')
    safe = _is_safe_inline(base)
    disposition = 'attachment' if as_attachment or not safe else 'inline'
    content_type = _served_content_type(base, safe=safe)
    header = content_disposition_value(disposition, filename)
    return content_type, header


def apply_stored_file_headers(
    response: HttpResponse,
    *,
    mime_type: str | None,
    filename: str | None,
    as_attachment: bool = False,
    object_name: str | None = None,
) -> HttpResponse:
    """Set type, disposition, nosniff, and the sandbox CSP on ``response``."""
    content_type, content_disposition = resolve_stored_file_response(
        mime_type,
        filename=filename,
        as_attachment=as_attachment,
        object_name=object_name,
    )
    response['Content-Type'] = content_type
    response['Content-Disposition'] = content_disposition
    response['X-Content-Type-Options'] = 'nosniff'
    response['Content-Security-Policy'] = STORED_FILE_CSP
    return response


def build_download_response(
    obj: StorageObject,
    *,
    as_attachment: bool = False,
    filename: str | None = None,
) -> HttpResponse:
    StorageObject.objects.filter(pk=obj.pk).update(last_accessed_at=timezone.now())

    download_name = filename or obj.basename or 'download'
    content_type, _disposition = resolve_stored_file_response(
        obj.mime_type,
        filename=download_name,
        as_attachment=as_attachment,
        object_name=obj.name,
    )

    fh = default_storage.open(obj.storage_key, 'rb')
    response = FileResponse(fh, content_type=content_type)
    apply_stored_file_headers(
        response,
        mime_type=obj.mime_type,
        filename=download_name,
        as_attachment=as_attachment,
        object_name=obj.name,
    )
    response['Content-Length'] = str(obj.size)
    if obj.etag:
        response['ETag'] = f'"{obj.etag}"'
    # Skip the browser cache. An expired JWT must not keep serving a private object.
    response['Cache-Control'] = 'private, no-store'
    return response


def signed_url_response_params(obj: StorageObject) -> dict[str, str]:
    """S3 response overrides for a signed download.

    Active types (HTML, SVG, XML, scripts, and anything outside the inline
    allowlist) are attachments with a safe content type. Raster images other
    than SVG, PDF, plain text, audio, and video stay inline.
    """
    filename = obj.basename or 'download'
    content_type, disposition = resolve_stored_file_response(
        obj.mime_type,
        filename=filename,
        object_name=obj.name,
    )
    return {
        'ResponseContentType': content_type,
        'ResponseContentDisposition': disposition,
    }


def build_signed_url(obj: StorageObject, expires_in: int | None = None) -> str:
    """Return a URL clients can use to fetch the object (signed when using S3).

    S3 URLs include ``ResponseContentType`` and ``ResponseContentDisposition``
    so the object store uses the same inline allowlist as Django downloads.
    The filesystem backend returns a ``/media/`` path and cannot set those headers.
    """
    max_expires = settings.SIGNED_URL_EXPIRES
    if expires_in is None:
        expires_in = max_expires
    else:
        expires_in = max(1, min(int(expires_in), max_expires))
    try:
        if is_s3_backend() and hasattr(default_storage, 'connection'):
            return _presigned_s3_url(obj, expires_in)
        return default_storage.url(obj.storage_key)
    except Exception:
        return ''


def _presigned_s3_url(obj: StorageObject, expires_in: int) -> str:
    """Sign against the S3 API endpoint, never against ``AWS_S3_CUSTOM_DOMAIN``.

    ``S3Storage.url()`` returns an unsigned URL on the custom domain, and S3 would ignore
    the response overrides there. A private object is always served through a SigV4 URL
    that carries an expiry and the ``response-content-*`` overrides in the signature.
    """
    from storages.utils import clean_name

    params = signed_url_response_params(obj)
    key = default_storage._normalize_name(clean_name(obj.storage_key))
    params = {**params, 'Bucket': default_storage.bucket.name, 'Key': key}
    return default_storage.connection.meta.client.generate_presigned_url(
        'get_object',
        Params=params,
        ExpiresIn=expires_in,
    )
