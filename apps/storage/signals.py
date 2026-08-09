"""Django signals for storage lifecycle events (REST + WebDAV share these)."""

from __future__ import annotations

import logging

from django.core.files.storage import default_storage
from django.dispatch import Signal, receiver

logger = logging.getLogger(__name__)

# Fired after an object is created or overwritten (REST upload, WebDAV PUT, copy).
storage_object_uploaded = Signal()  # args: instance, created, request=None

# Fired after metadata/content update that is not a fresh upload path.
storage_object_updated = Signal()  # args: instance

# Fired after an object is deleted (DB row removed; blob already deleted).
storage_object_deleted = Signal()  # args: bucket_name, object_name, company_id, owner_id, mime_type, size


@receiver(storage_object_uploaded)
def log_upload(sender, instance, created, **kwargs):
    logger.info(
        'storage.upload company=%s bucket=%s path=%s size=%s mime=%s created=%s',
        instance.company_id,
        instance.bucket.name,
        instance.name,
        instance.size,
        instance.mime_type,
        created,
    )


@receiver(storage_object_deleted)
def log_delete(sender, bucket_name, object_name, company_id, **kwargs):
    logger.info(
        'storage.delete company=%s bucket=%s path=%s',
        company_id,
        bucket_name,
        object_name,
    )


@receiver(storage_object_uploaded)
def extract_markdown_sidecar(sender, instance, created, **kwargs):
    """
    Example reaction: when a Markdown file is uploaded, store extracted plain text
    in object metadata under ``markdown_text`` (truncated) for search/indexing hooks.
    """
    mime = (instance.mime_type or '').lower()
    if mime not in {'text/markdown', 'text/x-markdown'} and not instance.name.lower().endswith(
        ('.md', '.markdown')
    ):
        return

    try:
        with default_storage.open(instance.storage_key, 'rb') as fh:
            raw = fh.read(min(instance.size, 2 * 1024 * 1024))
        text = raw.decode('utf-8', errors='replace')
    except Exception:
        logger.exception('Failed reading markdown object %s', instance.name)
        return

    try:
        import markdown as md

        # Convert to plain-ish text by stripping tags from HTML render.
        html = md.markdown(text)
        plain = _strip_tags(html)
    except Exception:
        plain = text

    meta = dict(instance.metadata or {})
    meta['markdown_text'] = plain[:50_000]
    meta['markdown_chars'] = len(plain)
    # Avoid recursive save loops — update columns only.
    type(instance).objects.filter(pk=instance.pk).update(metadata=meta)
    instance.metadata = meta


def _strip_tags(html: str) -> str:
    import re

    return re.sub(r'<[^>]+>', ' ', html).replace('&nbsp;', ' ').strip()
