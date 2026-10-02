"""Wire storage lifecycle signals to Shellui Actions emit."""

from __future__ import annotations

from django.dispatch import receiver

from apps.actions.emit import emit_event_if_rules
from apps.storage.models import FOLDER_PLACEHOLDER_NAME
from apps.storage.signals import storage_object_deleted, storage_object_uploaded


def actor_from_request(request) -> dict | None:
    if request is None:
        return None
    return actor_from_user(getattr(request, 'user', None))


def actor_from_user(user) -> dict | None:
    if not user or not getattr(user, 'is_authenticated', False):
        return None
    actor: dict = {'user_id': int(getattr(user, 'user_id', getattr(user, 'pk', 0)))}
    email = getattr(user, 'email', '') or ''
    username = getattr(user, 'username', '') or ''
    if email:
        actor['email'] = email
    if username:
        actor['username'] = username
    return actor


def _is_folder_placeholder(object_name: str) -> bool:
    name = (object_name or '').strip()
    return name == FOLDER_PLACEHOLDER_NAME or name.endswith(f'/{FOLDER_PLACEHOLDER_NAME}')


@receiver(storage_object_uploaded)
def actions_on_object_uploaded(sender, instance, created, request=None, **kwargs):
    if _is_folder_placeholder(instance.name):
        return
    emit_event_if_rules(
        'storage.object.uploaded',
        int(instance.company_id),
        {
            'object_id': str(instance.id),
            'bucket_name': instance.bucket.name,
            'bucket_kind': instance.bucket.kind,
            'path': instance.name,
            'size': int(instance.size),
            'mime_type': instance.mime_type or '',
            'version': int(instance.version),
            'created': bool(created),
        },
        actor=actor_from_request(request),
    )


@receiver(storage_object_deleted)
def actions_on_object_deleted(sender, bucket_name, object_name, company_id, mime_type, size, request=None, **kwargs):
    if _is_folder_placeholder(object_name):
        return
    emit_event_if_rules(
        'storage.object.deleted',
        int(company_id),
        {
            'bucket_name': bucket_name,
            'path': object_name,
            'size': int(size or 0),
            'mime_type': mime_type or '',
        },
        actor=actor_from_request(request),
    )


def emit_bucket_created(bucket, *, request=None, principal=None) -> None:
    emit_event_if_rules(
        'storage.bucket.created',
        int(bucket.company_id),
        {
            'bucket_id': str(bucket.id),
            'bucket_name': bucket.name,
            'bucket_kind': bucket.kind,
        },
        actor=actor_from_request(request) or actor_from_user(principal),
    )
