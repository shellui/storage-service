"""Register storage-service domain events (``storage.*`` prefix)."""

from apps.actions.registry import DomainEventType, EventFieldDoc, register_event

_OBJECT = (
    EventFieldDoc('object_id', 'StorageObject UUID', '550e8400-e29b-41d4-a716-446655440000'),
    EventFieldDoc('bucket_name', 'Bucket slug within the company', 'company'),
    EventFieldDoc('bucket_kind', 'Bucket kind (company or connector)', 'company'),
    EventFieldDoc('path', 'Object path within the bucket', 'docs/report.pdf'),
    EventFieldDoc('size', 'Object size in bytes', 4096),
    EventFieldDoc('mime_type', 'Detected MIME type', 'application/pdf'),
    EventFieldDoc('version', 'Monotonic content version after upload', 1),
    EventFieldDoc('created', 'True when the object row was created; false on overwrite', True),
)

_BUCKET = (
    EventFieldDoc('bucket_id', 'Bucket UUID', '550e8400-e29b-41d4-a716-446655440001'),
    EventFieldDoc('bucket_name', 'Bucket slug', 'company'),
    EventFieldDoc('bucket_kind', 'Bucket kind', 'company'),
)

register_event(
    DomainEventType(
        id='storage.bucket.created',
        label='Company bucket provisioned',
        description='The system company bucket was created for a company (first storage access).',
        payload_fields=_BUCKET,
    )
)

register_event(
    DomainEventType(
        id='storage.object.uploaded',
        label='Object uploaded',
        description='A file was uploaded or overwritten (REST, WebDAV, or internal services). Folder placeholders are omitted.',
        payload_fields=_OBJECT,
    )
)

register_event(
    DomainEventType(
        id='storage.object.deleted',
        label='Object deleted',
        description='An object row and blob were removed. Folder placeholders are omitted.',
        payload_fields=(
            EventFieldDoc('bucket_name', 'Bucket slug', 'company'),
            EventFieldDoc('path', 'Object path', 'docs/report.pdf'),
            EventFieldDoc('size', 'Former size in bytes', 4096),
            EventFieldDoc('mime_type', 'Former MIME type', 'application/pdf'),
        ),
    )
)
