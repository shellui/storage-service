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

# Platform events: one per finished scheduled job run. No company, staff only, never sent
# as a webhook. See docs/maintenance-jobs.md.
_SCHEDULED_JOB = (
    EventFieldDoc('run_id', 'ScheduledJobRun id', 1234),
    EventFieldDoc('job', 'Job name: retry_webhooks or purge_expired_data', 'retry_webhooks'),
    EventFieldDoc('trigger', 'celery (in-container beat) or command (external scheduler)', 'celery'),
    EventFieldDoc('duration_ms', 'Run duration in milliseconds', 412),
    EventFieldDoc(
        'counts',
        'Items processed, per kind',
        {'webhook_deliveries_attempted': 3, 'webhook_deliveries_succeeded': 3},
    ),
    EventFieldDoc('host', 'Host name and process id that ran the job', 'storage-7f9c:41'),
)

register_event(
    DomainEventType(
        id='storage.scheduled_job.succeeded',
        label='Scheduled job succeeded',
        description='A scheduled job run finished without error. Platform event, staff only.',
        payload_fields=_SCHEDULED_JOB,
        webhook=False,
        staff_only=True,
    )
)

register_event(
    DomainEventType(
        id='storage.scheduled_job.failed',
        label='Scheduled job failed',
        description='A scheduled job run raised an error. Platform event, staff only.',
        payload_fields=_SCHEDULED_JOB
        + (
            EventFieldDoc('error_key', 'Stable error key (database_error, redis_error, …)', 'database_error'),
            EventFieldDoc('error_class', 'Exception class name', 'OperationalError'),
        ),
        webhook=False,
        staff_only=True,
    )
)
