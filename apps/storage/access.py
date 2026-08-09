"""Bucket kinds and access control for storage-service.

v1 access model (enforced)
--------------------------
- ``company`` bucket: one per company; every member of that company can read/write.
- ``user`` bucket: one per (company, user); only that user can read/write.
- ``connector`` bucket: reserved for SharePoint / Dropbox / etc. Denied in v1.

Public buckets are disabled in v1 (``public`` is always forced false).

Future sharing (not enforced yet)
---------------------------------
``StorageAccessGrant`` is the intended extension point for invite / provide / block:

- Grant subject: user, group, or whole company
- Resource: bucket, folder prefix, or single object
- Effect: allow or deny
- Permission: read, write, admin

When grants ship, evaluation order should be:

1. Deny grants (block) win
2. Explicit allow grants
3. Fall back to bucket-kind defaults (company / owner)

Until then, only kind-based rules apply. Do not invent ad-hoc ACL checks elsewhere.
"""

from __future__ import annotations

from .models import Bucket, BucketKind


COMPANY_BUCKET_NAME = 'company'


def user_bucket_name(user_id: int) -> str:
    return f'user-{int(user_id)}'


def access_summary(bucket: Bucket) -> dict:
    """Machine-readable access descriptor for APIs and the Files UI."""
    if bucket.kind == BucketKind.COMPANY:
        return {
            'audience': 'company',
            'readers': 'company_members',
            'writers': 'company_members',
            'owner_id': None,
            'shareable': False,
            'description': 'Everyone in your company can view and edit these files.',
        }
    if bucket.kind == BucketKind.USER:
        return {
            'audience': 'owner',
            'readers': 'owner_only',
            'writers': 'owner_only',
            'owner_id': bucket.owner_id,
            'shareable': False,
            'description': 'Only you can view and edit these files.',
        }
    return {
        'audience': 'connector',
        'readers': 'none',
        'writers': 'none',
        'owner_id': bucket.owner_id,
        'shareable': False,
        'description': 'External connector bucket (not available yet).',
    }


def display_name_for_bucket(bucket: Bucket) -> str:
    if bucket.kind == BucketKind.COMPANY:
        return 'Company files'
    if bucket.kind == BucketKind.USER:
        return 'My files'
    provider = (bucket.connector_provider or 'connector').strip() or 'connector'
    return f'{provider} files'


def can_access_bucket(principal, bucket: Bucket, *, write: bool = False) -> bool:
    """Return whether principal may read (or write) the bucket under v1 rules."""
    del write  # v1: read and write use the same audience rules
    company_id = getattr(principal, 'company_id', None)
    user_id = getattr(principal, 'user_id', None)
    if company_id is None or user_id is None:
        return False
    if int(bucket.company_id) != int(company_id):
        return False

    if bucket.kind == BucketKind.COMPANY:
        return True
    if bucket.kind == BucketKind.USER:
        return bucket.owner_id is not None and int(bucket.owner_id) == int(user_id)
    # Connector: reserved — no access in v1
    return False


def assert_can_access_bucket(principal, bucket: Bucket, *, write: bool = False) -> None:
    from .services import StorageError

    if can_access_bucket(principal, bucket, write=write):
        return
    raise StorageError(
        'You do not have access to this bucket.',
        status=403,
        code='bucket_access_denied',
    )


def ensure_system_buckets(*, company_id: int, user_id: int) -> list[Bucket]:
    """
    Ensure the company private bucket and this user's private bucket exist.
    Safe to call on every list; does not create arbitrary buckets.
    """
    company_bucket, _ = Bucket.objects.get_or_create(
        company_id=company_id,
        name=COMPANY_BUCKET_NAME,
        defaults={
            'kind': BucketKind.COMPANY,
            'public': False,
            'owner_id': None,
        },
    )
    if company_bucket.kind != BucketKind.COMPANY or company_bucket.public:
        company_bucket.kind = BucketKind.COMPANY
        company_bucket.public = False
        company_bucket.owner_id = None
        company_bucket.save(update_fields=['kind', 'public', 'owner_id', 'updated_at'])

    personal_name = user_bucket_name(user_id)
    user_bucket, _ = Bucket.objects.get_or_create(
        company_id=company_id,
        name=personal_name,
        defaults={
            'kind': BucketKind.USER,
            'public': False,
            'owner_id': user_id,
        },
    )
    if (
        user_bucket.kind != BucketKind.USER
        or user_bucket.public
        or user_bucket.owner_id != user_id
    ):
        user_bucket.kind = BucketKind.USER
        user_bucket.public = False
        user_bucket.owner_id = user_id
        user_bucket.save(update_fields=['kind', 'public', 'owner_id', 'updated_at'])

    return [company_bucket, user_bucket]


def list_accessible_buckets(principal) -> list[Bucket]:
    """Provision defaults, then return buckets this principal may see."""
    from .services import require_company_id

    company_id = require_company_id(principal)
    user_id = int(principal.user_id)
    ensure_system_buckets(company_id=company_id, user_id=user_id)

    buckets = list(Bucket.objects.filter(company_id=company_id).order_by('kind', 'name'))
    return [b for b in buckets if can_access_bucket(principal, b)]


def get_accessible_bucket(principal, name: str, *, write: bool = False) -> Bucket:
    """Resolve bucket by name within the principal's company and enforce ACL."""
    from .services import StorageError, require_company_id

    company_id = require_company_id(principal)
    user_id = int(principal.user_id)
    # Auto-create system buckets so first object API call works without a prior list.
    ensure_system_buckets(company_id=company_id, user_id=user_id)

    try:
        bucket = Bucket.objects.get(company_id=company_id, name=name)
    except Bucket.DoesNotExist as exc:
        raise StorageError('Bucket not found', status=404, code='bucket_not_found') from exc

    assert_can_access_bucket(principal, bucket, write=write)
    return bucket
