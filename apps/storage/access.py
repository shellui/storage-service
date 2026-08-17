"""Bucket kinds and access control for storage-service.

Model
-----
- One system ``company`` bucket per company (auto-provisioned).
- New folders/files are **private to the creator** by default (auto grants);
  nested items inherit ancestor folder grants.
- ``StorageAccessGrant`` refines who can read/write/admin folders and objects.
- ``connector`` buckets (SharePoint, Dropbox, …) are optional mounts: company
  members get **read-only** access when present; writes are denied.

Grant evaluation order
----------------------
1. Matching grants at highest specificity (object › folder › bucket; user › group › company)
2. Among those: deny wins, else allow
3. Bucket-kind defaults

Anonymous access is **not** granted here — use ``ObjectShareLink`` capability URLs.
"""

from __future__ import annotations

from django.db.models import Q
from django.utils import timezone

from .models import (
    Bucket,
    BucketKind,
    FOLDER_PLACEHOLDER_NAME,
    StorageAccessGrant,
    StorageObject,
    folder_path_from_placeholder,
    folder_placeholder_path,
)


COMPANY_BUCKET_NAME = 'company'

_PERMISSION_RANK = {
    StorageAccessGrant.Permission.READ: 0,
    StorageAccessGrant.Permission.WRITE: 1,
    StorageAccessGrant.Permission.ADMIN: 2,
}


def access_summary(bucket: Bucket) -> dict:
    """Machine-readable access descriptor for APIs and the Files UI."""
    if bucket.kind == BucketKind.COMPANY:
        return {
            'audience': 'company',
            'readers': 'company_members_and_grants',
            'writers': 'company_members_and_grants',
            'owner_id': None,
            'shareable': True,
            'grants_enabled': True,
            'description': (
                'Company files. New folders and files are private to their creator by default; '
                'share with access grants. Nested items inherit the parent folder\'s permissions.'
            ),
        }
    provider = (bucket.connector_provider or 'connector').strip() or 'connector'
    return {
        'audience': 'connector',
        'readers': 'company_members',
        'writers': 'none',
        'owner_id': bucket.owner_id,
        'shareable': False,
        'grants_enabled': True,
        'description': f'Read-only {provider} connector mount.',
    }


def path_access_summary(
    bucket: Bucket,
    *,
    path: str,
    object_id: str | None = None,
    grants: list[StorageAccessGrant] | None = None,
) -> dict:
    """
    Bucket access summary refined by grants that apply to ``path``.

    Used in object listings so the Files UI can show Restricted vs company-wide
    access instead of always repeating the bucket default.
    """
    base = access_summary(bucket)
    if not base.get('grants_enabled'):
        return base

    path = _normalize_path(path)
    if not path and not object_id:
        return base

    if grants is None:
        grants = list(_active_grants_qs(company_id=int(bucket.company_id)))

    matching = [
        g
        for g in grants
        if _resource_matches_grant(g, bucket=bucket, path=path or None, object_id=object_id)
    ]
    if not matching:
        return base

    company_deny_read = any(
        g.effect == StorageAccessGrant.Effect.DENY
        and g.subject_type == StorageAccessGrant.SubjectType.COMPANY
        and _deny_blocks(g.permission, StorageAccessGrant.Permission.READ)
        for g in matching
    )
    allow_users = sorted(
        {
            str(g.subject_id)
            for g in matching
            if g.effect == StorageAccessGrant.Effect.ALLOW
            and g.subject_type == StorageAccessGrant.SubjectType.USER
        }
    )
    allow_groups = sorted(
        {
            str(g.subject_id)
            for g in matching
            if g.effect == StorageAccessGrant.Effect.ALLOW
            and g.subject_type == StorageAccessGrant.SubjectType.GROUP
        }
    )
    has_other_grants = any(
        not (
            g.effect == StorageAccessGrant.Effect.DENY
            and g.subject_type == StorageAccessGrant.SubjectType.COMPANY
        )
        for g in matching
    )

    if company_deny_read:
        parts: list[str] = []
        if allow_users:
            parts.append(f'{len(allow_users)} user(s)')
        if allow_groups:
            parts.append(f'{len(allow_groups)} group(s)')
        who = ', '.join(parts) if parts else 'invited principals only'
        return {
            **base,
            'audience': 'restricted',
            'readers': 'grants_only',
            'writers': 'grants_only',
            'allowed_user_ids': allow_users,
            'allowed_group_ids': allow_groups,
            'grant_count': len(matching),
            'description': f'Restricted folder/file — {who}.',
        }

    if has_other_grants:
        return {
            **base,
            'audience': 'limited',
            'readers': 'company_members_and_grants',
            'writers': 'company_members_and_grants',
            'allowed_user_ids': allow_users,
            'allowed_group_ids': allow_groups,
            'grant_count': len(matching),
            'description': (
                'Company members can access by default; additional grants refine access '
                f'({len(matching)} grant(s) on this path).'
            ),
        }

    return {
        **base,
        'grant_count': len(matching),
    }


def display_name_for_bucket(bucket: Bucket) -> str:
    if bucket.kind == BucketKind.COMPANY:
        return 'Company files'
    provider = (bucket.connector_provider or 'connector').strip() or 'connector'
    return f'{provider} files'


def _permission_at_least(granted: str, required: str) -> bool:
    return _PERMISSION_RANK.get(granted, -1) >= _PERMISSION_RANK.get(required, 99)


def _deny_blocks(denied: str, required: str) -> bool:
    """Deny read blocks everything; deny write blocks write+admin; deny admin blocks admin."""
    return _PERMISSION_RANK.get(required, 99) >= _PERMISSION_RANK.get(denied, 99)


def _required_permission(*, write: bool = False, admin: bool = False) -> str:
    if admin:
        return StorageAccessGrant.Permission.ADMIN
    if write:
        return StorageAccessGrant.Permission.WRITE
    return StorageAccessGrant.Permission.READ


def _normalize_path(path: str | None) -> str:
    return (path or '').strip().strip('/')


def _folder_matches(prefix: str, path: str) -> bool:
    """True if ``path`` is inside folder prefix (or is the folder itself)."""
    prefix = _normalize_path(prefix)
    path = _normalize_path(path)
    if not prefix:
        return True
    return path == prefix or path.startswith(prefix + '/')


def _grant_bucket_name(grant: StorageAccessGrant) -> str:
    if grant.bucket_id:
        return grant.bucket.name
    return COMPANY_BUCKET_NAME


def _resource_matches_grant(
    grant: StorageAccessGrant,
    *,
    bucket: Bucket,
    path: str | None,
    object_id: str | None = None,
) -> bool:
    if grant.bucket_id != bucket.id:
        return False

    path = _normalize_path(path)

    if grant.resource_type == StorageAccessGrant.ResourceType.BUCKET:
        return True

    if grant.resource_type == StorageAccessGrant.ResourceType.FOLDER:
        if path is None or grant.object_id is None:
            return False
        return _folder_matches(folder_path_from_placeholder(grant.object.name), path)

    if grant.resource_type == StorageAccessGrant.ResourceType.OBJECT:
        if grant.object_id is None:
            return False
        if object_id and str(grant.object_id) == str(object_id):
            return True
        return bool(path) and _normalize_path(grant.object.name) == path

    return False


def _subject_matches(grant: StorageAccessGrant, principal) -> bool:
    user_id = getattr(principal, 'user_id', None)
    company_id = getattr(principal, 'company_id', None)
    if user_id is None or company_id is None:
        return False

    if grant.subject_type == StorageAccessGrant.SubjectType.USER:
        return str(grant.subject_id) == str(int(user_id))

    if grant.subject_type == StorageAccessGrant.SubjectType.COMPANY:
        return str(grant.subject_id) == str(int(company_id))

    # Groups: reserved until identity-service exposes group membership claims.
    return False


def _active_grants_qs(*, company_id: int):
    now = timezone.now()
    return (
        StorageAccessGrant.objects.select_related('bucket', 'object')
        .filter(company_id=company_id)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
    )


def active_grants_for_company(company_id: int) -> list[StorageAccessGrant]:
    """Active (non-expired) grants for a company — used when summarizing list rows."""
    return list(_active_grants_qs(company_id=int(company_id)))


def _kind_default_allows(principal, bucket: Bucket, *, required: str) -> bool:
    company_id = getattr(principal, 'company_id', None)
    user_id = getattr(principal, 'user_id', None)
    if company_id is None or user_id is None:
        return False
    if int(bucket.company_id) != int(company_id):
        return False

    if bucket.kind == BucketKind.COMPANY:
        # Company members: read + write by default; admin only for owners/staff.
        if required == StorageAccessGrant.Permission.ADMIN:
            return bool(
                getattr(principal, 'is_company_owner', False)
                or getattr(principal, 'is_staff', False)
            )
        return True

    if bucket.kind == BucketKind.CONNECTOR:
        # External mounts are read-only for company members.
        return required == StorageAccessGrant.Permission.READ

    return False


def _grant_specificity(grant: StorageAccessGrant, *, path: str | None) -> tuple[int, int]:
    """
    Higher wins. Resource specificity first, then subject.

    Lets ``allow user`` on a folder override ``deny company`` on the same folder.
    """
    subject_score = {
        StorageAccessGrant.SubjectType.USER: 3,
        StorageAccessGrant.SubjectType.GROUP: 2,
        StorageAccessGrant.SubjectType.COMPANY: 1,
    }.get(grant.subject_type, 0)

    if grant.resource_type == StorageAccessGrant.ResourceType.OBJECT:
        resource_score = 1000
    elif grant.resource_type == StorageAccessGrant.ResourceType.FOLDER:
        folder_path = folder_path_from_placeholder(grant.object.name) if grant.object_id else ''
        depth = len(_normalize_path(folder_path).split('/')) if folder_path else 0
        resource_score = 100 + depth
    else:
        resource_score = 1
    return (resource_score, subject_score)


def evaluate_access(
    principal,
    bucket: Bucket,
    *,
    path: str | None = None,
    object_id: str | None = None,
    write: bool = False,
    admin: bool = False,
) -> bool:
    """Return whether principal may perform the required action on bucket/path."""
    company_id = getattr(principal, 'company_id', None)
    user_id = getattr(principal, 'user_id', None)
    if company_id is None or user_id is None:
        return False
    if int(bucket.company_id) != int(company_id):
        return False

    required = _required_permission(write=write, admin=admin)

    grants = [
        g
        for g in _active_grants_qs(company_id=int(company_id))
        if _subject_matches(g, principal)
        and _resource_matches_grant(g, bucket=bucket, path=path, object_id=object_id)
    ]

    if grants:
        best = max(_grant_specificity(g, path=path) for g in grants)
        top = [g for g in grants if _grant_specificity(g, path=path) == best]

        for grant in top:
            if grant.effect == StorageAccessGrant.Effect.DENY and _deny_blocks(
                grant.permission, required
            ):
                return False

        saw_allow = False
        for grant in top:
            if grant.effect != StorageAccessGrant.Effect.ALLOW:
                continue
            saw_allow = True
            if _permission_at_least(grant.permission, required):
                return True

        # Explicit allow at this specificity that is too weak (e.g. read when
        # write required) must not fall through to open company defaults.
        if saw_allow:
            return False

    return _kind_default_allows(principal, bucket, required=required)


def can_access_bucket(principal, bucket: Bucket, *, write: bool = False, admin: bool = False) -> bool:
    """Bucket-level check (ignores folder/object grants except bucket-scoped ones)."""
    return evaluate_access(principal, bucket, path=None, write=write, admin=admin)


def can_access_path(
    principal,
    bucket: Bucket,
    path: str,
    *,
    write: bool = False,
    admin: bool = False,
    object_id: str | None = None,
) -> bool:
    """Path-aware check including folder and object grants."""
    return evaluate_access(
        principal,
        bucket,
        path=path,
        object_id=object_id,
        write=write,
        admin=admin,
    )


def assert_can_access_bucket(
    principal,
    bucket: Bucket,
    *,
    write: bool = False,
    admin: bool = False,
) -> None:
    from .services import StorageError

    if can_access_bucket(principal, bucket, write=write, admin=admin):
        return
    raise StorageError(
        'You do not have access to this bucket.',
        status=403,
        code='bucket_access_denied',
    )


def assert_can_access_path(
    principal,
    bucket: Bucket,
    path: str,
    *,
    write: bool = False,
    admin: bool = False,
    object_id: str | None = None,
) -> None:
    from .services import StorageError

    if can_access_path(
        principal,
        bucket,
        path,
        write=write,
        admin=admin,
        object_id=object_id,
    ):
        return
    raise StorageError(
        'You do not have access to this path.',
        status=403,
        code='path_access_denied',
    )


def ensure_company_bucket(*, company_id: int) -> Bucket:
    """Ensure the single system company bucket exists."""
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
    return company_bucket


def ensure_system_buckets(*, company_id: int, user_id: int | None = None) -> list[Bucket]:
    """Ensure the company bucket exists. ``user_id`` is ignored (compat alias)."""
    del user_id
    return [ensure_company_bucket(company_id=company_id)]


def list_accessible_buckets(principal) -> list[Bucket]:
    """Provision the company bucket, then return buckets this principal may see."""
    from .services import require_company_id

    company_id = require_company_id(principal)
    ensure_company_bucket(company_id=company_id)

    buckets = list(Bucket.objects.filter(company_id=company_id).order_by('kind', 'name'))
    return [b for b in buckets if can_access_bucket(principal, b)]


def get_accessible_bucket(principal, name: str, *, write: bool = False, admin: bool = False) -> Bucket:
    """Resolve bucket by name within the principal's company and enforce ACL."""
    from .services import StorageError, require_company_id

    company_id = require_company_id(principal)
    ensure_company_bucket(company_id=company_id)

    try:
        bucket = Bucket.objects.get(company_id=company_id, name=name)
    except Bucket.DoesNotExist as exc:
        raise StorageError('Bucket not found', status=404, code='bucket_not_found') from exc

    assert_can_access_bucket(principal, bucket, write=write, admin=admin)
    return bucket


def get_accessible_object(
    principal,
    bucket_name: str,
    path: str,
    *,
    write: bool = False,
    admin: bool = False,
) -> tuple[Bucket, StorageObject]:
    """Resolve bucket + object and enforce path ACL."""
    from .services import StorageError
    from .mime import safe_object_path

    bucket = get_accessible_bucket(principal, bucket_name, write=write, admin=admin)
    name = safe_object_path(path)
    obj = StorageObject.objects.filter(bucket=bucket, name=name).first()
    if not obj:
        raise StorageError('Object not found', status=404, code='object_not_found')
    assert_can_access_path(
        principal,
        bucket,
        name,
        write=write,
        admin=admin,
        object_id=str(obj.id),
    )
    return bucket, obj


def serialize_grant(grant: StorageAccessGrant) -> dict:
    return {
        'id': str(grant.id),
        'company_id': grant.company_id,
        'bucket': _grant_bucket_name(grant),
        'subject_type': grant.subject_type,
        'subject_id': grant.subject_id,
        'resource_type': grant.resource_type,
        'resource_id': grant.resource_path(),
        'permission': grant.permission,
        'effect': grant.effect,
        'created_by_id': grant.created_by_id,
        'created_at': grant.created_at.isoformat().replace('+00:00', 'Z'),
        'updated_at': grant.updated_at.isoformat().replace('+00:00', 'Z'),
        'expires_at': (
            grant.expires_at.isoformat().replace('+00:00', 'Z') if grant.expires_at else None
        ),
        'notes': grant.notes or '',
    }


AUTO_PRIVATE_NOTES = 'auto: private by default'


def _ancestor_folder_prefixes(path: str) -> list[str]:
    """Parent folder prefixes of ``path`` (excludes the full path itself)."""
    path = _normalize_path(path)
    if not path or '/' not in path:
        return []
    parts = path.split('/')
    return ['/'.join(parts[:i]) for i in range(1, len(parts))]


def _folder_grants_for_prefixes(
    *,
    company_id: int,
    bucket_name: str,
    folder_prefixes: list[str],
) -> list[StorageAccessGrant]:
    if not folder_prefixes:
        return []
    names = [folder_placeholder_path(prefix) for prefix in folder_prefixes]
    return list(
        _active_grants_qs(company_id=company_id)
        .filter(
            resource_type=StorageAccessGrant.ResourceType.FOLDER,
            object__name__in=names,
            bucket__name=bucket_name,
        )
    )


def _nearest_ancestor_folder_grants(
    *,
    company_id: int,
    bucket_name: str,
    path: str,
) -> tuple[str | None, list[StorageAccessGrant]]:
    """
    Deepest ancestor folder that has grants, and those grants.

    Walks from the immediate parent up to the top-level segment.
    """
    ancestors = _ancestor_folder_prefixes(path)
    if not ancestors:
        return None, []
    grants = _folder_grants_for_prefixes(
        company_id=company_id,
        bucket_name=bucket_name,
        folder_prefixes=ancestors,
    )
    if not grants:
        return None, []
    by_prefix: dict[str, list[StorageAccessGrant]] = {}
    for g in grants:
        by_prefix.setdefault(folder_path_from_placeholder(g.object.name), []).append(g)
    # ancestors are root→leaf; prefer deepest (nearest parent).
    for prefix in reversed(ancestors):
        if prefix in by_prefix:
            return prefix, by_prefix[prefix]
    return None, []


def nearest_private_ancestor_folder(
    *,
    company_id: int,
    bucket_name: str,
    path: str,
) -> str | None:
    """
    Nearest ancestor folder that denies company-wide read (i.e. is private).

    Used to block opening a nested path to the whole company while a parent
    folder remains private — company members would still be blocked (or, with a
    nested company allow, could pierce the parent).
    """
    ancestors = _ancestor_folder_prefixes(path)
    if not ancestors:
        return None
    grants = _folder_grants_for_prefixes(
        company_id=int(company_id),
        bucket_name=bucket_name,
        folder_prefixes=ancestors,
    )
    private_prefixes = {
        folder_path_from_placeholder(g.object.name)
        for g in grants
        if g.effect == StorageAccessGrant.Effect.DENY
        and g.subject_type == StorageAccessGrant.SubjectType.COMPANY
        and _deny_blocks(g.permission, StorageAccessGrant.Permission.READ)
        and str(g.subject_id) == str(int(company_id))
    }
    for prefix in reversed(ancestors):
        if prefix in private_prefixes:
            return prefix
    return None


def assert_can_open_to_company(
    *,
    company_id: int,
    bucket_name: str,
    path: str,
) -> None:
    """Raise if ``path`` sits under a private ancestor folder."""
    from .services import StorageError

    parent = nearest_private_ancestor_folder(
        company_id=company_id,
        bucket_name=bucket_name,
        path=path,
    )
    if not parent:
        return
    raise StorageError(
        f'Cannot open this path to the company while the parent folder "{parent}" '
        f'is private. Change access on "{parent}" first.',
        status=400,
        code='parent_folder_private',
    )

def _resource_grants_exist(*, target: StorageObject, resource_type: str) -> bool:
    return (
        _active_grants_qs(company_id=int(target.company_id))
        .filter(resource_type=resource_type, object=target, bucket=target.bucket)
        .exists()
    )


def _copy_folder_grants(
    *,
    source_grants: list[StorageAccessGrant],
    user_id: int,
    target: StorageObject,
) -> list[StorageAccessGrant]:
    """Materialize parent folder ACL onto a new folder marker object."""
    created: list[StorageAccessGrant] = []
    for src in source_grants:
        created.append(
            StorageAccessGrant.objects.create(
                company_id=int(target.company_id),
                bucket=target.bucket,
                object=target,
                subject_type=src.subject_type,
                subject_id=src.subject_id,
                resource_type=StorageAccessGrant.ResourceType.FOLDER,
                permission=src.permission,
                effect=src.effect,
                created_by_id=int(user_id),
                expires_at=src.expires_at,
                notes=src.notes or AUTO_PRIVATE_NOTES,
            )
        )
    return created


def ensure_default_private_access(
    *,
    user_id: int,
    target: StorageObject,
    resource_type: str,
) -> list[StorageAccessGrant]:
    """
    Make a newly created folder/file private to its creator, or match the parent folder.

    - Nested under a folder that already has grants → **copy** that folder's grants
      onto the new folder (so Permissions UI and listings match the parent). Nested
      **files** inherit via path matching and get no extra grants.
    - Otherwise create:
      - ``deny`` + ``read`` for the company (blocks company-wide default access)
      - ``allow`` + ``admin`` for the creating user (so they can share later)
    """
    if user_id is None:
        return []

    if resource_type not in {
        StorageAccessGrant.ResourceType.FOLDER,
        StorageAccessGrant.ResourceType.OBJECT,
    }:
        return []

    path = (
        folder_path_from_placeholder(target.name)
        if resource_type == StorageAccessGrant.ResourceType.FOLDER
        else _normalize_path(target.name)
    )
    if not path:
        return []

    if _resource_grants_exist(target=target, resource_type=resource_type):
        return []

    nearest, parent_grants = _nearest_ancestor_folder_grants(
        company_id=int(target.company_id),
        bucket_name=target.bucket.name,
        path=path,
    )
    if nearest and parent_grants:
        if resource_type == StorageAccessGrant.ResourceType.FOLDER:
            return _copy_folder_grants(
                source_grants=parent_grants,
                user_id=int(user_id),
                target=target,
            )
        return []

    common = dict(
        company_id=int(target.company_id),
        bucket=target.bucket,
        object=target,
        resource_type=resource_type,
        created_by_id=int(user_id),
        notes=AUTO_PRIVATE_NOTES,
    )
    created = [
        StorageAccessGrant.objects.create(
            **common,
            subject_type=StorageAccessGrant.SubjectType.COMPANY,
            subject_id=str(int(target.company_id)),
            permission=StorageAccessGrant.Permission.READ,
            effect=StorageAccessGrant.Effect.DENY,
        ),
        StorageAccessGrant.objects.create(
            **common,
            subject_type=StorageAccessGrant.SubjectType.USER,
            subject_id=str(int(user_id)),
            permission=StorageAccessGrant.Permission.ADMIN,
            effect=StorageAccessGrant.Effect.ALLOW,
        ),
    ]
    return created


def apply_default_private_on_create(
    *,
    instance: StorageObject,
    user_id: int | None,
    is_folder: bool = False,
) -> list[StorageAccessGrant]:
    """
    Apply private-by-default grants after creating a folder or uploading a file.

    Empty-folder placeholder uploads (``…/.emptyFolderPlaceholder``) are treated
    as folder creates on the parent path. Nested folders copy the nearest parent
    folder's grants when present.
    """
    if user_id is None:
        return []

    path = _normalize_path(instance.name)
    if not path or path == FOLDER_PLACEHOLDER_NAME:
        return []

    placeholder_suffix = f'/{FOLDER_PLACEHOLDER_NAME}'
    if is_folder or path.endswith(placeholder_suffix):
        folder_path = folder_path_from_placeholder(path)
        if not folder_path:
            return []
        return ensure_default_private_access(
            user_id=int(user_id),
            target=instance,
            resource_type=StorageAccessGrant.ResourceType.FOLDER,
        )

    return ensure_default_private_access(
        user_id=int(user_id),
        target=instance,
        resource_type=StorageAccessGrant.ResourceType.OBJECT,
    )
