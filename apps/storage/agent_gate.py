"""Changes that always need a person's approval when an agent makes them.

``decide_write`` lets a non-destructive write through in Full mode. These calls are
different: they create a way for data or access to leave the agent's own files, or they
change limits. An agent asks first, in every access mode, with a single-use approval bound
to the exact arguments. Read only agents are still refused outright.
"""

from __future__ import annotations

from typing import Any

from django.db import transaction

from apps.authapi.principal import StoragePrincipal

from .access import active_grants_for_company, apply_default_private_on_create, evaluate_access
from .mime import safe_object_path
from .models import FOLDER_PLACEHOLDER_NAME, Bucket, StorageAccessGrant, StorageObject, folder_path_from_placeholder
from .services import StorageError, move_object, objects_under_prefix, rename_folder

# Operation ids (OpenAPI ``operationId``) that always need approval for an agent.
ALWAYS_APPROVE_OPERATIONS: dict[str, str] = {
    # An Actions webhook sends file events and signed deliveries to a URL the agent picks.
    'api_v1_actions_rules_create': 'Creating an Actions webhook requires approval.',
    'api_v1_actions_rules_partial_update': 'Changing an Actions webhook requires approval.',
    # Quotas cap how much a company or a person can store.
    'storage_v1_quota_company_update': 'Changing a storage quota requires approval.',
    'storage_v1_quota_company_user_update': 'Changing a storage quota requires approval.',
    # A connector mounts an outside bucket with credentials the agent supplies. Changing or
    # removing one is already a destructive call that needs approval.
    'storage_v1_connector_create': 'Mounting an outside bucket requires approval.',
}

WIDENS_VISIBILITY_REASON = 'Moving, copying or renaming a file or folder so more people can read it requires approval.'

OBJECT_MOVE = 'storage_v1_object_move_create'
OBJECT_COPY = 'storage_v1_object_copy_create'
FOLDER_RENAME = 'storage_v1_object_prefix_create'
_VISIBILITY_OPERATIONS = frozenset({OBJECT_MOVE, OBJECT_COPY, FOLDER_RENAME})

# A user id no grant names, so it reads only what every company member reads.
_PLAIN_MEMBER_ID = 2**31 - 2
# More affected objects than this and the check is not worth running: ask.
_MAX_OBJECTS = 2000


class _Unknown(Exception):
    """The operation or its source cannot be resolved. The caller treats it as "ask"."""


def _probes(company_id: int, owner_id: int) -> list[StoragePrincipal]:
    """A plain member, the caller's creator (a copy is theirs), and every person a grant names.

    The same people are checked before and after, so a person only counts as gaining access
    when the real access check says so for both states.
    """
    ids = {_PLAIN_MEMBER_ID}
    if owner_id > 0:
        ids.add(owner_id)
    grants = active_grants_for_company(company_id)
    for g in grants:
        if g.subject_type == StorageAccessGrant.SubjectType.USER and str(g.subject_id).isdigit():
            if int(g.subject_id) > 0:
                ids.add(int(g.subject_id))
    return [StoragePrincipal(user_id=uid, company_id=company_id) for uid in sorted(ids)]


def _readers(company_id: int, probes: list[StoragePrincipal], ids: dict[Any, Any]) -> dict[Any, frozenset[int]]:
    """Who can read each object right now, by the real access check.

    ``ids`` maps a key to an object id. Objects are loaded fresh, so a name or a grant changed
    in this transaction is seen. Grants are read once and passed in.
    """
    grants = active_grants_for_company(company_id)
    objs = {o.pk: o for o in StorageObject.objects.select_related('bucket').filter(pk__in=list(ids.values()))}
    out: dict[Any, frozenset[int]] = {}
    for key, oid in ids.items():
        obj = objs.get(oid)
        if obj is None:
            raise _Unknown('object disappeared')
        out[key] = frozenset(
            p.user_id
            for p in probes
            if evaluate_access(p, obj.bucket, path=obj.name, object_id=str(obj.pk), grants=grants)
        )
    return out


def _split(key: Any) -> tuple[str, str]:
    """Bucket and object path, split and normalized the way the views and services do."""
    bucket_name, _, name = str(key or '').partition('/')
    if not bucket_name or not name:
        raise _Unknown('bad key')
    try:
        return bucket_name, safe_object_path(name)
    except ValueError as exc:
        raise _Unknown('bad path') from exc


def _bucket(company_id: int, name: str) -> Bucket:
    bucket = Bucket.objects.filter(company_id=company_id, name=name).first()
    if bucket is None:
        raise _Unknown('bucket not found')
    return bucket


def _with_left_behind(bucket: Bucket, objs: list[StorageObject]) -> dict[Any, Any]:
    """The objects an operation changes, plus those left in a folder whose marker moves.

    Folder grants sit on the folder's placeholder object. Moving the marker takes the folder's
    privacy with it, so every object still in that folder is affected too.
    """
    affected = {o.pk: o.pk for o in objs}
    for o in objs:
        if o.name.rsplit('/', 1)[-1] == FOLDER_PLACEHOLDER_NAME:
            folder = folder_path_from_placeholder(o.name)
            if folder:
                for left in objects_under_prefix(bucket, folder):
                    affected.setdefault(left.pk, left.pk)
    if len(affected) > _MAX_OBJECTS:
        raise _Unknown('too many objects')
    return affected


def _plan(operation_id: str, arguments: dict[str, Any], company_id: int, owner_id: int):
    """Resolve the call to (before: {key: object id}, simulate: callable returning after ids)."""
    body = arguments.get('body') if isinstance(arguments.get('body'), dict) else {}
    if operation_id == FOLDER_RENAME:
        params = arguments.get('path_params') if isinstance(arguments.get('path_params'), dict) else {}
        bucket = _bucket(company_id, str(params.get('bucket_id') or ''))
        source = str(body.get('from') or body.get('prefix') or body.get('source') or '').strip('/')
        dest = str(body.get('to') or body.get('destination') or '').strip('/')
        try:
            src, dst = safe_object_path(source), safe_object_path(dest)
        except ValueError as exc:
            raise _Unknown('bad path') from exc
        objs = list(objects_under_prefix(bucket, src))
        if not objs:
            raise _Unknown('folder not found')
        before = _with_left_behind(bucket, objs)

        def rename():
            rename_folder(bucket=bucket, source_path=src, dest_path=dst)
            return before

        return before, rename

    src_bucket_name, src_name = _split(body.get('sourceKey') or body.get('from'))
    dst_bucket_name, dst_name = _split(body.get('destinationKey') or body.get('to'))
    src_bucket, dst_bucket = _bucket(company_id, src_bucket_name), _bucket(company_id, dst_bucket_name)
    src = StorageObject.objects.filter(bucket=src_bucket, name=src_name).first()
    if src is None:
        raise _Unknown('source not found')

    if operation_id == OBJECT_MOVE:
        before = _with_left_behind(src_bucket, [src])

        def move():
            move_object(bucket=src_bucket, source_path=src_name, dest_bucket=dst_bucket, dest_path=dst_name)
            return before

        return before, move

    def copy():
        """What ``copy_object`` leaves behind, without the blob: a new row and its default grants."""
        new = StorageObject.objects.create(
            bucket=dst_bucket,
            name=dst_name,
            company_id=dst_bucket.company_id,
            owner_id=owner_id,
            size=src.size,
            mime_type=src.mime_type,
            storage_key=f'simulated/{src.pk}',
        )
        apply_default_private_on_create(instance=new, user_id=new.owner_id)
        return {src.pk: new.pk}

    return {src.pk: src.pk}, copy


def copy_or_move_widens_visibility(operation_id: str, arguments: dict[str, Any], principal: Any) -> bool:
    """True when anyone could read something after this call that they could not read before.

    One comparison for every move, copy and folder rename: take who can read each affected
    object now, apply the operation inside a transaction that is rolled back, take who can read
    it afterwards, and compare, using the real access check for a plain member and for every
    person a grant names. Anything that cannot be resolved (a key that is not found, a bad path,
    too many objects, an operation that would fail) asks, because the safe answer is a person.
    """
    if operation_id not in _VISIBILITY_OPERATIONS:
        return False
    company_id = getattr(principal, 'company_id', None)
    if company_id is None:
        return True
    owner_id = int(getattr(principal, 'user_id', 0) or 0)  # copy_object uses the caller's id as is
    try:
        before_ids, simulate = _plan(operation_id, arguments, int(company_id), owner_id)
        probes = _probes(int(company_id), owner_id)
        before = _readers(int(company_id), probes, before_ids)
        with transaction.atomic():
            after_ids = simulate()
            after = _readers(int(company_id), probes, after_ids)
            transaction.set_rollback(True)
    except (_Unknown, StorageError, ValueError):
        return True
    return any(after[key] - before[key] for key in before)


def approval_reason_for_agent_call(operation_id: str, arguments: dict[str, Any], principal: Any) -> str | None:
    """Why this agent call needs approval even when its access mode would allow it, or None."""
    reason = ALWAYS_APPROVE_OPERATIONS.get(operation_id)
    if reason:
        return reason
    if copy_or_move_widens_visibility(operation_id, arguments, principal):
        return WIDENS_VISIBILITY_REASON
    return None
