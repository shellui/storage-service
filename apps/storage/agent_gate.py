"""Changes that always need a person's approval when an agent makes them.

``decide_write`` lets a non-destructive write through in Full mode. These calls are
different: they create a way for data or access to leave the agent's own files, or they
change limits. An agent asks first, in every access mode, with a single-use approval bound
to the exact arguments. Read only agents are still refused outright.

Moves, copies and renames are different again: they only ask when they would let someone read
something they could not read before. ``checked`` answers that by running the real write inside
one transaction and comparing who can read each affected object before and after, so the
answer is about what actually happened, under a lock no other move, copy or rename can
interleave with. If access widened, the transaction rolls back and nothing was written.
"""

from __future__ import annotations

from collections import defaultdict
from time import monotonic
from typing import Any, Callable

from django.db import transaction

from apps.authapi.principal import StoragePrincipal

from . import write_guard
from .access import (
    _normalize_path,
    active_grants_for_company,
    evaluate_access,
)
from .mime import safe_object_path
from .models import FOLDER_PLACEHOLDER_NAME, Bucket, StorageAccessGrant, StorageObject, folder_path_from_placeholder
from .services import lock_company_buckets, objects_under_prefix

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

OBJECT_MOVE = 'storage_v1_object_move_create'
OBJECT_COPY = 'storage_v1_object_copy_create'
FOLDER_RENAME = 'storage_v1_object_prefix_create'
OBJECT_DESTROY = 'storage_v1_object_destroy'
VISIBILITY_OPERATIONS = frozenset({OBJECT_MOVE, OBJECT_COPY, FOLDER_RENAME})

WIDENS_REASON = 'This would let more people read a file or folder than can read it now.'
MARKER_REASON = (
    "This moves or removes a folder's marker, which is what keeps the folder private, "
    'so the files left in that folder would become readable by more people.'
)
TOO_MANY_REASON = 'Too many files are affected to check who can read them afterwards (the limit is {n}).'
BUDGET_REASON = 'Checking who could read the result took more work than the limit allows.'
UNRESOLVED_REASON = 'The source or destination could not be resolved, so who can read the result could not be checked.'

# Bounds on the check. Above any of them the call asks a person instead of being checked.
MAX_OBJECTS = 300
MAX_EVALUATIONS = 3000
MAX_SECONDS = 2.5

# Ids no grant names. The probes below stand for everyone who is not named by a grant.
_PLAIN_MEMBER_ID = 2**31 - 2
_COMPANY_OWNER_ID = 2**31 - 3


class _Ask(Exception):
    """The call cannot be checked, or the check failed. It asks a person, with ``reason``."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class _GrantIndex:
    """The company's active grants, found by what they point at instead of by scanning.

    ``for_object`` returns exactly the grants ``_resource_matches_grant`` would match for an
    object, in time that depends on the path depth and not on how many grants the company has.
    """

    def __init__(self, grants: list[StorageAccessGrant]):
        self._bucket: dict[int, list[StorageAccessGrant]] = defaultdict(list)
        self._folder: dict[tuple[int, str], list[StorageAccessGrant]] = defaultdict(list)
        self._by_id: dict[str, list[StorageAccessGrant]] = defaultdict(list)
        self._by_name: dict[tuple[int, str], list[StorageAccessGrant]] = defaultdict(list)
        for g in grants:
            if g.bucket_id is None:
                continue
            if g.resource_type == StorageAccessGrant.ResourceType.BUCKET:
                self._bucket[g.bucket_id].append(g)
            elif g.object_id is None:
                continue
            elif g.resource_type == StorageAccessGrant.ResourceType.FOLDER:
                prefix = _normalize_path(folder_path_from_placeholder(g.object.name))
                self._folder[(g.bucket_id, prefix)].append(g)
            elif g.resource_type == StorageAccessGrant.ResourceType.OBJECT:
                self._by_id[str(g.object_id)].append(g)
                self._by_name[(g.bucket_id, _normalize_path(g.object.name))].append(g)

    def for_object(self, bucket_id: int, name: str, object_id: str) -> list[StorageAccessGrant]:
        path = _normalize_path(name)
        found: dict[int, StorageAccessGrant] = {g.pk: g for g in self._bucket.get(bucket_id, ())}
        parts = path.split('/') if path else []
        for depth in range(len(parts) + 1):
            for g in self._folder.get((bucket_id, '/'.join(parts[:depth])), ()):
                found[g.pk] = g
        for g in self._by_id.get(str(object_id), ()):
            if g.bucket_id == bucket_id:
                found[g.pk] = g
        for g in self._by_name.get((bucket_id, path), ()):
            found[g.pk] = g
        return list(found.values())


def _named_users(grants: list[StorageAccessGrant]) -> set[int]:
    return {
        int(g.subject_id)
        for g in grants
        if g.subject_type == StorageAccessGrant.SubjectType.USER and str(g.subject_id).isdigit() and int(g.subject_id) > 0
    }


class _Reader:
    """Who can read an object, by the real access check, with the work bounded."""

    def __init__(self, company_id: int, owner_id: int):
        self.company_id = company_id
        self.standard = [_PLAIN_MEMBER_ID, _COMPANY_OWNER_ID] + ([owner_id] if owner_id > 0 else [])
        self.evaluations = 0
        self.deadline = monotonic() + MAX_SECONDS
        self._principals: dict[int, StoragePrincipal] = {}

    def _principal(self, user_id: int) -> StoragePrincipal:
        if user_id not in self._principals:
            self._principals[user_id] = StoragePrincipal(
                user_id=user_id, company_id=self.company_id, is_company_owner=user_id == _COMPANY_OWNER_ID
            )
        return self._principals[user_id]

    def snapshot(self, ids: dict[Any, Any]) -> tuple[dict[Any, StorageObject], _GrantIndex]:
        """The affected objects and the company's grants as they are right now (two queries)."""
        objs = {o.pk: o for o in StorageObject.objects.select_related('bucket').filter(pk__in=list(ids.values()))}
        if len(objs) != len(set(ids.values())):
            raise _Ask(UNRESOLVED_REASON)
        return objs, _GrantIndex(active_grants_for_company(self.company_id))

    def readers(self, obj: StorageObject, matching: list[StorageAccessGrant], users: set[int]) -> dict[int, bool]:
        out = {}
        for uid in users:
            if self.evaluations >= MAX_EVALUATIONS or monotonic() > self.deadline:
                raise _Ask(BUDGET_REASON)
            self.evaluations += 1
            out[uid] = evaluate_access(
                self._principal(uid), obj.bucket, path=obj.name, object_id=str(obj.pk), grants=matching
            )
        return out


def _bucket(company_id: int, name: str) -> Bucket:
    bucket = Bucket.objects.filter(company_id=company_id, name=name).first()
    if bucket is None:
        raise _Ask(UNRESOLVED_REASON)
    return bucket


def _split(key: Any) -> tuple[str, str]:
    """Bucket and object path, split and normalized the way the views and services do."""
    bucket_name, _, name = str(key or '').partition('/')
    if not bucket_name or not name:
        raise _Ask(UNRESOLVED_REASON)
    try:
        return bucket_name, safe_object_path(name)
    except ValueError as exc:
        raise _Ask(UNRESOLVED_REASON) from exc


def _is_marker(name: str) -> bool:
    return name.rsplit('/', 1)[-1] == FOLDER_PLACEHOLDER_NAME


def _affected(operation_id: str, arguments: dict[str, Any], company_id: int) -> tuple[dict[Any, Any], bool]:
    """Ids of the objects the call changes, and whether it moves a folder marker.

    That is the source object, every object under a renamed prefix, and every object left in
    a folder whose marker moves (the marker is what makes that folder private).
    """
    body = arguments.get('body') if isinstance(arguments.get('body'), dict) else {}
    if operation_id == FOLDER_RENAME:
        params = arguments.get('path_params') if isinstance(arguments.get('path_params'), dict) else {}
        bucket = _bucket(company_id, str(params.get('bucket_id') or ''))
        source = str(body.get('from') or body.get('prefix') or body.get('source') or '')
        try:
            src = safe_object_path(source).strip('/')
        except ValueError as exc:
            raise _Ask(UNRESOLVED_REASON) from exc
        objs = list(objects_under_prefix(bucket, src)[: MAX_OBJECTS + 1]) if src else []
        if not objs:
            raise _Ask(UNRESOLVED_REASON)
    else:
        bucket_name, name = _split(body.get('sourceKey') or body.get('from'))
        bucket = _bucket(company_id, bucket_name)
        src_obj = StorageObject.objects.filter(bucket=bucket, name=name).first()
        if src_obj is None:
            raise _Ask(UNRESOLVED_REASON)
        objs = [src_obj]

    affected = {o.pk: o.pk for o in objs}
    moves_marker = False
    if operation_id != OBJECT_COPY:
        for o in objs:
            if _is_marker(o.name) and folder_path_from_placeholder(o.name):
                moves_marker = True
                for left in objects_under_prefix(bucket, folder_path_from_placeholder(o.name))[: MAX_OBJECTS + 1]:
                    affected.setdefault(left.pk, left.pk)
    if len(affected) > MAX_OBJECTS:
        raise _Ask(TOO_MANY_REASON.format(n=MAX_OBJECTS))
    return affected, moves_marker


def checked(
    operation_id: str,
    arguments: dict[str, Any],
    principal: Any,
    run: Callable[[], Any],
) -> tuple[bool, Any]:
    """Run the agent's move, copy or rename with the visibility check.

    Returns ``(True, result)`` when ``run()`` committed, or ``(False, reason)`` when the call
    must ask a person first. In that case nothing was written, in the database or in S3.

    Inside one transaction: lock the company's buckets, record who can read each affected
    object, let ``run()`` do the real write, record who can read afterwards (the services call
    ``write_guard.after_write`` once their rows are written and before a blob is copied), and
    roll back if anyone gained read access. Only the grants that apply to an object are
    evaluated, for a plain member, a company owner, the caller's creator and the people those
    grants name. More than ``MAX_OBJECTS`` objects, or more work than ``MAX_EVALUATIONS`` or
    ``MAX_SECONDS`` allows, asks.
    """
    company_id = getattr(principal, 'company_id', None)
    if company_id is None:
        return False, UNRESOLVED_REASON
    company_id = int(company_id)
    owner_id = int(getattr(principal, 'user_id', 0) or 0)
    token = None
    try:
        with transaction.atomic():
            lock_company_buckets(company_id)
            before_ids, moves_marker = _affected(operation_id, arguments, company_id)
            reader = _Reader(company_id, owner_id)
            objs, index = reader.snapshot(before_ids)
            before: dict[Any, dict[int, bool]] = {}
            before_named: dict[Any, set[int]] = {}
            for key, oid in before_ids.items():
                obj = objs[oid]
                matching = index.for_object(obj.bucket_id, obj.name, str(obj.pk))
                before_named[key] = _named_users(matching)
                before[key] = reader.readers(obj, matching, set(reader.standard) | before_named[key])

            done = False

            def after(new_ids: dict[Any, Any] | None) -> None:
                nonlocal done
                done = True
                ids = new_ids if new_ids is not None else before_ids
                try:
                    new_objs, new_index = reader.snapshot({k: ids[k] for k in before_ids})
                    for key in before_ids:
                        obj = new_objs[ids[key]]
                        matching = new_index.for_object(obj.bucket_id, obj.name, str(obj.pk))
                        users = set(reader.standard) | before_named[key] | _named_users(matching)
                        now = reader.readers(obj, matching, users)
                        baseline = before[key]
                        for uid, can in now.items():
                            if can and not baseline.get(uid, baseline[_PLAIN_MEMBER_ID]):
                                raise write_guard.WriteWouldWiden(MARKER_REASON if moves_marker else WIDENS_REASON)
                except _Ask as ask:
                    raise write_guard.WriteWouldWiden(ask.reason) from ask

            token = write_guard.activate(after)
            try:
                result = run()
            finally:
                write_guard.deactivate(token)
            if not done and operation_id != OBJECT_COPY and getattr(result, 'status_code', 200) < 400:
                after(None)
            return True, result
    except write_guard.WriteWouldWiden as widen:
        return False, widen.reason
    except _Ask as ask:
        return False, ask.reason


def approval_reason_for_agent_call(operation_id: str, arguments: dict[str, Any]) -> str | None:
    """Why this agent call needs approval even when its access mode would allow it, or None."""
    return ALWAYS_APPROVE_OPERATIONS.get(operation_id)


def destructive_reason(operation_id: str, arguments: dict[str, Any]) -> str | None:
    """Why a destructive call asks, when a person needs more than "this deletes something"."""
    if operation_id == OBJECT_DESTROY:
        params = arguments.get('path_params') if isinstance(arguments.get('path_params'), dict) else {}
        name = str(params.get('object_path') or '').strip('/')
        if _is_marker(name):
            return MARKER_REASON
    return None
