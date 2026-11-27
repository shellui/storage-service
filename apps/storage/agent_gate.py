"""Changes that always need a person's approval when an agent makes them.

``decide_write`` lets a non-destructive write through in Full mode. These calls are
different: they create a way for data or access to leave the agent's own files, or they
change limits. An agent asks first, in every access mode, with a single-use approval bound
to the exact arguments. Read only agents are still refused outright.
"""

from __future__ import annotations

from typing import Any

from .access import (
    default_private_would_apply,
    path_access_summary,
)
from .models import Bucket, StorageAccessGrant, StorageObject, folder_path_from_placeholder

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

WIDENS_VISIBILITY_REASON = 'Moving or copying a file somewhere more people can see it requires approval.'

_COPY_MOVE_OPERATIONS = frozenset({'storage_v1_object_copy_create', 'storage_v1_object_move_create'})


def _audience(summary: dict[str, Any]) -> tuple[bool, frozenset[str], frozenset[str]]:
    """(whole company can read, allowed user ids, allowed group ids) from an access summary."""
    company = summary.get('audience') != 'restricted'
    users = frozenset(str(u) for u in summary.get('allowed_user_ids') or [])
    groups = frozenset(str(g) for g in summary.get('allowed_group_ids') or [])
    return company, users, groups


def _wider(
    source: tuple[bool, frozenset[str], frozenset[str]],
    dest: tuple[bool, frozenset[str], frozenset[str]],
) -> bool:
    src_company, src_users, src_groups = source
    dst_company, dst_users, dst_groups = dest
    if src_company:
        return False
    return bool(dst_company or (dst_users - src_users) or (dst_groups - src_groups))


def _split(key: Any) -> tuple[str, str]:
    bucket_name, _, name = str(key or '').partition('/')
    return bucket_name, name


def copy_or_move_widens_visibility(
    operation_id: str,
    arguments: dict[str, Any],
    principal: Any,
) -> bool:
    """True when the copy or move would let more people see the file than at the source.

    Unknown buckets or files return False: the call fails on its own and changes nothing.
    """
    if operation_id not in _COPY_MOVE_OPERATIONS:
        return False
    body = arguments.get('body') if isinstance(arguments.get('body'), dict) else {}
    src_bucket_name, src_name = _split(body.get('sourceKey') or body.get('from'))
    dst_bucket_name, dst_name = _split(body.get('destinationKey') or body.get('to'))
    if not (src_bucket_name and src_name and dst_bucket_name and dst_name):
        return False
    company_id = getattr(principal, 'company_id', None)
    if company_id is None:
        return False
    src_bucket = Bucket.objects.filter(company_id=company_id, name=src_bucket_name).first()
    dst_bucket = Bucket.objects.filter(company_id=company_id, name=dst_bucket_name).first()
    if src_bucket is None or dst_bucket is None:
        return False
    src_obj = StorageObject.objects.filter(bucket=src_bucket, name=src_name).first()
    if src_obj is None:
        return False

    source = _audience(path_access_summary(src_bucket, path=src_name, object_id=str(src_obj.id)))
    if operation_id == 'storage_v1_object_move_create':
        has_own_grants = StorageAccessGrant.objects.filter(
            company_id=company_id,
            resource_type=StorageAccessGrant.ResourceType.OBJECT,
            object=src_obj,
        ).exists()
        if has_own_grants:
            # The file's own grants move with it and are more specific than any folder.
            return False
        dest = _audience(path_access_summary(dst_bucket, path=dst_name))
        return _wider(source, dest)

    owner_id = getattr(principal, 'user_id', None)
    private_to_owner = (
        isinstance(owner_id, int)
        and owner_id > 0
        and default_private_would_apply(company_id=int(company_id), bucket_name=dst_bucket.name, name=dst_name)
    )
    if private_to_owner:
        dest = (False, frozenset({str(owner_id)}), frozenset())
    else:
        dest = _audience(path_access_summary(dst_bucket, path=folder_path_from_placeholder(dst_name) or dst_name))
    return _wider(source, dest)


def approval_reason_for_agent_call(operation_id: str, arguments: dict[str, Any], principal: Any) -> str | None:
    """Why this agent call needs approval even when its access mode would allow it, or None."""
    reason = ALWAYS_APPROVE_OPERATIONS.get(operation_id)
    if reason:
        return reason
    if copy_or_move_widens_visibility(operation_id, arguments, principal):
        return WIDENS_VISIBILITY_REASON
    return None
