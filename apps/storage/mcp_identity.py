"""Calls to identity-service for MCP revocations, approvals, and call logs."""

from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from functools import lru_cache
from typing import Any

import requests
from django.conf import settings
from django.core.cache import cache

from shellui_django.mcp.internal import (
    REVOCATION_CACHE_SECONDS,
    InternalAssertionError,
    build_mcp_approval_assertion,
    build_mcp_call_log_assertion,
    build_mcp_revocation_assertion,
    verify_mcp_revocation_list_response,
)

from apps.authapi.mcp_authority import (
    DelegatedAuthorityDenied,
    DelegatedAuthorityUnavailable,
    delegated_regional_authority_live_ok,
)
from apps.storage.mcp_assertions import (
    parse_company_binding_version,
    parse_global_agent_id,
    parse_global_company_id,
    parse_grant_version,
    parse_trusted_agent_claims,
)
from config.service_signing import signing_kwargs

logger = logging.getLogger(__name__)

_REVOKED_CACHE_KEY = 'mcp:revoked_trusted_payload'
_REVOKED_TRUST_KEY = 'mcp:revoked_list_trusted'
_REVOKED_VERIFIED_KEY = 'mcp:revoked_verified_claims'
_REVOKED_EPOCH_KEY = 'mcp:revoked_cache_epoch'
_REVOKED_LOCK = threading.Lock()

# Allowlist forwarded to Identity call logs (shellui-django / gateway contract).
_CALL_LOG_APPROVED_KEYS = frozenset(
    {
        'agent_id',
        'company_id',
        'global_company_id',
        'global_agent_id',
        'grant_version',
        'company_binding_version',
        'service',
        'tool',
        'http_method',
        'resource_path',
        'access_kind',
        'outcome',
        'status',
        'duration_ms',
        'approval_request_id',
        'approval_id',
        'error_code',
    }
)

_CALL_LOG_OUTCOMES = frozenset(
    {
        'pending_approval',
        'allowed',
        'denied',
        'failed',
        'session_used',
    }
)

_CALL_LOG_ACCESS_KINDS = frozenset({'read', 'write'})

_APPROVAL_HTTP_METHODS = frozenset({'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'})

_APPROVAL_STATUS_OK = frozenset({'approved', 'pending', 'denied', 'expired'})
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I
)


def _identity_origin() -> str:
    return (getattr(settings, 'IDENTITY_SERVICE_URL', '') or settings.IDENTITY_ISSUER or '').rstrip('/')


def _identity_audience(origin: str) -> str:
    """Identity checks internal assertions against its public issuer, not the internal URL we call."""
    return (settings.IDENTITY_ISSUER or origin).rstrip('/')


def _revocation_headers(origin: str) -> dict[str, str]:
    assertion = build_mcp_revocation_assertion(audience_url=_identity_audience(origin), **signing_kwargs())
    return {'Authorization': f'Bearer {assertion}'}


def _revocation_verify_kwargs(origin: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = {'expected_issuer': settings.IDENTITY_ISSUER or origin}
    document = getattr(settings, 'IDENTITY_JWKS_DOCUMENT', None)
    if document is not None:
        kwargs['jwks'] = document
    else:
        jwks_url = getattr(settings, 'IDENTITY_JWKS_URL', None)
        if jwks_url:
            kwargs['identity_jwks_url'] = jwks_url
    return kwargs


def _mark_revocation_untrusted() -> None:
    cache.delete(_REVOKED_CACHE_KEY)
    cache.delete(_REVOKED_VERIFIED_KEY)
    cache.set(_REVOKED_TRUST_KEY, False, timeout=REVOCATION_CACHE_SECONDS)
    _bump_revocation_epoch()


def _bump_revocation_epoch() -> None:
    try:
        cache.incr(_REVOKED_EPOCH_KEY)
    except ValueError:
        cache.set(_REVOKED_EPOCH_KEY, 1, timeout=None)


def revocation_cache_epoch() -> int:
    v = cache.get(_REVOKED_EPOCH_KEY)
    return int(v) if isinstance(v, int) and not isinstance(v, bool) else 0


def _store_trusted_revocation(
    *,
    revoked_ids: frozenset[str],
    agents: list[dict[str, Any]],
    cache_seconds: int,
    verified_signed_claims: dict[str, Any],
) -> None:
    cache.set(
        _REVOKED_CACHE_KEY,
        {
            'revoked_ids': sorted(revoked_ids),
            'agents': agents,
            'cache_seconds': cache_seconds,
        },
        timeout=max(cache_seconds, REVOCATION_CACHE_SECONDS),
    )
    cache.set(_REVOKED_VERIFIED_KEY, verified_signed_claims, timeout=max(cache_seconds, REVOCATION_CACHE_SECONDS))
    cache.set(_REVOKED_TRUST_KEY, True, timeout=max(cache_seconds, REVOCATION_CACHE_SECONDS))
    _bump_revocation_epoch()


def _cached_revocation() -> dict[str, Any] | None:
    if cache.get(_REVOKED_TRUST_KEY) is not True:
        return None
    raw = cache.get(_REVOKED_CACHE_KEY)
    if not isinstance(raw, dict):
        return None
    return raw


def _verified_revocation_claims() -> dict[str, Any] | None:
    if cache.get(_REVOKED_TRUST_KEY) is not True:
        return None
    raw = cache.get(_REVOKED_VERIFIED_KEY)
    return raw if isinstance(raw, dict) else None


def _agent_blocked_for_tenant(agent_id: str, *, company_id: int | None, payload: dict[str, Any]) -> bool:
    revoked_ids = {str(item) for item in (payload.get('revoked_ids') or [])}
    if str(agent_id) not in revoked_ids:
        return False
    if company_id is None:
        return True
    agents = payload.get('agents') or []
    if not agents:
        return True
    for entry in agents:
        if str(entry.get('agent_id') or '') != str(agent_id):
            continue
        entry_company = entry.get('company_id')
        if entry_company is None:
            return True
        try:
            return int(entry_company) == int(company_id)
        except (TypeError, ValueError):
            return False
    return False


def _refresh_revocations() -> bool:
    """Return True when identity answered with a trusted signed revocation list."""
    origin = _identity_origin()
    if not origin:
        _mark_revocation_untrusted()
        return False
    url = f'{origin}/api/v1/mcp/internal/mcp-revocations'
    try:
        headers = _revocation_headers(origin)
    except InternalAssertionError as exc:
        logger.warning('MCP revocation poll skipped: %s', exc.message)
        _mark_revocation_untrusted()
        return False
    try:
        response = requests.get(url, headers=headers, timeout=5)
    except requests.RequestException as exc:
        logger.warning('MCP revocation poll failed: %s', type(exc).__name__)
        _mark_revocation_untrusted()
        return False
    if response.status_code == 404 or response.status_code >= 400:
        logger.warning('MCP revocation poll rejected: %s', response.status_code)
        _mark_revocation_untrusted()
        return False
    try:
        body = response.json()
    except ValueError:
        _mark_revocation_untrusted()
        return False
    try:
        trusted = verify_mcp_revocation_list_response(
            body,
            **_revocation_verify_kwargs(origin),
        )
    except InternalAssertionError as exc:
        logger.warning('MCP revocation list untrusted: %s', exc.message)
        _mark_revocation_untrusted()
        return False
    revoked_ids = frozenset(trusted['revoked_agent_ids'])
    cache_seconds = int(trusted['cache_seconds'] or REVOCATION_CACHE_SECONDS)
    agents = list(trusted.get('agents') or [])
    rp = trusted.get('revocation_policy_version')
    mv = trusted.get('max_active_grant_version')
    rp_int = parse_grant_version(rp) if rp is not None else None
    if rp is not None and rp_int is None:
        logger.warning('MCP revocation list has invalid revocation_policy_version')
        _mark_revocation_untrusted()
        return False
    mv_int = parse_grant_version(mv) if mv is not None else None
    if mv is not None and mv_int is None:
        logger.warning('MCP revocation list has invalid max_active_grant_version')
        _mark_revocation_untrusted()
        return False
    _store_trusted_revocation(
        revoked_ids=revoked_ids,
        agents=agents,
        cache_seconds=cache_seconds,
        verified_signed_claims={
            'revocation_policy_version': rp_int,
            'max_active_grant_version': mv_int,
        },
    )
    return True


def identity_revocation_unavailable() -> bool:
    """True when the signed revocation list cannot be loaded (fail closed at the HTTP layer)."""
    if _cached_revocation() is not None:
        return False
    with _REVOKED_LOCK:
        if _cached_revocation() is not None:
            return False
        _refresh_revocations()
    return _cached_revocation() is None


def _regional_company_id(claims: dict[str, Any]) -> int | None:
    raw = claims.get('company_id')
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 0:
        return None
    return raw


def _snapshot_row_grant_version(row: dict[str, Any]) -> int | None:
    """Snapshot ``grant_version``: non-negative int only (no string coercion)."""
    if 'grant_version' not in row:
        return None
    v = row.get('grant_version')
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        return None
    return v


def _snapshot_row_company_binding_version(row: dict[str, Any]) -> int | None:
    """Snapshot ``company_binding_version``: non-negative int only (no string coercion)."""
    if 'company_binding_version' not in row:
        return None
    v = row.get('company_binding_version')
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        return None
    return v


def _grant_row_snapshot_fields(row: dict[str, Any]) -> tuple[int | None, str | None, int | None]:
    """Regional company id, global company UUID, grant version from Identity snapshot row."""
    rc: int | None = None
    raw_c = row.get('company_id')
    if raw_c is not None:
        if not isinstance(raw_c, int) or isinstance(raw_c, bool) or raw_c < 0:
            rc = None
        else:
            rc = raw_c
    gg = parse_global_company_id(row.get('global_company_id'))
    gv = _snapshot_row_grant_version(row)
    return rc, gg, gv


def _row_global_pair_consistent(row: dict[str, Any]) -> bool:
    g_pres = row.get('global_company_id') is not None
    raw_b = row.get('company_binding_version')
    # Reject non-integer snapshot fields so string digits do not match token ints.
    b_pres = raw_b is not None and isinstance(raw_b, int) and not isinstance(raw_b, bool) and raw_b >= 0
    return g_pres == b_pres


def _authority_row_status(
    agent_id: str, agent_claims: dict[str, Any]
) -> tuple[str, dict[str, Any] | None]:
    """
    Select at most one revocation snapshot row for this agent and token.

    Returns (status, row) where status is:
    - ``exact``: exactly one row matches (delegated: regional + global triple; personal: regional only)
    - ``absent``: no rows list this ``agent_id`` (authority proof deferred to caps and revoked ids)
    - ``missing``: rows exist for this agent but none match this token (fail closed for delegated;
      personal treat as stale or wrong tenant)
    - ``ambiguous``: more than one row would match (never pick ``candidates[0]``)
    """
    payload = _cached_revocation()
    if not payload:
        return 'missing', None
    agents = payload.get('agents') or []
    if not isinstance(agents, list):
        return 'missing', None

    entries = [
        e
        for e in agents
        if isinstance(e, dict) and str(e.get('agent_id') or '') == str(agent_id)
    ]
    if not entries:
        return 'absent', None

    token_rc = _regional_company_id(agent_claims)
    token_gg = parse_global_company_id(agent_claims.get('global_company_id'))
    token_gai = parse_global_agent_id(agent_claims.get('global_agent_id'))
    delegated = token_gg is not None or token_gai is not None

    if delegated:
        if token_rc is None or token_gg is None:
            return 'missing', None
        matches: list[dict[str, Any]] = []
        for entry in entries:
            if not _row_global_pair_consistent(entry):
                continue
            rc, gg, _gv = _grant_row_snapshot_fields(entry)
            if entry.get('global_company_id') is None:
                continue
            if gg is None or gg != token_gg:
                continue
            if rc is None or rc != token_rc:
                continue
            matches.append(entry)
        if len(matches) == 1:
            return 'exact', matches[0]
        if len(matches) == 0:
            return 'missing', None
        return 'ambiguous', None

    matches = []
    for entry in entries:
        if not _row_global_pair_consistent(entry):
            continue
        if entry.get('global_company_id') is not None:
            continue
        rc, _gg, _gv = _grant_row_snapshot_fields(entry)
        if token_rc is None or rc is None or rc != token_rc:
            continue
        matches.append(entry)
    if len(matches) == 1:
        return 'exact', matches[0]
    if len(matches) == 0:
        return 'missing', None
    return 'ambiguous', None


def _grant_row_matches_agent(agent_claims: dict[str, Any], row: dict[str, Any]) -> bool:
    if not _row_global_pair_consistent(row):
        return False
    rc_row, gg_row, gv_row = _grant_row_snapshot_fields(row)
    rc_tok = _regional_company_id(agent_claims)
    gg_tok = parse_global_company_id(agent_claims.get('global_company_id'))
    token_gai = parse_global_agent_id(agent_claims.get('global_agent_id'))
    delegated = gg_tok is not None or token_gai is not None
    gv_tok = (
        parse_grant_version(agent_claims.get('grant_version'))
        if 'grant_version' in agent_claims
        else None
    )
    cb_tok = (
        parse_company_binding_version(agent_claims.get('company_binding_version'))
        if 'company_binding_version' in agent_claims
        else None
    )

    if delegated:
        if gg_row is None or gg_tok is None or gg_row != gg_tok:
            return False
        if rc_tok is None or rc_row is None or rc_tok != rc_row:
            return False
        cb_row = _snapshot_row_company_binding_version(row)
        if cb_tok is None or cb_row is None:
            return False
        if gv_tok is None or gv_row is None:
            return False
        return cb_tok == cb_row and gv_tok == gv_row

    if rc_row is None or rc_tok is None or rc_row != rc_tok:
        return False
    if row.get('global_company_id') is not None:
        return False
    if gv_tok is None and gv_row is None:
        return True
    if gv_tok is None or gv_row is None:
        return False
    return gv_tok == gv_row


def agent_is_revoked(agent_id: str, company_id: int | None = None, agent_claims: dict[str, Any] | None = None) -> bool:
    """True when the trusted list marks this agent revoked for the given company (fail closed)."""
    if identity_revocation_unavailable():
        return True
    payload = _cached_revocation()
    if payload is None:
        return True
    if _agent_blocked_for_tenant(str(agent_id), company_id=company_id, payload=payload):
        return True
    if agent_claims:
        delegated_tok = (
            parse_global_company_id(agent_claims.get('global_company_id')) is not None
            or parse_global_agent_id(agent_claims.get('global_agent_id')) is not None
        )
        status, row = _authority_row_status(str(agent_id), agent_claims)
        if status in ('missing', 'ambiguous'):
            return True
        if delegated_tok:
            if status == 'absent' or row is None or not _grant_row_matches_agent(agent_claims, row):
                return True
        elif row is not None and not _grant_row_matches_agent(agent_claims, row):
            return True
    return False


def max_active_grant_version() -> int | None:
    vc = _verified_revocation_claims()
    if not vc:
        return None
    return parse_grant_version(vc.get('max_active_grant_version'))


def revocation_policy_version() -> int | None:
    vc = _verified_revocation_claims()
    if not vc:
        return None
    return parse_grant_version(vc.get('revocation_policy_version'))


def grant_versions_compatible(agent_claims: dict[str, Any]) -> bool | None:
    """None when signed policy is unusable; False when token is stale; True when ok."""
    mv = max_active_grant_version()
    gv = parse_grant_version(agent_claims.get('grant_version')) if 'grant_version' in agent_claims else None
    delegated = (
        parse_global_company_id(agent_claims.get('global_company_id')) is not None
        or parse_global_agent_id(agent_claims.get('global_agent_id')) is not None
    )
    if delegated:
        agent_id = str(agent_claims.get('agent_id') or '')
        if not agent_id:
            return None
        status, row = _authority_row_status(agent_id, agent_claims)
        if status == 'absent':
            return False
        if status != 'exact' or row is None or not _grant_row_matches_agent(agent_claims, row):
            return False
        if mv is None:
            return None
        if gv is None:
            return False
        return gv >= mv
    agent_id = str(agent_claims.get('agent_id') or '')
    if agent_id:
        st, _row = _authority_row_status(agent_id, agent_claims)
        if st == 'absent':
            return True
    if mv is None:
        return True
    if gv is None:
        return True
    return gv >= mv


def delegated_live_authority_gate(
    payload: dict[str, Any], agent_claims: dict[str, Any]
) -> tuple[bool, bool]:
    """
    Returns (allow, identity_unavailable).

    When a regional resource token carries the delegated exchange triple, Identity must
    confirm the live row before approval calls and before direct tools.
    """
    ok_claims, _reason, norm = parse_trusted_agent_claims(agent_claims)
    if not ok_claims or norm is None:
        return False, False
    if norm.get('global_company_id') is None:
        return True, False
    if norm.get('mcp_authority') != 'delegated':
        return False, False
    expected = payload.get('mcp_expected_resource')
    if not isinstance(expected, str) or not expected.strip():
        return False, False
    try:
        delegated_regional_authority_live_ok(agent_claims, expected_resource=expected)
        return True, False
    except DelegatedAuthorityUnavailable:
        return False, True
    except DelegatedAuthorityDenied:
        return False, False


def identity_token_ok(agent_claims: dict[str, Any]) -> tuple[bool, str]:
    """Strict claim shape for MCP (all tools). Returns (ok, reason_code)."""
    ok, reason, _norm = parse_trusted_agent_claims(agent_claims)
    return ok, reason


def _approval_assertion_from_payload(payload: dict[str, Any], agent_claims: dict[str, Any]) -> str | None:
    origin = _identity_origin()
    agent_id = str(payload.get('agent_id') or '')
    company_id = payload.get('company_id')
    args_hash = str(payload.get('arguments_hash') or '')
    if not origin or not agent_id or company_id is None or not args_hash:
        return None
    if not isinstance(company_id, int) or isinstance(company_id, bool) or company_id < 1:
        return None
    company_int = company_id

    ok_claims, _reason, _norm = parse_trusted_agent_claims(agent_claims)
    if not ok_claims:
        return None
    gv = parse_grant_version(agent_claims.get('grant_version')) if 'grant_version' in agent_claims else None
    gcid = parse_global_company_id(agent_claims.get('global_company_id'))
    cbv_raw = agent_claims.get('company_binding_version')
    cbv = parse_company_binding_version(cbv_raw) if cbv_raw is not None else None
    if gcid is not None:
        if gv is None or cbv is None:
            return None

    try:
        return build_mcp_approval_assertion(
            company_id=company_int,
            agent_id=agent_id,
            service=str(payload.get('service') or 'storage'),
            action=str(payload.get('action') or ''),
            arguments_hash=args_hash,
            audience_url=_identity_audience(origin),
            grant_version=gv,
            global_company_id=gcid,
            company_binding_version=cbv,
            **signing_kwargs(),
        )
    except InternalAssertionError as exc:
        logger.warning('MCP approval assertion unavailable: %s', exc.message)
        return None


def create_approval_request(payload: dict[str, Any], agent_claims: dict[str, Any]) -> dict | None:
    try:
        allow, unavailable = delegated_live_authority_gate(payload, agent_claims)
    except DelegatedAuthorityDenied:
        allow, unavailable = False, False
    if unavailable:
        return {'_approval_error': True, 'error_code': 'identity_unavailable', 'message': 'Approval unavailable.'}
    if not allow:
        return {'_approval_error': True, 'error_code': 'forbidden', 'message': 'Forbidden.'}
    origin = _identity_origin()
    assertion = _approval_assertion_from_payload(payload, agent_claims)
    if not origin or not assertion:
        return {'_approval_error': True, 'error_code': 'approval_unavailable', 'message': 'Approval unavailable.'}
    try:
        response = requests.post(
            f'{origin}/api/v1/mcp/internal/mcp-approval-requests',
            json={},
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.warning('MCP approval request unreachable: %s', type(exc).__name__)
        return {'_approval_error': True, 'error_code': 'upstream_error', 'message': 'Approval unavailable.'}
    if response.status_code == 404 or response.status_code >= 400:
        logger.warning('MCP approval request failed: %s', response.status_code)
        return {'_approval_error': True, 'error_code': 'upstream_error', 'message': 'Approval unavailable.'}
    try:
        data = response.json()
    except ValueError:
        return {'_approval_error': True, 'error_code': 'upstream_error', 'message': 'Approval unavailable.'}
    if not isinstance(data, dict):
        return {'_approval_error': True, 'error_code': 'upstream_error', 'message': 'Approval unavailable.'}
    rid = data.get('id')
    if rid is None or not _UUID_RE.match(str(rid)):
        return {'_approval_error': True, 'error_code': 'upstream_error', 'message': 'Approval unavailable.'}
    return data


def approval_state(payload: dict[str, Any], agent_claims: dict[str, Any]) -> str | None:
    """Resolve approval status from identity-service. Fail closed on errors."""
    allow, unavailable = delegated_live_authority_gate(payload, agent_claims)
    if unavailable:
        return 'error'
    if not allow:
        return 'error'
    origin = _identity_origin()
    assertion = _approval_assertion_from_payload(payload, agent_claims)
    if not origin or not assertion:
        return 'error'
    try:
        response = requests.post(
            f'{origin}/api/v1/mcp/internal/mcp-approval-state',
            json={},
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
    except requests.RequestException:
        return 'error'
    if response.status_code == 404:
        return None
    if response.status_code >= 400:
        return 'error'
    try:
        data = response.json()
    except ValueError:
        return 'error'
    if not isinstance(data, dict):
        return 'error'
    state = str(data.get('status') or '')
    if state not in _APPROVAL_STATUS_OK:
        return 'error'
    if state == 'approved':
        aid = data.get('id')
        if aid is None or not _UUID_RE.match(str(aid)):
            return 'error'
        payload['approval_id'] = str(aid)
        return 'approved'
    if state == 'pending':
        return 'pending'
    if state == 'denied':
        return 'denied'
    if state == 'expired':
        return 'expired'
    return 'error'


@lru_cache(maxsize=1)
def _cached_openapi_schema_public() -> dict[str, Any]:
    """OpenAPI schema for MCP tools (same as ``POST /mcp``); cached per process."""
    from drf_spectacular.generators import SchemaGenerator

    return SchemaGenerator().get_schema(request=None, public=True)


def clear_mcp_call_log_schema_cache() -> None:
    """Drop the OpenAPI cache (for tests or after schema-changing reloads)."""
    _cached_openapi_schema_public.cache_clear()


def _registry_operation_for_call_log(
    tool_name: str, resource_path: str, http_method: str
) -> tuple[str, str] | None:
    """
    Resolve OpenAPI ``summary`` and path template for a tool when the triple matches.

    Rejects caller-supplied titles or paths that do not match the published operationId and template.
    """
    schema = _cached_openapi_schema_public()
    paths = schema.get('paths') or {}
    if not isinstance(paths, dict):
        return None
    p_item = paths.get(resource_path)
    if not isinstance(p_item, dict):
        return None
    op = p_item.get(str(http_method).lower())
    if not isinstance(op, dict):
        return None
    if str(op.get('operationId') or '') != str(tool_name):
        return None
    summary = (op.get('summary') or '').strip()
    title = (summary[:256] if summary else str(tool_name))[:256]
    p = resource_path.split('?', 1)[0].strip()
    if not p.startswith('/') or '\n' in p:
        return None
    return title, p[:2048]


def consume_approval(
    approval_id: str,
    payload: dict[str, Any] | None,
    agent_claims: dict[str, Any],
) -> bool:
    payload = payload or {}
    allow, unavailable = delegated_live_authority_gate(payload, agent_claims)
    if unavailable or not allow:
        return False
    origin = _identity_origin()
    assertion = _approval_assertion_from_payload(payload, agent_claims)
    if not origin or not approval_id or not assertion:
        return False
    if not _UUID_RE.match(str(approval_id)):
        return False
    try:
        response = requests.post(
            f'{origin}/api/v1/mcp/internal/mcp-approval-consume',
            json={'approval_id': str(approval_id)},
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
    except requests.RequestException:
        return False
    if response.status_code == 404 or response.status_code >= 400:
        return False
    try:
        data = response.json()
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    return data.get('consumed') is True


def _sanitize_call_log_entry(entry: dict[str, Any]) -> dict[str, Any]:
    tool = entry.get('tool')
    resource_path = entry.get('resource_path')
    http_method = entry.get('http_method')
    if not isinstance(tool, str) or not tool.strip():
        return {}
    if not isinstance(resource_path, str) or not isinstance(http_method, str):
        return {}
    method_u = http_method.strip().upper()
    if method_u not in _APPROVAL_HTTP_METHODS:
        return {}
    reg = _registry_operation_for_call_log(tool.strip(), resource_path, method_u)
    if reg is None:
        return {}
    operation_title, path_template = reg

    out: dict[str, Any] = {
        'tool': tool.strip()[:500],
        'resource_path': path_template,
        'http_method': method_u,
    }
    for key in _CALL_LOG_APPROVED_KEYS:
        if key in ('tool', 'resource_path', 'http_method'):
            continue
        if key not in entry:
            continue
        val = entry[key]
        if key == 'error_code' and isinstance(val, str) and val:
            out[key] = val[:128]
        elif key in ('duration_ms', 'status', 'grant_version', 'company_binding_version'):
            if isinstance(val, int) and not isinstance(val, bool) and val >= 0:
                out[key] = val
        elif key == 'company_id' and isinstance(val, int) and not isinstance(val, bool) and val >= 1:
            out[key] = val
        elif key == 'global_company_id' and isinstance(val, str) and parse_global_company_id(val):
            out[key] = parse_global_company_id(val)
        elif key == 'global_agent_id' and isinstance(val, str) and parse_global_agent_id(val):
            out[key] = parse_global_agent_id(val)
        elif key == 'outcome' and isinstance(val, str) and val in _CALL_LOG_OUTCOMES:
            out[key] = val
        elif key == 'access_kind' and isinstance(val, str) and val in _CALL_LOG_ACCESS_KINDS:
            out[key] = val
        elif key in ('agent_id', 'service'):
            if isinstance(val, str) and val:
                out[key] = val[:500]
        elif key in ('approval_request_id', 'approval_id'):
            if isinstance(val, str) and val and _UUID_RE.match(val):
                out[key] = val
    if 'outcome' not in out or out.get('outcome') not in _CALL_LOG_OUTCOMES:
        return {}
    if 'access_kind' not in out or out.get('access_kind') not in _CALL_LOG_ACCESS_KINDS:
        return {}
    return out


def forward_call_log(entry: dict[str, Any]) -> None:
    origin = _identity_origin()
    if not origin:
        return
    safe = _sanitize_call_log_entry(entry)
    if not safe:
        return
    try:
        assertion = build_mcp_call_log_assertion(audience_url=_identity_audience(origin), **signing_kwargs())
    except InternalAssertionError as exc:
        logger.warning('MCP call log skipped: %s', exc.message)
        return
    try:
        requests.post(
            f'{origin}/api/v1/mcp/internal/mcp-call-logs',
            json=safe,
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.debug('MCP call log forward failed: %s', type(exc).__name__)


def warm_revocation_cache() -> None:
    """Best-effort background refresh (tests may call directly)."""
    _refresh_revocations()
    time.sleep(0)
