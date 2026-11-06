"""Calls to identity-service for MCP revocations, approvals, and call logs."""

from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from typing import Any

import jwt
import requests
from django.conf import settings
from django.core.cache import cache

from shellui_django.mcp.internal import (
    REVOCATION_CACHE_SECONDS,
    InternalAssertionError,
    build_mcp_call_log_assertion,
    build_mcp_revocation_assertion,
    parse_trusted_revocation_poll_response,
)

from apps.storage.mcp_assertions import (
    build_mcp_approval_assertion_identity_bound,
    parse_company_binding_version,
    parse_global_company_id,
    parse_grant_version,
    parse_trusted_agent_claims,
)
from config.service_signing import signing_kwargs

logger = logging.getLogger(__name__)

_REVOKED_CACHE_KEY = 'mcp:revoked_trusted_payload'
_REVOKED_TRUST_KEY = 'mcp:revoked_list_trusted'
_REVOKED_VERIFIED_KEY = 'mcp:revoked_verified_claims'
_REVOKED_LOCK = threading.Lock()

# Allowlist forwarded to Identity call logs (shellui-django / gateway contract).
_CALL_LOG_APPROVED_KEYS = frozenset(
    {
        'agent_id',
        'company_id',
        'global_company_id',
        'grant_version',
        'company_binding_version',
        'service',
        'tool',
        'operation_title',
        'method',
        'path',
        'access_kind',
        'destructive',
        'read_level',
        'outcome',
        'status',
        'duration_ms',
        'approval_request_id',
        'approval_id',
        'error',
        'result_shape',
    }
)

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


def _parse_verified_revocation_jwt(token: str) -> dict[str, Any] | None:
    try:
        unverified = jwt.decode(token, options={'verify_signature': False})
    except Exception:
        return None
    return unverified if isinstance(unverified, dict) else None


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
        logger.warning('MCP revocation poll failed: %s', exc)
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
        revoked_ids, cache_seconds, agents = parse_trusted_revocation_poll_response(
            body,
            **_revocation_verify_kwargs(origin),
        )
    except InternalAssertionError as exc:
        logger.warning('MCP revocation list untrusted: %s', exc.message)
        _mark_revocation_untrusted()
        return False
    token = body.get('revocation_assertion') or body.get('assertion')
    if not isinstance(token, str) or not token.strip():
        _mark_revocation_untrusted()
        return False
    verified = _parse_verified_revocation_jwt(token.strip())
    if not verified:
        _mark_revocation_untrusted()
        return False
    rp = parse_grant_version(verified.get('revocation_policy_version'))
    if rp is None:
        logger.warning('MCP revocation JWT missing revocation_policy_version')
        _mark_revocation_untrusted()
        return False
    mv = parse_grant_version(verified.get('max_active_grant_version'))
    if mv is None:
        logger.warning('MCP revocation JWT missing max_active_grant_version')
        _mark_revocation_untrusted()
        return False
    _store_trusted_revocation(
        revoked_ids=revoked_ids,
        agents=agents,
        cache_seconds=cache_seconds,
        verified_signed_claims={
            'revocation_policy_version': rp,
            'max_active_grant_version': mv,
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
    if row.get('global_company_id') is not None and gg is None:
        gg = None
    gv = parse_grant_version(row.get('grant_version'))
    return rc, gg, gv


def _agent_grant_row(agent_id: str, agent_claims: dict[str, Any]) -> dict[str, Any] | None:
    payload = _cached_revocation()
    if not payload:
        return None
    agents = payload.get('agents') or []
    token_rc = _regional_company_id(agent_claims)
    token_gg = parse_global_company_id(agent_claims.get('global_company_id'))
    candidates: list[dict[str, Any]] = []
    for entry in agents:
        if not isinstance(entry, dict):
            continue
        if str(entry.get('agent_id') or '') != str(agent_id):
            continue
        rc, gg, _gv = _grant_row_snapshot_fields(entry)
        if token_rc is not None and rc is not None and rc == token_rc:
            candidates.append(entry)
        elif token_gg is not None and gg is not None and gg == token_gg:
            candidates.append(entry)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    if token_rc is not None:
        for c in candidates:
            rc, _gg, _gv = _grant_row_snapshot_fields(c)
            if rc == token_rc:
                return c
    if token_gg is not None:
        for c in candidates:
            _rc, gg, _gv = _grant_row_snapshot_fields(c)
            if gg == token_gg:
                return c
    return candidates[0]


def _grant_row_matches_agent(agent_claims: dict[str, Any], row: dict[str, Any]) -> bool:
    rc_row, gg_row, gv_row = _grant_row_snapshot_fields(row)
    rc_tok = _regional_company_id(agent_claims)
    gg_tok = parse_global_company_id(agent_claims.get('global_company_id'))
    gv_tok = parse_grant_version(agent_claims.get('grant_version'))

    if rc_tok is not None and rc_row is not None and rc_tok != rc_row:
        return False
    if gg_tok is not None and gg_row is not None and gg_tok != gg_row:
        return False
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
        row = _agent_grant_row(str(agent_id), agent_claims)
        if row is not None and not _grant_row_matches_agent(agent_claims, row):
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
    if mv is None:
        return None
    gv = parse_grant_version(agent_claims.get('grant_version'))
    if gv is None:
        return False
    return gv >= mv


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
    try:
        company_int = int(company_id)
    except (TypeError, ValueError):
        return None

    ok_claims, _reason, _norm = parse_trusted_agent_claims(agent_claims)
    if not ok_claims:
        return None
    gv = parse_grant_version(agent_claims.get('grant_version'))
    if gv is None:
        return None
    gcid = parse_global_company_id(agent_claims.get('global_company_id'))
    cbv_raw = agent_claims.get('company_binding_version')
    cbv = parse_company_binding_version(cbv_raw) if cbv_raw is not None else None

    try:
        return build_mcp_approval_assertion_identity_bound(
            company_id=company_int,
            agent_id=agent_id,
            service=str(payload.get('service') or 'storage'),
            action=str(payload.get('action') or ''),
            arguments_hash=args_hash,
            audience_url=_identity_audience(origin),
            grant_version=gv,
            global_company_id=gcid,
            company_binding_version=cbv,
        )
    except InternalAssertionError as exc:
        logger.warning('MCP approval assertion unavailable: %s', exc.message)
        return None


def create_approval_request(payload: dict[str, Any], agent_claims: dict[str, Any]) -> dict | None:
    origin = _identity_origin()
    assertion = _approval_assertion_from_payload(payload, agent_claims)
    if not origin or not assertion:
        return None
    body = {'arguments': payload.get('arguments') or {}}
    try:
        response = requests.post(
            f'{origin}/api/v1/mcp/internal/mcp-approval-requests',
            json=body,
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.warning('MCP approval request unreachable: %s', exc)
        return None
    if response.status_code == 404 or response.status_code >= 400:
        logger.warning('MCP approval request failed: %s', response.status_code)
        return None
    try:
        data = response.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    rid = data.get('id')
    if rid is None or not _UUID_RE.match(str(rid)):
        return None
    return data


def approval_state(payload: dict[str, Any], agent_claims: dict[str, Any]) -> str | None:
    """Resolve approval status from identity-service. Fail closed on errors."""
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
        return None
    if state == 'expired':
        return 'expired'
    return 'error'


def consume_approval(
    approval_id: str,
    payload: dict[str, Any] | None,
    agent_claims: dict[str, Any],
) -> bool:
    origin = _identity_origin()
    payload = payload or {}
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
    out: dict[str, Any] = {}
    for key in _CALL_LOG_APPROVED_KEYS:
        if key not in entry:
            continue
        val = entry[key]
        if key == 'error' and isinstance(val, dict):
            code = val.get('code')
            if isinstance(code, str) and code:
                out[key] = {'code': code[:128]}
        elif key == 'result_shape' and val in ('dict', 'list', 'scalar', 'empty'):
            out[key] = val
        elif key == 'operation_title' and isinstance(val, str):
            out[key] = val[:256]
        elif key == 'path' and isinstance(val, str):
            out[key] = val[:2048]
        elif key in ('duration_ms', 'status', 'grant_version', 'company_binding_version'):
            if isinstance(val, int) and not isinstance(val, bool) and val >= 0:
                out[key] = val
        elif key == 'company_id' and isinstance(val, int) and not isinstance(val, bool) and val >= 0:
            out[key] = val
        elif key == 'global_company_id' and isinstance(val, str) and parse_global_company_id(val):
            out[key] = parse_global_company_id(val)
        elif key in (
            'agent_id',
            'service',
            'tool',
            'method',
            'access_kind',
            'read_level',
            'outcome',
            'approval_request_id',
            'approval_id',
        ):
            if key in ('approval_request_id', 'approval_id'):
                if not isinstance(val, str) or not val or not _UUID_RE.match(val):
                    continue
                out[key] = val
            elif isinstance(val, str) and val:
                out[key] = val[:500]
        elif key == 'destructive' and isinstance(val, bool):
            out[key] = val
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
        logger.debug('MCP call log forward failed: %s', exc)


def warm_revocation_cache() -> None:
    """Best-effort background refresh (tests may call directly)."""
    _refresh_revocations()
    time.sleep(0)
