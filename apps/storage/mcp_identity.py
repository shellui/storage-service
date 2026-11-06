"""Calls to identity-service for MCP revocations, approvals, and call logs."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

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
    build_mcp_approval_assertion_extended,
    company_binding_version_from_claims,
    global_company_id_from_claims,
    grant_version_from_claims,
)
from config.service_signing import signing_kwargs

logger = logging.getLogger(__name__)

_REVOKED_CACHE_KEY = 'mcp:revoked_trusted_payload'
_REVOKED_TRUST_KEY = 'mcp:revoked_list_trusted'
_REVOKED_META_KEY = 'mcp:revoked_signed_context'
_REVOKED_LOCK = threading.Lock()


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
    cache.delete(_REVOKED_META_KEY)
    cache.set(_REVOKED_TRUST_KEY, False, timeout=REVOCATION_CACHE_SECONDS)


def _store_trusted_revocation(
    *,
    revoked_ids: frozenset[str],
    agents: list[dict[str, Any]],
    cache_seconds: int,
    signed_context: dict[str, Any],
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
    cache.set(_REVOKED_META_KEY, signed_context, timeout=max(cache_seconds, REVOCATION_CACHE_SECONDS))
    cache.set(_REVOKED_TRUST_KEY, True, timeout=max(cache_seconds, REVOCATION_CACHE_SECONDS))


def _cached_revocation() -> dict[str, Any] | None:
    if cache.get(_REVOKED_TRUST_KEY) is not True:
        return None
    raw = cache.get(_REVOKED_CACHE_KEY)
    if not isinstance(raw, dict):
        return None
    return raw


def _signed_revocation_context() -> dict[str, Any] | None:
    if cache.get(_REVOKED_TRUST_KEY) is not True:
        return None
    raw = cache.get(_REVOKED_META_KEY)
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
    signed_ctx: dict[str, Any] = {'raw_body': body}
    if isinstance(token, str) and token.strip():
        try:
            import jwt

            unverified = jwt.decode(token, options={'verify_signature': False})
            if isinstance(unverified, dict):
                signed_ctx = dict(unverified)
        except Exception:
            pass
    _store_trusted_revocation(
        revoked_ids=revoked_ids,
        agents=agents,
        cache_seconds=cache_seconds,
        signed_context=signed_ctx,
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


def _int_or_none(val: Any) -> int | None:
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _grant_row_matches_agent(agent_claims: dict[str, Any], row: dict[str, Any]) -> bool:
    token_company = _int_or_none(agent_claims.get('company_id'))
    row_company = _int_or_none(row.get('company_id'))
    if token_company is not None and row_company is not None and token_company != row_company:
        return False
    token_gv = grant_version_from_claims(agent_claims)
    if token_gv is None:
        token_gv = 0
    row_gv = grant_version_from_claims(row)
    if row_gv is None:
        row_gv = 0
    if token_gv != row_gv:
        return False
    return True


def _agent_grant_row(agent_id: str, agent_claims: dict[str, Any]) -> dict[str, Any] | None:
    payload = _cached_revocation()
    if not payload:
        return None
    agents = payload.get('agents') or []
    company_id = _int_or_none(agent_claims.get('company_id'))
    gcid = global_company_id_from_claims(agent_claims)
    candidates: list[dict[str, Any]] = []
    for entry in agents:
        if not isinstance(entry, dict):
            continue
        if str(entry.get('agent_id') or '') != str(agent_id):
            continue
        ec = _int_or_none(entry.get('company_id'))
        if company_id is not None and ec is not None and ec == company_id:
            candidates.append(entry)
        elif gcid is not None:
            eg = _int_or_none(entry.get('global_company_id'))
            if eg is not None and eg == gcid:
                candidates.append(entry)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    if company_id is not None:
        for c in candidates:
            if _int_or_none(c.get('company_id')) == company_id:
                return c
    return candidates[0]


def max_active_grant_version() -> int | None:
    """From the signed revocation JWT (not the unsigned HTTP body). None if unavailable."""
    ctx = _signed_revocation_context()
    if not ctx:
        return None
    mv = grant_version_from_claims(ctx)
    if mv is not None:
        return mv
    raw = ctx.get('max_active_grant_version')
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def grant_versions_compatible(agent_claims: dict[str, Any]) -> bool | None:
    """None when revocation metadata is unusable; False when token is stale; True when ok."""
    mv = max_active_grant_version()
    if mv is None:
        return None
    gv = grant_version_from_claims(agent_claims)
    if gv is None:
        gv = 0
    return gv >= mv


def identity_fields_for_approval(agent_claims: dict[str, Any]) -> tuple[bool, str]:
    """
    Validate identity-bound fields from the verified access token.

    Returns (ok, reason). Empty-string claims count as missing for required string fields.
    """
    access = str(agent_claims.get('mcp_access') or 'read_only').strip() or 'read_only'
    gcid = global_company_id_from_claims(agent_claims)
    cbv = company_binding_version_from_claims(agent_claims)

    if access == 'read_only':
        return True, ''

    grant_v = grant_version_from_claims(agent_claims)
    if grant_v is None:
        return False, 'missing_grant_version'

    company_present = agent_claims.get('company_id') is not None
    if not company_present:
        if gcid is None or cbv is None:
            return False, 'missing_company_binding'
        return True, ''

    if gcid is not None:
        try:
            if int(agent_claims.get('company_id')) != int(gcid):
                return False, 'company_mismatch'
        except (TypeError, ValueError):
            return False, 'company_mismatch'

    if cbv is None and gcid is not None:
        return False, 'missing_company_binding_version'

    return True, ''


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

    ok_fields, _reason = identity_fields_for_approval(agent_claims)
    if not ok_fields:
        return None

    gcid = global_company_id_from_claims(agent_claims)
    cbv = company_binding_version_from_claims(agent_claims)
    access = str(agent_claims.get('mcp_access') or 'read_only').strip() or 'read_only'
    grant_v = grant_version_from_claims(agent_claims)
    if grant_v is None:
        if access == 'read_only':
            grant_v = 0
        else:
            return None

    try:
        return build_mcp_approval_assertion_extended(
            company_id=company_int,
            agent_id=agent_id,
            service=str(payload.get('service') or 'storage'),
            action=str(payload.get('action') or ''),
            arguments_hash=args_hash,
            audience_url=_identity_audience(origin),
            grant_version=int(grant_v),
            global_company_id=int(gcid) if gcid is not None else None,
            company_binding_version=int(cbv) if cbv is not None else None,
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
        return response.json()
    except ValueError:
        return None


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
    state = str(data.get('status') or '')
    if state == 'approved' and data.get('id'):
        payload['approval_id'] = str(data['id'])
        return 'approved'
    if state == 'pending':
        return 'pending'
    if state == 'denied':
        return None
    if state == 'expired':
        return 'expired'
    return None


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
    return data.get('consumed') is True


def forward_call_log(entry: dict[str, Any]) -> None:
    origin = _identity_origin()
    if not origin:
        return
    try:
        assertion = build_mcp_call_log_assertion(audience_url=_identity_audience(origin), **signing_kwargs())
    except InternalAssertionError as exc:
        logger.warning('MCP call log skipped: %s', exc.message)
        return
    try:
        requests.post(
            f'{origin}/api/v1/mcp/internal/mcp-call-logs',
            json=entry,
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.debug('MCP call log forward failed: %s', exc)


def warm_revocation_cache() -> None:
    """Best-effort background refresh (tests may call directly)."""
    _refresh_revocations()
    time.sleep(0)
