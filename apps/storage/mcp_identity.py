"""Calls to identity-service for MCP revocations, approvals, and call logs."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

import requests
from django.conf import settings
from django.core.cache import cache

from shellui_mcp.internal import (
    REVOCATION_CACHE_SECONDS,
    build_mcp_approval_assertion,
    build_mcp_call_log_assertion,
)

logger = logging.getLogger(__name__)

_REVOKED_CACHE_KEY = 'mcp:revoked_agent_ids'
_REVOKED_LOCK = threading.Lock()


def _identity_origin() -> str:
    return (getattr(settings, 'IDENTITY_SERVICE_URL', '') or settings.IDENTITY_ISSUER or '').rstrip('/')


def _service_assertion_headers(origin: str) -> dict[str, str]:
    """Signed service assertion for identity internal MCP APIs (revocation list, and related reads)."""
    try:
        from shellui_mcp.internal import build_mcp_revocation_list_assertion
    except ImportError:
        assertion = build_mcp_call_log_assertion(audience_url=origin)
    else:
        assertion = build_mcp_revocation_list_assertion(audience_url=origin)
    return {'Authorization': f'Bearer {assertion}'}


def _refresh_revocations() -> set[str]:
    origin = _identity_origin()
    if not origin:
        return set()
    url = f'{origin}/api/v1/mcp/internal/mcp-revocations'
    try:
        response = requests.get(url, headers=_service_assertion_headers(origin), timeout=5)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.debug('MCP revocation poll failed: %s', exc)
        cached = cache.get(_REVOKED_CACHE_KEY)
        return set(cached or [])
    ids = {str(item) for item in (payload.get('revoked_agent_ids') or [])}
    cache.set(_REVOKED_CACHE_KEY, list(ids), timeout=REVOCATION_CACHE_SECONDS)
    return ids


def blocked_agent_ids() -> set[str]:
    cached = cache.get(_REVOKED_CACHE_KEY)
    if cached is not None:
        return set(cached)
    with _REVOKED_LOCK:
        cached = cache.get(_REVOKED_CACHE_KEY)
        if cached is not None:
            return set(cached)
        return _refresh_revocations()


def agent_is_revoked(agent_id: str) -> bool:
    return str(agent_id) in blocked_agent_ids()


def create_approval_request(payload: dict[str, Any]) -> dict | None:
    origin = _identity_origin()
    if not origin:
        return None
    agent_id = str(payload.get('agent_id') or '')
    company_id = payload.get('company_id')
    if not agent_id or company_id is None:
        return None
    arguments_hash = str(payload.get('arguments_hash') or '')
    assertion = build_mcp_approval_assertion(
        company_id=int(company_id),
        agent_id=agent_id,
        service=str(payload.get('service') or 'storage'),
        action=str(payload.get('action') or ''),
        arguments_hash=arguments_hash,
        audience_url=origin,
    )
    body = {'arguments': payload.get('arguments') or {}}
    try:
        response = requests.post(
            f'{origin}/api/v1/mcp/internal/mcp-approval-requests',
            json=body,
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
        if response.status_code >= 400:
            logger.warning('MCP approval request failed: %s %s', response.status_code, response.text[:200])
            return None
        return response.json()
    except requests.RequestException as exc:
        logger.warning('MCP approval request unreachable: %s', exc)
        return None


def approval_state(payload: dict[str, Any]) -> str | None:
    """Resolve approval status from identity-service (approved writes run once after owner approval)."""
    origin = _identity_origin()
    agent_id = payload.get('agent_id')
    company_id = payload.get('company_id')
    args_hash = str(payload.get('arguments_hash') or '')
    if not origin or not agent_id or company_id is None or not args_hash:
        return None
    assertion = build_mcp_approval_assertion(
        company_id=int(company_id),
        agent_id=str(agent_id),
        service=str(payload.get('service') or 'storage'),
        action=str(payload.get('action') or ''),
        arguments_hash=args_hash,
        audience_url=origin,
    )
    body = {
        'agent_id': str(agent_id),
        'company_id': company_id,
        'service': str(payload.get('service') or ''),
        'action': str(payload.get('action') or ''),
        'arguments_hash': args_hash,
    }
    try:
        response = requests.post(
            f'{origin}/api/v1/mcp/internal/mcp-approval-state',
            json=body,
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
    except requests.RequestException:
        return None
    if response.status_code == 404:
        return None
    if response.status_code >= 400:
        return None
    data = response.json()
    state = str(data.get('status') or '')
    if state == 'approved' and data.get('id'):
        payload['approval_id'] = str(data['id'])
    if state in {'pending', 'approved', 'executed'}:
        return state
    return None


def consume_approval(approval_id: str) -> bool:
    origin = _identity_origin()
    if not origin or not approval_id:
        return False
    assertion = build_mcp_call_log_assertion(audience_url=origin)
    try:
        response = requests.post(
            f'{origin}/api/v1/mcp/internal/mcp-approval-consume',
            json={'approval_id': approval_id},
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
    except requests.RequestException:
        return False
    if response.status_code == 404:
        return False
    return response.status_code < 300 and bool(response.json().get('consumed', True))


def forward_call_log(entry: dict[str, Any]) -> None:
    origin = _identity_origin()
    if not origin:
        return
    assertion = build_mcp_call_log_assertion(audience_url=origin)
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
