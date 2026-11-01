"""Signed internal calls between Shellui services (approval requests, call logs)."""

from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
from django.conf import settings
from rest_framework_simplejwt.settings import api_settings


def _identity_issuer() -> str:
    return (api_settings.ISSUER or getattr(settings, 'JWT_ISSUER', None) or '').strip()

APPROVAL_AUDIENCE = 'shellui-mcp-approval'
APPROVAL_SCOPE = 'mcp.approval.create'
CALL_LOG_AUDIENCE = 'shellui-mcp-call-log'
CALL_LOG_SCOPE = 'mcp.call_log.create'
REVOCATION_AUDIENCE = 'shellui-mcp-revocation'
REVOCATION_SCOPE = 'mcp.revocation.read'
REVOCATION_LIST_SCOPE = 'mcp.revocation.list'
REVOCATION_CACHE_SECONDS = 30
REVOCATION_LIST_ASSERTION_LIFETIME_SECONDS = REVOCATION_CACHE_SECONDS


class InternalAssertionError(Exception):
    def __init__(self, message: str, *, status: int = 401):
        super().__init__(message)
        self.message = message
        self.status = status


def _encode_assertion(claims: dict[str, Any]) -> str:
    headers = {}
    kid = getattr(settings, 'JWT_ACTIVE_KEY_ID', '')
    if kid:
        headers['kid'] = kid
    token = jwt.encode(claims, api_settings.SIGNING_KEY, algorithm=api_settings.ALGORITHM, headers=headers or None)
    return token.decode('utf-8') if isinstance(token, bytes) else token


def build_mcp_approval_assertion(
    *,
    company_id: int,
    agent_id: str,
    service: str,
    action: str,
    arguments_hash: str,
    audience_url: str,
    lifetime_seconds: int = 60,
) -> str:
    now = int(time.time())
    claims = {
        'iss': api_settings.ISSUER or '',
        'aud': APPROVAL_AUDIENCE,
        'sub': f'agent:{agent_id}',
        'scope': APPROVAL_SCOPE,
        'company_id': company_id,
        'agent_id': agent_id,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
        'target': audience_url,
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    return _encode_assertion(claims)


def _verification_key(signing_key: str | bytes | None) -> str | bytes:
    if signing_key is not None:
        return signing_key
    verifying = getattr(api_settings, 'VERIFYING_KEY', None)
    if verifying:
        return verifying
    return api_settings.SIGNING_KEY


def build_mcp_revocation_list_response_assertion(
    *,
    revoked_agent_ids: list[str],
    agents: list[dict[str, Any]] | None = None,
    cache_seconds: int = REVOCATION_CACHE_SECONDS,
    lifetime_seconds: int = REVOCATION_LIST_ASSERTION_LIFETIME_SECONDS,
) -> str:
    """Identity signs revocation poll responses so services can fail closed on tampering."""
    now = int(time.time())
    agent_rows = agents or []
    claims = {
        'iss': _identity_issuer(),
        'aud': REVOCATION_AUDIENCE,
        'sub': 'identity',
        'scope': REVOCATION_LIST_SCOPE,
        'revoked_agent_ids': [str(item) for item in revoked_agent_ids],
        'agents': agent_rows,
        'cache_seconds': int(cache_seconds),
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    return _encode_assertion(claims)


def build_mcp_revocation_assertion(*, audience_url: str, lifetime_seconds: int = 60) -> str:
    now = int(time.time())
    claims = {
        'iss': api_settings.ISSUER or '',
        'aud': REVOCATION_AUDIENCE,
        'sub': 'service',
        'scope': REVOCATION_SCOPE,
        'target': audience_url,
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    return _encode_assertion(claims)


def build_mcp_call_log_assertion(*, audience_url: str, lifetime_seconds: int = 60) -> str:
    now = int(time.time())
    claims = {
        'iss': api_settings.ISSUER or '',
        'aud': CALL_LOG_AUDIENCE,
        'sub': 'service',
        'scope': CALL_LOG_SCOPE,
        'target': audience_url,
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    return _encode_assertion(claims)


def verify_mcp_internal_assertion(
    raw_token: str,
    *,
    expected_audience: str,
    expected_scope: str,
    expected_target: str | None = None,
) -> dict[str, Any]:
    if not raw_token or not raw_token.strip():
        raise InternalAssertionError('Missing assertion.')
    token = raw_token.strip()
    if token.lower().startswith('bearer '):
        token = token[7:].strip()
    try:
        payload = jwt.decode(
            token,
            api_settings.SIGNING_KEY,
            algorithms=[api_settings.ALGORITHM],
            audience=expected_audience,
            issuer=api_settings.ISSUER or None,
            options={'require': ['exp', 'iat', 'sub', 'scope']},
        )
    except jwt.PyJWTError as exc:
        raise InternalAssertionError('Invalid assertion.') from exc
    scope = str(payload.get('scope') or '')
    if scope != expected_scope:
        raise InternalAssertionError('Assertion scope mismatch.')
    if expected_target:
        target = str(payload.get('target') or '').rstrip('/')
        if target and target != expected_target.rstrip('/'):
            raise InternalAssertionError('Assertion target mismatch.')
    if payload.get('agent_id') or payload.get('pat_id') or payload.get('user_id'):
        pass
    return payload


def _revocation_list_assertion_token(payload: dict[str, Any]) -> str:
    token = payload.get('revocation_assertion') or payload.get('assertion')
    if not token or not str(token).strip():
        raise InternalAssertionError('Missing revocation list assertion.')
    return str(token).strip()


def verify_mcp_revocation_list_response(
    payload: dict[str, Any],
    *,
    signing_key: str | bytes | None = None,
    expected_issuer: str | None = None,
) -> dict[str, Any]:
    """Verify Identity's signed revocation poll response; raises when untrusted."""
    token = _revocation_list_assertion_token(payload)
    issuer = expected_issuer if expected_issuer is not None else (_identity_issuer() or None)
    try:
        claims = jwt.decode(
            token,
            _verification_key(signing_key),
            algorithms=[api_settings.ALGORITHM],
            audience=REVOCATION_AUDIENCE,
            issuer=issuer,
            options={'require': ['exp', 'iat', 'sub', 'scope']},
        )
    except jwt.PyJWTError as exc:
        raise InternalAssertionError('Invalid revocation list assertion.') from exc
    if str(claims.get('scope') or '') != REVOCATION_LIST_SCOPE:
        raise InternalAssertionError('Revocation list scope mismatch.')
    if str(claims.get('sub') or '') != 'identity':
        raise InternalAssertionError('Revocation list issuer subject mismatch.')
    claimed_ids = [str(item) for item in (claims.get('revoked_agent_ids') or [])]
    claimed_cache = int(claims.get('cache_seconds') or 0)
    body_ids = payload.get('revoked_agent_ids')
    if body_ids is not None:
        normalized_body = [str(item) for item in body_ids]
        if normalized_body != claimed_ids:
            raise InternalAssertionError('Revocation list body mismatch.')
    body_cache = payload.get('cache_seconds')
    if body_cache is not None and int(body_cache) != claimed_cache:
        raise InternalAssertionError('Revocation list cache mismatch.')
    claimed_agents = claims.get('agents') or []
    body_agents = payload.get('agents')
    if body_agents is not None and body_agents != claimed_agents:
        raise InternalAssertionError('Revocation list agents mismatch.')
    return {
        'revoked_agent_ids': claimed_ids,
        'agents': claimed_agents,
        'cache_seconds': claimed_cache,
    }


def parse_trusted_revocation_poll_response(
    payload: dict[str, Any],
    *,
    signing_key: str | bytes | None = None,
    expected_issuer: str | None = None,
) -> tuple[frozenset[str], int]:
    """Return trusted revoked agent ids and cache TTL; fail closed on any problem."""
    trusted = verify_mcp_revocation_list_response(
        payload,
        signing_key=signing_key,
        expected_issuer=expected_issuer,
    )
    ids = frozenset(trusted['revoked_agent_ids'])
    cache_seconds = int(trusted['cache_seconds'] or REVOCATION_CACHE_SECONDS)
    return ids, cache_seconds
