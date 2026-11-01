"""Signed internal calls between Shellui services (approval requests, call logs)."""

from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
from django.conf import settings
from rest_framework_simplejwt.settings import api_settings

APPROVAL_AUDIENCE = 'shellui-mcp-approval'
APPROVAL_SCOPE = 'mcp.approval.create'
CALL_LOG_AUDIENCE = 'shellui-mcp-call-log'
CALL_LOG_SCOPE = 'mcp.call_log.create'
REVOCATION_AUDIENCE = 'shellui-mcp-revocation'
REVOCATION_SCOPE = 'mcp.revocation.read'
REVOCATION_CACHE_SECONDS = 30


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
