"""Storage-specific MCP internal assertions to Identity (extends shellui-django 0.4.0)."""

from __future__ import annotations

import time
import uuid
from typing import Any

import jwt

from shellui_django.mcp.internal import APPROVAL_AUDIENCE, APPROVAL_SCOPE

from config.service_signing import signing_kwargs


def _encode_rs256(claims: dict[str, Any], *, private_key_pem: str, kid: str) -> str:
    headers: dict[str, str] | None = {'kid': kid} if kid else None
    token = jwt.encode(claims, private_key_pem, algorithm='RS256', headers=headers)
    return token.decode('utf-8') if isinstance(token, bytes) else token


def normalized_int_claim(raw: Any) -> int | None:
    """Parse a claim as a non-negative int; treat empty string as None. ``0`` is valid."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return None
        try:
            v = int(s)
        except ValueError:
            return None
        return v if v >= 0 else None
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return None
    return v if v >= 0 else None


def grant_version_from_claims(claims: dict[str, Any]) -> int | None:
    """Prefer ``grant_version``; legacy ``permission_version`` is a transitional alias only here."""
    gv = normalized_int_claim(claims.get('grant_version'))
    if gv is not None:
        return gv
    return normalized_int_claim(claims.get('permission_version'))


def global_company_id_from_claims(claims: dict[str, Any]) -> int | None:
    return normalized_int_claim(claims.get('global_company_id'))


def company_binding_version_from_claims(claims: dict[str, Any]) -> int | None:
    return normalized_int_claim(claims.get('company_binding_version'))


def build_mcp_approval_assertion_extended(
    *,
    company_id: int,
    agent_id: str,
    service: str,
    action: str,
    arguments_hash: str,
    audience_url: str,
    grant_version: int,
    global_company_id: int | None,
    company_binding_version: int | None,
    lifetime_seconds: int = 60,
) -> str:
    """RS256 MCP approval assertion including binding and grant versions (Identity strict mode)."""
    kwargs = signing_kwargs()
    private_key_pem = kwargs['private_key_pem']
    kid = kwargs['kid']
    issuer = kwargs['issuer']
    now = int(time.time())
    claims: dict[str, Any] = {
        'iss': str(issuer).strip().rstrip('/'),
        'aud': APPROVAL_AUDIENCE,
        'sub': f'agent:{agent_id}',
        'scope': APPROVAL_SCOPE,
        'company_id': company_id,
        'agent_id': agent_id,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
        'target': audience_url,
        'grant_version': int(grant_version),
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    if global_company_id is not None:
        claims['global_company_id'] = int(global_company_id)
    if company_binding_version is not None:
        claims['company_binding_version'] = int(company_binding_version)
    return _encode_rs256(claims, private_key_pem=private_key_pem, kid=kid)
