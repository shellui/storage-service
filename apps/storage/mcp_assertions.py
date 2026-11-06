"""Strict parsing of Identity claims and MCP approval assertions for storage-service."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

from shellui_django.mcp.internal import (
    APPROVAL_AUDIENCE,
    APPROVAL_SCOPE,
    InternalAssertionError,
    _encode_rs256_assertion,
    _service_issuer,
)

from config.service_signing import signing_kwargs

# Lowercase UUID with hyphens only (JWT string claim for global company id).
_GLOBAL_COMPANY_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
)


def parse_global_company_id(raw: Any) -> str | None:
    """Return normalized global company UUID string, or None when absent. Never int-cast."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower()
    if not s:
        return None
    if _GLOBAL_COMPANY_UUID_RE.match(s):
        return s
    return None


def parse_grant_version(raw: Any) -> int | None:
    """Non-negative int only. No string coercion, no aliases."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    return None


def parse_company_binding_version(raw: Any) -> int | None:
    """Non-negative int only (0 is valid)."""
    return parse_grant_version(raw)


def build_mcp_approval_assertion_identity_bound(
    *,
    company_id: int,
    agent_id: str,
    service: str,
    action: str,
    arguments_hash: str,
    audience_url: str,
    grant_version: int,
    global_company_id: str | None,
    company_binding_version: int | None,
    lifetime_seconds: int = 60,
) -> str:
    """
    RS256 MCP approval assertion with Identity-bound fields.

    Extends the stock ``build_mcp_approval_assertion`` claim set using the same encoder as
    shellui-django. When django-commons/shellui-django publishes these fields on the public
    helper, switch the call site to that API and delete this wrapper.
    """
    kwargs = signing_kwargs()
    pem = kwargs['private_key_pem']
    kid = kwargs['kid']
    issuer = kwargs['issuer']
    now = int(time.time())
    claims: dict[str, Any] = {
        'iss': _service_issuer(issuer),
        'aud': APPROVAL_AUDIENCE,
        'sub': f'agent:{agent_id}',
        'scope': APPROVAL_SCOPE,
        'company_id': company_id,
        'agent_id': agent_id,
        'service': service,
        'action': action,
        'arguments_hash': arguments_hash,
        'target': audience_url,
        'grant_version': grant_version,
        'iat': now,
        'exp': now + lifetime_seconds,
        'jti': uuid.uuid4().hex,
    }
    if global_company_id is not None:
        claims['global_company_id'] = global_company_id
    if company_binding_version is not None:
        claims['company_binding_version'] = company_binding_version
    try:
        return _encode_rs256_assertion(claims, private_key_pem=pem, kid=kid)
    except InternalAssertionError:
        raise
    except Exception as exc:
        raise InternalAssertionError('MCP approval assertion signing failed.', status=503) from exc


def parse_trusted_agent_claims(claims: dict[str, Any]) -> tuple[bool, str, dict[str, Any] | None]:
    """
    Validate verified agent access token claims for MCP. No legacy aliases.

    Returns (ok, reason, normalized) where normalized is set only when ok.
    """
    access = str(claims.get('mcp_access') or 'read_only').strip() or 'read_only'

    raw_company = claims.get('company_id')
    if not isinstance(raw_company, int) or isinstance(raw_company, bool):
        return False, 'invalid_company_id', None
    if raw_company < 0:
        return False, 'invalid_company_id', None

    gv = parse_grant_version(claims.get('grant_version'))
    if gv is None:
        return False, 'missing_grant_version', None

    gcid = parse_global_company_id(claims.get('global_company_id'))
    raw_glob = claims.get('global_company_id')
    if raw_glob is not None and gcid is None:
        return False, 'invalid_global_company_id', None

    cbv_raw = claims.get('company_binding_version')
    cbv = parse_company_binding_version(cbv_raw) if cbv_raw is not None else None
    if cbv_raw is not None and cbv is None:
        return False, 'invalid_company_binding_version', None

    if gcid is not None:
        if cbv is None:
            return False, 'missing_company_binding_version', None
    else:
        if cbv is not None:
            return False, 'unexpected_company_binding_version', None

    normalized = {
        'mcp_access': access,
        'company_id': raw_company,
        'grant_version': gv,
        'global_company_id': gcid,
        'company_binding_version': cbv,
    }
    return True, '', normalized
