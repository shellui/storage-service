"""
Live delegated MCP authority: Identity must confirm the current regional agent row.

Used for tokens with a global org triple and ``mcp_authority: delegated``.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

import jwt
import requests
from django.conf import settings
from django.core.cache import cache

from apps.storage.mcp_assertions import parse_global_company_id, parse_trusted_agent_claims
from config.service_signing import signing_kwargs

_REVOKED_CACHE_KEY = 'mcp:revoked_trusted_payload'
_REVOKED_EPOCH_KEY = 'mcp:revoked_cache_epoch'

logger = logging.getLogger(__name__)

_AUTH_LOCK = threading.Lock()
_AUTH_CACHE: dict[tuple[Any, ...], tuple[float, bool]] = {}

_AGENT_AUTH_AUDIENCE = 'shellui-mcp-agent-authority'
_AGENT_AUTH_SCOPE = 'mcp.agent.authority.verify'


class DelegatedAuthorityUnavailable(Exception):
    """Identity delegated-authority lookup failed (network or misconfiguration)."""


def build_mcp_agent_authority_assertion(*, audience_url: str, lifetime_seconds: int = 60) -> str:
    kwargs = signing_kwargs()
    now = int(time.time())
    claims = {
        'iss': kwargs['issuer'],
        'aud': _AGENT_AUTH_AUDIENCE,
        'sub': 'service',
        'scope': _AGENT_AUTH_SCOPE,
        'target': audience_url,
        'iat': now,
        'exp': now + int(lifetime_seconds),
        'jti': uuid.uuid4().hex,
    }
    token = jwt.encode(
        claims,
        kwargs['private_key_pem'],
        algorithm='RS256',
        headers={'kid': kwargs['kid']} if kwargs.get('kid') else None,
    )
    return token.decode('utf-8') if isinstance(token, bytes) else token


def _identity_origin() -> str:
    return (getattr(settings, 'IDENTITY_SERVICE_URL', '') or settings.IDENTITY_ISSUER or '').rstrip('/')


def _authority_url() -> str:
    explicit = (getattr(settings, 'IDENTITY_MCP_DELEGATED_AUTHORITY_PATH', None) or '').strip()
    if explicit.startswith('http://') or explicit.startswith('https://'):
        return explicit.rstrip('/')
    origin = _identity_origin()
    if not origin:
        return ''
    path = explicit or '/api/v1/mcp/internal/mcp-delegated-agent-authority'
    if not path.startswith('/'):
        path = '/' + path
    return f'{origin}{path}'


def _identity_audience_for_assertion(origin: str) -> str:
    return (settings.IDENTITY_ISSUER or origin).rstrip('/')


def _is_regional_identity_mcp_token(claims: dict[str, Any], *, expected_resource: str) -> bool:
    iss = str(claims.get('iss') or '')
    cfg_iss = (settings.IDENTITY_ISSUER or '').strip().rstrip('/')
    if not cfg_iss or iss.rstrip('/') != cfg_iss:
        return False
    from shellui_django.mcp.resources import access_token_audience_matches, normalize_resource_indicator

    exp = normalize_resource_indicator(expected_resource) or ''
    if not exp:
        return False
    return access_token_audience_matches(claims, exp)


def _revocation_ttl_seconds() -> int:
    from shellui_django.mcp.internal import REVOCATION_CACHE_SECONDS

    payload = cache.get(_REVOKED_CACHE_KEY)
    if not isinstance(payload, dict):
        return int(REVOCATION_CACHE_SECONDS)
    cs = payload.get('cache_seconds')
    if isinstance(cs, int) and not isinstance(cs, bool) and cs > 0:
        return min(cs, int(REVOCATION_CACHE_SECONDS))
    return int(REVOCATION_CACHE_SECONDS)


def _revocation_epoch() -> int:
    v = cache.get(_REVOKED_EPOCH_KEY)
    return int(v) if isinstance(v, int) and not isinstance(v, bool) else 0


def _cache_ttl() -> int:
    return min(5, _revocation_ttl_seconds())


def _request_body_from_claims(claims: dict[str, Any]) -> dict[str, Any]:
    ok, _reason, norm = parse_trusted_agent_claims(claims)
    if not ok or norm is None:
        raise ValueError('claims')
    if norm.get('global_company_id') is None:
        raise ValueError('not_delegated')
    if norm.get('mcp_authority') != 'delegated':
        raise ValueError('not_delegated_exchange')
    gci = norm['global_company_id']
    agent_id = str(claims.get('agent_id') or '').strip()
    if not agent_id:
        raise ValueError('agent_id')
    cid = claims.get('company_id')
    if not isinstance(cid, int) or isinstance(cid, bool) or cid < 0:
        raise ValueError('company_id')
    gv = norm['grant_version']
    cbv = norm['company_binding_version']
    if gv is None or cbv is None:
        raise ValueError('triple')
    return {
        'agent_id': agent_id,
        'company_id': cid,
        'global_company_id': gci,
        'grant_version': gv,
        'company_binding_version': cbv,
    }


def _row_strict_int(row: dict[str, Any], key: str) -> int | None:
    if key not in row:
        return None
    v = row[key]
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        return None
    return v


def _response_authorizes(body: dict[str, Any], data: dict[str, Any]) -> bool:
    if data.get('authorized') is not True:
        return False
    if data.get('revoked') is not False:
        return False
    if data.get('paused') is not False:
        return False
    row = data.get('row')
    if not isinstance(row, dict):
        return False
    if str(row.get('agent_id') or '') != body['agent_id']:
        return False
    rc = row.get('company_id')
    if not isinstance(rc, int) or isinstance(rc, bool) or rc != body['company_id']:
        return False
    rg = parse_global_company_id(row.get('global_company_id'))
    if rg != body['global_company_id']:
        return False
    rgv = _row_strict_int(row, 'grant_version')
    rcb = _row_strict_int(row, 'company_binding_version')
    if rgv is None or rcb is None:
        return False
    if rgv != body['grant_version'] or rcb != body['company_binding_version']:
        return False
    return True


def clear_delegated_authority_cache() -> None:
    with _AUTH_LOCK:
        _AUTH_CACHE.clear()


def _cache_get(key: tuple[Any, ...]) -> bool | None:
    now = time.monotonic()
    ttl = _cache_ttl()
    with _AUTH_LOCK:
        ent = _AUTH_CACHE.get(key)
        if not ent:
            return None
        ts, ok = ent
        if now - ts > ttl:
            del _AUTH_CACHE[key]
            return None
        return ok


def _cache_set(key: tuple[Any, ...], ok: bool) -> None:
    with _AUTH_LOCK:
        _AUTH_CACHE[key] = (time.monotonic(), ok)


def delegated_regional_authority_live_ok(
    claims: dict[str, Any],
    *,
    expected_resource: str,
) -> bool:
    """
    True when no delegated exchange triple, or Identity authorizes the live row.

    Raises DelegatedAuthorityUnavailable when Identity is required but not reachable.
    """
    if claims.get('global_company_id') is None:
        return True
    ok_claims, _reason, norm = parse_trusted_agent_claims(claims)
    if not ok_claims or norm is None:
        return False
    if norm.get('global_company_id') is None:
        return True
    if norm.get('mcp_authority') != 'delegated':
        return False

    if not _is_regional_identity_mcp_token(claims, expected_resource=expected_resource):
        return False

    try:
        body = _request_body_from_claims(claims)
    except ValueError:
        return False

    url = _authority_url()
    if not url:
        logger.warning('Delegated authority check skipped: identity URL not configured')
        raise DelegatedAuthorityUnavailable('identity URL not configured')

    epoch = _revocation_epoch()
    cache_key = (
        epoch,
        body['agent_id'],
        body['company_id'],
        body['global_company_id'],
        body['grant_version'],
        body['company_binding_version'],
    )
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    origin = _identity_origin()
    try:
        assertion = build_mcp_agent_authority_assertion(
            audience_url=_identity_audience_for_assertion(origin),
        )
    except Exception as exc:
        logger.warning('Delegated authority assertion failed: %s', type(exc).__name__)
        raise DelegatedAuthorityUnavailable('assertion') from exc

    try:
        response = requests.post(
            url,
            json=body,
            headers={'Authorization': f'Bearer {assertion}'},
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.warning('Delegated authority request failed: %s', type(exc).__name__)
        raise DelegatedAuthorityUnavailable('request') from exc

    if response.status_code == 404 or response.status_code >= 500:
        logger.warning('Delegated authority rejected: %s', response.status_code)
        raise DelegatedAuthorityUnavailable('upstream')

    if response.status_code != 200:
        _cache_set(cache_key, False)
        return False

    try:
        data = response.json()
    except ValueError:
        _cache_set(cache_key, False)
        return False
    if not isinstance(data, dict):
        _cache_set(cache_key, False)
        return False

    ok = _response_authorizes(body, data)
    _cache_set(cache_key, ok)
    return ok


