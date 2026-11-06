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

from apps.storage.mcp_assertions import (
    parse_global_agent_id,
    parse_global_company_id,
    parse_trusted_agent_claims,
)
from config.service_signing import signing_kwargs

_REVOKED_CACHE_KEY = 'mcp:revoked_trusted_payload'
_REVOKED_EPOCH_KEY = 'mcp:revoked_cache_epoch'

logger = logging.getLogger(__name__)

_AUTH_LOCK = threading.Lock()
_AUTH_CACHE: dict[tuple[Any, ...], tuple[float, bool]] = {}

_AGENT_AUTH_AUDIENCE = 'shellui-mcp-agent-delegated-authority'
_AGENT_AUTH_SCOPE = 'mcp.agent.delegated.authority.read'


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
    path = explicit or '/api/v1/mcp/internal/mcp-agent-delegated-authority'
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


def _cache_set_positive(key: tuple[Any, ...]) -> None:
    """Cache only strict positive outcomes (short TTL); negatives are never cached."""
    with _AUTH_LOCK:
        _AUTH_CACHE[key] = (time.monotonic(), True)


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

    token_global_agent_id = parse_global_agent_id(claims.get('global_agent_id'))

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

    if response.status_code == 403:
        return False

    if response.status_code != 200:
        return False

    try:
        data = response.json()
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False

    ok = _delegated_identity_authority_strict_ok(data, body, token_global_agent_id=token_global_agent_id)
    if ok:
        _cache_set_positive(cache_key)
    return ok


def _strict_bool(data: dict[str, Any], key: str) -> bool | None:
    if key not in data:
        return None
    v = data.get(key)
    if isinstance(v, bool):
        return v
    return None


def _delegated_identity_authority_strict_ok(
    data: dict[str, Any],
    body: dict[str, Any],
    *,
    token_global_agent_id: str | None,
) -> bool:
    """
    Fail closed on Identity ``mcp-agent-delegated-authority`` JSON (200 only).

    Required booleans (actual JSON bool, not strings): ``authorized``, ``revoked``, ``paused``.
    Accept only ``authorized`` true, ``revoked`` false, ``paused`` false.
    When ``active`` is present it must be true; omitted ``active`` is allowed.
    Top-level identity fields must match the POST body; ``global_agent_id`` is taken from the
    response (Identity is authoritative). Extra keys (for example capability lists) are ignored.
    """
    for k in ('authorized', 'revoked', 'paused'):
        b = _strict_bool(data, k)
        if b is None:
            return False
    if data['authorized'] is not True or data['revoked'] is not False or data['paused'] is not False:
        return False

    act = _strict_bool(data, 'active')
    if act is not None and act is not True:
        return False

    aid = str(data.get('agent_id') or '').strip()
    if not aid or aid != str(body['agent_id']):
        return False

    cid = data.get('company_id')
    if isinstance(cid, bool) or not isinstance(cid, int) or cid < 0 or cid != body['company_id']:
        return False

    gg = parse_global_company_id(data.get('global_company_id'))
    if gg is None or gg != body['global_company_id']:
        return False

    gv = data.get('grant_version')
    if isinstance(gv, bool) or not isinstance(gv, int) or gv < 0 or gv != body['grant_version']:
        return False

    cbv = data.get('company_binding_version')
    if isinstance(cbv, bool) or not isinstance(cbv, int) or cbv < 0 or cbv != body['company_binding_version']:
        return False

    gai = parse_global_agent_id(data.get('global_agent_id'))
    if gai is None:
        return False
    if token_global_agent_id is not None and gai != token_global_agent_id:
        return False
    return True
