"""Decode Shellui MCP agent access tokens issued by identity-service."""

from __future__ import annotations

import jwt
from django.conf import settings
from django.http import HttpRequest

from apps.authapi.jwks_client import get_jwks_client
from shellui_django.mcp.resources import access_token_audience_matches, normalize_resource_indicator

from apps.authapi.mcp_authority import (
    DelegatedAuthorityDenied,
    DelegatedAuthorityUnavailable,
    delegated_regional_authority_live_ok,
)

from .principal import StoragePrincipal


def mcp_resource_audience(request: HttpRequest) -> str:
    """RFC 8707 resource indicator: this service's public ``/mcp`` URL."""
    public = (getattr(settings, 'STORAGE_PUBLIC_URL', '') or '').strip().rstrip('/')
    if public:
        return normalize_resource_indicator(f'{public}/mcp') or ''
    return normalize_resource_indicator(request.build_absolute_uri('/mcp')) or ''


def _decode_agent_claims(raw_token: str, *, expected_resource: str) -> dict | None:
    expected = normalize_resource_indicator(expected_resource) or ''
    if not expected:
        return None
    algorithms = list(getattr(settings, 'JWT_ALGORITHMS', ['RS256']))
    options = {
        'require': ['exp', 'sub', 'agent_id', 'aud'],
        'verify_aud': True,
        'verify_iss': bool(settings.IDENTITY_ISSUER),
    }
    decode_kwargs: dict = {'algorithms': algorithms, 'options': options, 'audience': expected}
    if settings.IDENTITY_ISSUER:
        decode_kwargs['issuer'] = settings.IDENTITY_ISSUER

    try:
        signing_key = get_jwks_client().get_signing_key(raw_token)
        if signing_key is not None:
            payload = jwt.decode(raw_token, key=signing_key.key, **decode_kwargs)
            if str(payload.get('sub', '')).startswith('agent:') and access_token_audience_matches(
                payload, expected
            ):
                return payload
    except jwt.InvalidTokenError:
        pass
    except Exception:
        pass

    secret = getattr(settings, 'JWT_HS256_FALLBACK_SECRET', None)
    allow_hs256 = bool(secret) and (
        settings.DEBUG or getattr(settings, 'ALLOW_JWT_HS256_FALLBACK', False)
    )
    if allow_hs256:
        try:
            payload = jwt.decode(
                raw_token,
                key=secret,
                algorithms=['HS256'],
                audience=expected,
                issuer=settings.IDENTITY_ISSUER or None,
                options=options,
            )
            if str(payload.get('sub', '')).startswith('agent:') and access_token_audience_matches(
                payload, expected
            ):
                return payload
        except jwt.InvalidTokenError:
            pass
    return None


def agent_scope_allows_storage(claims: dict) -> bool:
    scope = str(claims.get('scope') or '')
    parts = {part.strip() for part in scope.split() if part.strip()}
    return 'storage' in parts


def is_refresh_token(claims: dict) -> bool:
    """True when the JWT is a refresh token and must not be used as a bearer."""
    return str(claims.get('token_type') or '').strip().lower() == 'refresh'


def is_agent_access_claims(claims: dict) -> bool:
    """True for an MCP agent access token (``agent_id`` or ``sub`` ``agent:…``)."""
    if claims.get('agent_id'):
        return True
    return str(claims.get('sub') or '').startswith('agent:')


def is_agent_principal(user) -> bool:
    """True when ``user`` was built from an MCP agent token."""
    if user is None:
        return False
    claims = getattr(user, 'claims', None) or {}
    if isinstance(claims, dict) and is_agent_access_claims(claims):
        return True
    username = str(getattr(user, 'username', '') or '')
    return username.startswith('agent:')


def _owner_user_id(claims: dict) -> int:
    """Regional user id of the human who created the agent, or 0 when absent.

    Only a positive JSON integer is accepted. Bool and other types are ignored.
    """
    raw = claims.get('owner_user_id')
    if isinstance(raw, bool) or not isinstance(raw, int):
        return 0
    if raw < 1:
        return 0
    return raw


def principal_from_agent_claims(claims: dict) -> StoragePrincipal:
    """Build a principal for an MCP agent access token.

    The user id is ``owner_user_id`` when Identity sent one. The agent is never
    a company owner and never staff, including when the creating user is.
    """
    company_id = claims.get('company_id')
    try:
        cid = int(company_id)
    except (TypeError, ValueError) as exc:
        raise ValueError('Agent token is missing a numeric company_id.') from exc
    user_meta = claims.get('user_metadata')
    if not isinstance(user_meta, dict):
        user_meta = {}
    username = str(claims.get('username') or user_meta.get('username') or '')
    if not username:
        username = f"agent:{claims.get('agent_id')}"
    return StoragePrincipal(
        user_id=_owner_user_id(claims),
        company_id=cid,
        email=str(claims.get('email') or user_meta.get('email') or ''),
        username=username,
        is_staff=False,
        is_company_owner=False,
        access_global_metrics=False,
        claims=claims,
    )


def _agent_staff_refused(claims: dict) -> bool:
    if claims.get('is_staff') or claims.get('is_superuser') or claims.get('is_global_staff'):
        return True
    user_meta = claims.get('user_metadata')
    if isinstance(user_meta, dict) and (
        user_meta.get('is_staff') or user_meta.get('is_superuser') or user_meta.get('is_global_staff')
    ):
        return True
    return False


def authenticate_agent_bearer(
    raw_token: str,
    *,
    expected_resource: str,
) -> tuple[StoragePrincipal, dict] | None:
    claims = _decode_agent_claims(raw_token, expected_resource=expected_resource)
    if claims is None:
        return None
    if is_refresh_token(claims):
        return None
    if _agent_staff_refused(claims):
        return None
    if not agent_scope_allows_storage(claims):
        return None
    try:
        delegated_regional_authority_live_ok(claims, expected_resource=expected_resource)
    except (DelegatedAuthorityUnavailable, DelegatedAuthorityDenied):
        raise
    principal = principal_from_agent_claims(claims)
    return principal, claims
