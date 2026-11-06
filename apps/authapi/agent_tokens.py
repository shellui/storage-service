"""Decode Shellui MCP agent access tokens issued by identity-service."""

from __future__ import annotations

import jwt
from django.conf import settings
from django.http import HttpRequest

from apps.authapi.jwks_client import get_jwks_client
from shellui_django.mcp.resources import access_token_audience_matches, normalize_resource_indicator

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


def principal_from_agent_claims(claims: dict) -> StoragePrincipal:
    company_id = claims.get('company_id')
    try:
        cid = int(company_id)
    except (TypeError, ValueError) as exc:
        raise ValueError('Agent token is missing a numeric company_id.') from exc
    return StoragePrincipal(
        user_id=0,
        company_id=cid,
        email='',
        username=f"agent:{claims.get('agent_id')}",
        is_staff=False,
        is_company_owner=True,
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
    if _agent_staff_refused(claims):
        return None
    if not agent_scope_allows_storage(claims):
        return None
    principal = principal_from_agent_claims(claims)
    return principal, claims
