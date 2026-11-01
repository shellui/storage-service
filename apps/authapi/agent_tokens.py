"""Decode Shellui MCP agent access tokens issued by identity-service."""

from __future__ import annotations

import jwt
from django.conf import settings
from django.http import HttpRequest

from apps.authapi.jwks_client import get_jwks_client

from .principal import StoragePrincipal

MCP_ACCESS_AUDIENCE = 'shellui-mcp'


def mcp_resource_audience(request: HttpRequest) -> str:
    """RFC 8707 resource indicator: this service's ``/mcp`` URL."""
    return request.build_absolute_uri('/mcp').rstrip('/')


def _audiences(*, mcp_resource_audience: str | None = None) -> list[str]:
    values: list[str] = []
    if mcp_resource_audience:
        values.append(mcp_resource_audience.rstrip('/'))
    if settings.IDENTITY_AUDIENCE:
        values.append(settings.IDENTITY_AUDIENCE)
    if MCP_ACCESS_AUDIENCE not in values:
        values.append(MCP_ACCESS_AUDIENCE)
    return values


def _decode_agent_claims(raw_token: str, *, mcp_resource_audience: str | None = None) -> dict | None:
    algorithms = list(getattr(settings, 'JWT_ALGORITHMS', ['RS256']))
    options = {
        'require': ['exp', 'sub', 'agent_id'],
        'verify_aud': True,
        'verify_iss': bool(settings.IDENTITY_ISSUER),
    }
    decode_kwargs: dict = {'algorithms': algorithms, 'options': options}
    if settings.IDENTITY_ISSUER:
        decode_kwargs['issuer'] = settings.IDENTITY_ISSUER

    audiences = _audiences(mcp_resource_audience=mcp_resource_audience)
    try:
        signing_key = get_jwks_client().get_signing_key(raw_token)
        if signing_key is not None:
            for audience in audiences:
                try:
                    payload = jwt.decode(
                        raw_token,
                        key=signing_key.key,
                        audience=audience,
                        **decode_kwargs,
                    )
                    if str(payload.get('sub', '')).startswith('agent:'):
                        return payload
                except jwt.InvalidTokenError:
                    continue
    except Exception:
        pass

    secret = getattr(settings, 'JWT_HS256_FALLBACK_SECRET', None)
    allow_hs256 = bool(secret) and (
        settings.DEBUG or getattr(settings, 'ALLOW_JWT_HS256_FALLBACK', False)
    )
    if allow_hs256:
        for audience in audiences:
            try:
                payload = jwt.decode(
                    raw_token,
                    key=secret,
                    algorithms=['HS256'],
                    audience=audience,
                    issuer=settings.IDENTITY_ISSUER or None,
                    options=options,
                )
                if str(payload.get('sub', '')).startswith('agent:'):
                    return payload
            except jwt.InvalidTokenError:
                continue
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


def authenticate_agent_bearer(
    raw_token: str,
    *,
    mcp_resource_audience: str | None = None,
) -> tuple[StoragePrincipal, dict] | None:
    claims = _decode_agent_claims(raw_token, mcp_resource_audience=mcp_resource_audience)
    if claims is None:
        return None
    if not agent_scope_allows_storage(claims):
        return None
    principal = principal_from_agent_claims(claims)
    return principal, claims
