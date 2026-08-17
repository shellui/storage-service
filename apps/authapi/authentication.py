"""JWT authentication via identity-service JWKS (RS256) with optional HS256 fallback."""

from __future__ import annotations

import logging
from typing import Any

import jwt
from django.conf import settings
from rest_framework import authentication, exceptions

from .jwks_client import get_jwks_client
from .principal import StoragePrincipal, principal_from_claims

logger = logging.getLogger(__name__)

_GENERIC_TOKEN_DETAIL = 'Token is invalid or could not be verified against identity JWKS.'


def _safe_jwt_meta(raw_token: str) -> dict[str, Any]:
    """Header/claim fields that are safe to log (never the token or signature)."""
    meta: dict[str, Any] = {'token_segments': raw_token.count('.') + 1 if raw_token else 0}
    try:
        header = jwt.get_unverified_header(raw_token)
    except Exception as exc:
        meta['header_error'] = f'{type(exc).__name__}: {exc}'
        return meta
    meta['alg'] = header.get('alg')
    meta['kid'] = header.get('kid')
    meta['typ'] = header.get('typ')
    try:
        payload = jwt.decode(
            raw_token,
            options={
                'verify_signature': False,
                'verify_exp': False,
                'verify_nbf': False,
                'verify_aud': False,
                'verify_iss': False,
            },
            algorithms=[header['alg']] if header.get('alg') else ['RS256', 'HS256'],
        )
    except Exception as exc:
        meta['payload_error'] = f'{type(exc).__name__}: {exc}'
        return meta
    meta['iss'] = payload.get('iss')
    meta['aud'] = payload.get('aud')
    meta['exp'] = payload.get('exp')
    meta['sub'] = payload.get('sub')
    return meta


def _jwks_meta() -> dict[str, Any]:
    info: dict[str, Any] = {
        'jwks_source': getattr(settings, 'IDENTITY_JWKS_SOURCE', None) or 'url',
        'jwks_url': getattr(settings, 'IDENTITY_JWKS_URL', None),
        'jwks_file': getattr(settings, 'IDENTITY_JWKS_FILE', None),
        'algorithms': list(getattr(settings, 'JWT_ALGORITHMS', ['RS256'])),
        'issuer': getattr(settings, 'IDENTITY_ISSUER', None),
        'audience': getattr(settings, 'IDENTITY_AUDIENCE', None),
        'hs256_fallback': bool(getattr(settings, 'JWT_HS256_FALLBACK_SECRET', None))
        and (
            settings.DEBUG or getattr(settings, 'ALLOW_JWT_HS256_FALLBACK', False)
        ),
    }
    try:
        client = get_jwks_client()
        info['jwks_key_count'] = client.key_count()
        info['jwks_kids'] = client.key_ids()
    except Exception as exc:
        info['jwks_error'] = f'{type(exc).__name__}: {exc}'
    return info


def _format_context(*parts: dict[str, Any]) -> str:
    merged: dict[str, Any] = {}
    for part in parts:
        merged.update(part)
    chunks = []
    for key, value in merged.items():
        if value is None or value == '' or value == []:
            continue
        chunks.append(f'{key}={value!r}')
    return ' '.join(chunks)


def _client_detail(errors: list[Exception]) -> str:
    if settings.DEBUG and errors:
        last = errors[-1]
        return f'{_GENERIC_TOKEN_DETAIL} ({type(last).__name__}: {last})'
    return _GENERIC_TOKEN_DETAIL


class IdentityJWKSAuthentication(authentication.BaseAuthentication):
    """
    Verify Bearer JWTs issued by identity-service.

    Production path: verify RS256 with a local JWKS document
    (``IDENTITY_JWKS_FILE`` / ``IDENTITY_JWKS``) or keys fetched from
    ``IDENTITY_JWKS_URL``. Local/dev fallback: if JWKS has no keys and
    ``JWT_HS256_FALLBACK_SECRET`` is set, verify HS256 tokens (identity DEBUG mode).
    """

    keyword = 'Bearer'

    def authenticate(self, request):
        header = authentication.get_authorization_header(request).decode('utf-8')
        if not header:
            return None

        parts = header.split()
        if len(parts) == 0:
            return None
        if parts[0] != self.keyword:
            # Also accept raw JWT without scheme (some WebDAV / Basic clients)
            if len(parts) == 1 and parts[0].count('.') == 2:
                raw_token = parts[0]
            else:
                return None
        else:
            if len(parts) != 2:
                raise exceptions.AuthenticationFailed('Invalid Authorization header.')
            raw_token = parts[1]

        principal = self.authenticate_credentials(raw_token)
        return (principal, raw_token)

    def authenticate_credentials(self, raw_token: str) -> StoragePrincipal:
        claims = self._decode_token(raw_token)
        try:
            return principal_from_claims(claims)
        except ValueError as exc:
            logger.warning(
                'JWT claims rejected: %s. %s',
                exc,
                _format_context(_safe_jwt_meta(raw_token)),
            )
            raise exceptions.AuthenticationFailed(str(exc)) from exc

    def _decode_token(self, raw_token: str) -> dict:
        algorithms = list(getattr(settings, 'JWT_ALGORITHMS', ['RS256']))
        options = {
            'require': ['exp'],
            'verify_aud': bool(settings.IDENTITY_AUDIENCE),
            'verify_iss': bool(settings.IDENTITY_ISSUER),
        }
        decode_kwargs: dict = {
            'algorithms': algorithms,
            'options': options,
        }
        if settings.IDENTITY_AUDIENCE:
            decode_kwargs['audience'] = settings.IDENTITY_AUDIENCE
        if settings.IDENTITY_ISSUER:
            decode_kwargs['issuer'] = settings.IDENTITY_ISSUER

        token_meta = _safe_jwt_meta(raw_token)
        errors: list[Exception] = []

        # RS256 via JWKS
        try:
            client = get_jwks_client()
            signing_key = client.get_signing_key(raw_token)
            if signing_key is not None:
                return jwt.decode(
                    raw_token,
                    key=signing_key.key,
                    **decode_kwargs,
                )
        except jwt.ExpiredSignatureError as exc:
            logger.info('JWT expired. %s', _format_context(token_meta, _jwks_meta()))
            raise exceptions.AuthenticationFailed('Token has expired.') from exc
        except jwt.InvalidTokenError as exc:
            logger.warning(
                'JWT JWKS verification failed (%s): %s. %s',
                type(exc).__name__,
                exc,
                _format_context(token_meta, _jwks_meta()),
            )
            errors.append(exc)
        except Exception as exc:
            logger.warning(
                'JWT JWKS verification error (%s): %s. %s',
                type(exc).__name__,
                exc,
                _format_context(token_meta, _jwks_meta()),
            )
            errors.append(exc)

        # HS256 fallback for local identity-service DEBUG mode only (gated in settings).
        secret = getattr(settings, 'JWT_HS256_FALLBACK_SECRET', None)
        allow_hs256 = bool(secret) and (
            settings.DEBUG or getattr(settings, 'ALLOW_JWT_HS256_FALLBACK', False)
        )
        if allow_hs256:
            try:
                return jwt.decode(
                    raw_token,
                    key=secret,
                    algorithms=['HS256'],
                    options=options,
                    audience=settings.IDENTITY_AUDIENCE,
                    issuer=settings.IDENTITY_ISSUER,
                )
            except jwt.ExpiredSignatureError as exc:
                logger.info('JWT expired (HS256 fallback). %s', _format_context(token_meta))
                raise exceptions.AuthenticationFailed('Token has expired.') from exc
            except jwt.InvalidTokenError as exc:
                logger.warning(
                    'JWT HS256 fallback failed (%s): %s. %s',
                    type(exc).__name__,
                    exc,
                    _format_context(token_meta),
                )
                errors.append(exc)
        elif token_meta.get('alg') == 'HS256':
            logger.warning(
                'Token alg is HS256 but HS256 fallback is disabled. '
                'For identity-service DEBUG tokens set JWT_HS256_FALLBACK_SECRET '
                'to identity SECRET_KEY; otherwise issue RS256 tokens. %s',
                _format_context(token_meta, _jwks_meta()),
            )

        detail = _client_detail(errors)
        logger.warning(
            'JWT authentication failed. %s errors=%s',
            _format_context(token_meta, _jwks_meta()),
            [type(exc).__name__ for exc in errors] or ['no_signing_key'],
        )
        if errors:
            raise exceptions.AuthenticationFailed(detail) from errors[-1]
        raise exceptions.AuthenticationFailed(detail)

    def authenticate_header(self, request):
        return self.keyword
