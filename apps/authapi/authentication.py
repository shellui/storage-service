"""JWT authentication via identity-service JWKS (RS256) with optional HS256 fallback."""

from __future__ import annotations

import logging

import jwt
from django.conf import settings
from rest_framework import authentication, exceptions

from .jwks_client import get_jwks_client
from .principal import StoragePrincipal, principal_from_claims

logger = logging.getLogger(__name__)


class IdentityJWKSAuthentication(authentication.BaseAuthentication):
    """
    Verify Bearer JWTs issued by identity-service.

    Production path: fetch public keys from ``IDENTITY_JWKS_URL`` and verify RS256.
    Local/dev fallback: if JWKS has no keys and ``JWT_HS256_FALLBACK_SECRET`` is set,
    verify HS256 tokens (matches identity-service DEBUG mode).
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
            raise exceptions.AuthenticationFailed('Token has expired.') from exc
        except jwt.InvalidTokenError as exc:
            errors.append(exc)
        except Exception as exc:
            logger.debug('JWKS verification failed: %s', exc)
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
                raise exceptions.AuthenticationFailed('Token has expired.') from exc
            except jwt.InvalidTokenError as exc:
                errors.append(exc)

        detail = 'Token is invalid or could not be verified against identity JWKS.'
        if errors:
            raise exceptions.AuthenticationFailed(detail) from errors[-1]
        raise exceptions.AuthenticationFailed(detail)

    def authenticate_header(self, request):
        return self.keyword
