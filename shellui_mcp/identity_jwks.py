"""Thread-safe Identity JWKS fetch and RS256 JWT verification (no SimpleJWT)."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any

import jwt
from jwt.algorithms import RSAAlgorithm

_CACHE_TTL_SECONDS = 300
_cache_lock = threading.Lock()
_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}


class IdentityJwksError(Exception):
    pass


def identity_jwks_url_for_issuer(issuer: str) -> str:
    base = (issuer or '').strip().rstrip('/')
    if not base:
        raise IdentityJwksError('Identity issuer is required.')
    return f'{base}/.well-known/jwks.json'


def _fetch_jwks_document(url: str, *, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise IdentityJwksError('Failed to fetch Identity JWKS.') from exc
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityJwksError('Identity JWKS response was not JSON.') from exc
    if not isinstance(document, dict) or not isinstance(document.get('keys'), list):
        raise IdentityJwksError('Identity JWKS document is invalid.')
    return document


def get_jwks_document(*, jwks_url: str | None = None, jwks: dict[str, Any] | None = None, timeout: float = 10.0) -> dict[str, Any]:
    if jwks is not None:
        if not isinstance(jwks.get('keys'), list):
            raise IdentityJwksError('Inline JWKS document is invalid.')
        return jwks
    if not jwks_url:
        raise IdentityJwksError('identity_jwks_url or jwks is required.')
    now = time.monotonic()
    with _cache_lock:
        cached = _jwks_cache.get(jwks_url)
        if cached and now - cached[0] < _CACHE_TTL_SECONDS:
            return cached[1]
    document = _fetch_jwks_document(jwks_url, timeout=timeout)
    with _cache_lock:
        _jwks_cache[jwks_url] = (now, document)
    return document


def _public_key_from_jwk(jwk: dict[str, Any]):
    if jwk.get('kty') != 'RSA':
        raise IdentityJwksError('Unsupported JWK type.')
    return RSAAlgorithm.from_jwk(json.dumps(jwk))


def resolve_verification_key(token: str, jwks_document: dict[str, Any]):
    header = jwt.get_unverified_header(token)
    kid = header.get('kid')
    keys = jwks_document.get('keys') or []
    candidates = [item for item in keys if isinstance(item, dict)]
    if kid:
        for jwk in candidates:
            if jwk.get('kid') == kid:
                return _public_key_from_jwk(jwk)
    if len(candidates) == 1:
        return _public_key_from_jwk(candidates[0])
    raise IdentityJwksError('No matching JWKS key for revocation assertion.')


def decode_identity_rs256_jwt(
    token: str,
    *,
    audience: str,
    issuer: str,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    header = jwt.get_unverified_header(token)
    if header.get('alg') != 'RS256':
        raise IdentityJwksError('Identity JWT must use RS256.')
    document = get_jwks_document(jwks_url=jwks_url, jwks=jwks, timeout=timeout)
    key = resolve_verification_key(token, document)
    try:
        return jwt.decode(
            token,
            key=key,
            algorithms=['RS256'],
            audience=audience,
            issuer=issuer,
            options={'require': ['exp', 'iat', 'sub', 'scope']},
        )
    except jwt.PyJWTError as exc:
        raise IdentityJwksError('Invalid Identity JWT.') from exc
