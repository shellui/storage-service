"""This service's RS256 key for internal MCP assertions to Identity, and its public JWKS.

Identity verifies those assertions with ``GET /.well-known/jwks.json`` and trusts them only
from the issuer it has registered for this service. The private key is never logged or served.
"""

from __future__ import annotations

import base64
import hashlib
import json
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import JsonResponse
from jwt.algorithms import RSAAlgorithm

MIN_RSA_KEY_SIZE = 2048


def read_signing_pem(*, value: str, file_path: str, base_dir: Path) -> str:
    """Settings helper: PEM from ``*_SIGNING_KEY_FILE`` (preferred) or ``*_SIGNING_KEY``."""
    if file_path:
        path = Path(file_path)
        if not path.is_absolute():
            path = base_dir / path
        if not path.is_file():
            raise ImproperlyConfigured(f'Signing key file not found: {path}')
        value = path.read_text(encoding='utf-8')
    pem = (value or '').strip().replace('\\n', '\n')
    if pem:
        public_jwk(pem)
    return pem


@lru_cache(maxsize=4)
def public_jwk(private_pem: str) -> dict:
    """Public JWK with an RFC 7638 thumbprint ``kid``. Raises ImproperlyConfigured on a bad key."""
    try:
        key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    except ValueError as exc:
        raise ImproperlyConfigured('Service signing key is not a valid PEM private key.') from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < MIN_RSA_KEY_SIZE:
        raise ImproperlyConfigured(f'Service signing key must be RSA, at least {MIN_RSA_KEY_SIZE} bits.')
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    canonical = json.dumps({k: jwk[k] for k in ('e', 'kty', 'n')}, separators=(',', ':'), sort_keys=True)
    kid = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b'=').decode()
    return {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': kid, 'n': jwk['n'], 'e': jwk['e']}


def signing_kwargs() -> dict[str, str]:
    """Keyword arguments for ``shellui_django.mcp.internal.build_mcp_*_assertion``."""
    # Imported here: settings.py loads this module before SimpleJWT settings exist.
    from shellui_django.mcp.internal import InternalAssertionError

    pem = getattr(settings, 'MCP_SIGNING_KEY_PEM', '') or ''
    issuer = (getattr(settings, 'MCP_SIGNING_ISSUER', '') or '').strip().rstrip('/')
    if not pem or not issuer:
        raise InternalAssertionError('Service assertion signing is not configured.', status=503)
    return {'private_key_pem': pem, 'kid': public_jwk(pem)['kid'], 'issuer': issuer}


def jwks_view(_request):
    pem = getattr(settings, 'MCP_SIGNING_KEY_PEM', '') or ''
    response = JsonResponse({'keys': [public_jwk(pem)] if pem else []})
    response['Cache-Control'] = 'public, max-age=900'
    return response
