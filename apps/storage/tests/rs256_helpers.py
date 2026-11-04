"""RS256 JWKS fixtures for MCP identity tests (mirrors shellui-django mcp/tests/rs256_helpers)."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _int_to_base64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, 'big')).rstrip(b'=').decode('ascii')


def generate_test_rsa_jwks() -> tuple[dict, str, str]:
    """Return ``(jwks_document, private_pem, kid)``."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_numbers = private_key.public_key().public_numbers()
    canonical = json.dumps(
        {
            'e': _int_to_base64url(public_numbers.e),
            'kty': 'RSA',
            'n': _int_to_base64url(public_numbers.n),
        },
        separators=(',', ':'),
        sort_keys=True,
    )
    kid = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b'=').decode('ascii')
    jwk = {
        'kty': 'RSA',
        'use': 'sig',
        'alg': 'RS256',
        'kid': kid,
        'n': _int_to_base64url(public_numbers.n),
        'e': _int_to_base64url(public_numbers.e),
    }
    return {'keys': [jwk]}, private_pem, kid


def sign_test_revocation_list_assertion(
    *,
    private_pem: str,
    kid: str,
    issuer: str,
    revoked_agent_ids: list[str],
    agents: list[dict] | None = None,
    cache_seconds: int = 30,
) -> str:
    now = int(time.time())
    claims = {
        'iss': issuer,
        'aud': 'shellui-mcp-revocation',
        'sub': 'identity',
        'scope': 'mcp.revocation.list',
        'revoked_agent_ids': revoked_agent_ids,
        'agents': agents or [],
        'cache_seconds': cache_seconds,
        'iat': now,
        'exp': now + cache_seconds,
        'jti': uuid.uuid4().hex,
    }
    token = jwt.encode(claims, private_pem, algorithm='RS256', headers={'kid': kid})
    return token.decode('utf-8') if isinstance(token, bytes) else token


# This service's own signing key for internal MCP assertions (config/service_signing.py).
_SIGNING_JWKS, _SIGNING_PEM, _SIGNING_KID = generate_test_rsa_jwks()
MCP_SIGNING_TEST_SETTINGS = {'MCP_SIGNING_KEY_PEM': _SIGNING_PEM, 'MCP_SIGNING_ISSUER': 'https://storage.test'}
