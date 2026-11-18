"""This service signs internal MCP assertions with its own RS256 key and serves the public JWKS."""

from __future__ import annotations

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings
from shellui_django.mcp.internal import (
    REVOCATION_AUDIENCE,
    REVOCATION_SCOPE,
    InternalAssertionError,
    build_mcp_revocation_assertion,
    verify_mcp_internal_assertion,
)

from config.service_signing import public_jwk, signing_kwargs


def _private_pem(bits: int = 2048) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


_PEM = _private_pem()
_ISSUER = 'https://service.test'


@override_settings(MCP_SIGNING_KEY_PEM=_PEM, MCP_SIGNING_ISSUER=_ISSUER)
class ServiceSigningTests(SimpleTestCase):
    def test_jwks_serves_only_the_public_key(self):
        response = self.client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        keys = json.loads(response.content)['keys']
        self.assertEqual(len(keys), 1)
        self.assertEqual(set(keys[0]), {'kty', 'use', 'alg', 'kid', 'n', 'e'})

    def test_assertion_verifies_with_served_jwks(self):
        token = build_mcp_revocation_assertion(audience_url='https://identity.test', **signing_kwargs())
        jwks = json.loads(self.client.get('/.well-known/jwks.json').content)
        claims = verify_mcp_internal_assertion(
            token,
            jwks,
            expected_issuer=_ISSUER,
            expected_audience=REVOCATION_AUDIENCE,
            expected_scope=REVOCATION_SCOPE,
            expected_target='https://identity.test',
        )
        self.assertEqual(claims['iss'], _ISSUER)

    @override_settings(MCP_SIGNING_KEY_PEM='')
    def test_without_key_signing_is_unavailable_and_jwks_is_empty(self):
        with self.assertRaises(InternalAssertionError) as ctx:
            signing_kwargs()
        self.assertEqual(ctx.exception.status, 503)
        self.assertEqual(json.loads(self.client.get('/.well-known/jwks.json').content), {'keys': []})

    @override_settings(MCP_SIGNING_ISSUER='')
    def test_without_issuer_signing_is_unavailable(self):
        with self.assertRaises(InternalAssertionError):
            signing_kwargs()

    def test_weak_or_invalid_keys_are_refused(self):
        with self.assertRaises(ImproperlyConfigured):
            public_jwk(_private_pem(1024))
        with self.assertRaises(ImproperlyConfigured):
            public_jwk('not a key')
