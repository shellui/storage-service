"""JWKS fetch retries and stale-cache behaviour."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase
from jwt.algorithms import RSAAlgorithm
from requests.exceptions import ReadTimeout

from apps.authapi.jwks_client import JWKSClient


def _sample_jwks(*, kid: str = 'kid-1') -> dict:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update({'kid': kid, 'use': 'sig', 'alg': 'RS256'})
    return {'keys': [jwk]}


def _ok_response(document: dict) -> MagicMock:
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = document
    return response


class JWKSClientRetryTests(SimpleTestCase):
    def test_retries_after_read_timeout_then_succeeds(self):
        document = _sample_jwks()
        client = JWKSClient('https://id.example/.well-known/jwks.json', retries=2)
        with (
            patch.object(
                client._session,
                'get',
                side_effect=[ReadTimeout('slow'), ReadTimeout('slow'), _ok_response(document)],
            ) as mock_get,
            patch('apps.authapi.jwks_client.time.sleep'),
        ):
            client._refresh()
        self.assertEqual(mock_get.call_count, 3)
        self.assertIn('kid-1', client._keys)

    def test_stale_keys_kept_when_refresh_times_out(self):
        document = _sample_jwks()
        client = JWKSClient('https://id.example/.well-known/jwks.json', ttl=0, retries=1)
        with patch.object(client._session, 'get', return_value=_ok_response(document)):
            client._refresh()
        self.assertTrue(client._keys)
        with (
            patch.object(client._session, 'get', side_effect=ReadTimeout('slow')),
            patch('apps.authapi.jwks_client.time.sleep'),
        ):
            client._refresh(force=True)
        self.assertIn('kid-1', client._keys)

    def test_empty_cache_raises_after_retries_exhausted(self):
        client = JWKSClient('https://id.example/.well-known/jwks.json', retries=1)
        with (
            patch.object(client._session, 'get', side_effect=ReadTimeout('slow')),
            patch('apps.authapi.jwks_client.time.sleep'),
            self.assertRaises(ReadTimeout),
        ):
            client._refresh()
