"""JWKS fetch retries and stale-cache behaviour."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase
from jwt.algorithms import RSAAlgorithm
from requests.exceptions import HTTPError, ReadTimeout

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

    def test_http_400_is_not_retried(self):
        response = MagicMock()
        response.status_code = 400
        error = HTTPError('400 Client Error')
        error.response = response
        response.raise_for_status.side_effect = error
        client = JWKSClient('https://id.example/.well-known/jwks.json', retries=2)
        with (
            patch.object(client._session, 'get', return_value=response) as mock_get,
            patch('apps.authapi.jwks_client.time.sleep') as mock_sleep,
            self.assertRaises(HTTPError),
        ):
            client._refresh()
        self.assertEqual(mock_get.call_count, 1)
        mock_sleep.assert_not_called()

    def test_static_document_never_fetches(self):
        document = _sample_jwks()
        token = jwt.encode(
            {'exp': 2**31 - 1},
            'secret',
            algorithm='HS256',
            headers={'kid': 'kid-1'},
        )
        client = JWKSClient(
            'https://id.example/.well-known/jwks.json',
            static_document=document,
        )
        with patch.object(client._session, 'get') as mock_get:
            key = client.get_signing_key(token)
        mock_get.assert_not_called()
        self.assertIsNotNone(key)
        self.assertEqual(client.key_count(), 1)
        self.assertEqual(client.key_ids(), ['kid-1'])

    def test_empty_keys_returns_none_and_logs(self):
        token = jwt.encode(
            {'exp': 2**31 - 1},
            'secret',
            algorithm='HS256',
            headers={'kid': 'kid-1', 'alg': 'HS256'},
        )
        client = JWKSClient('https://id.example/.well-known/jwks.json')
        with (
            patch.object(client._session, 'get', return_value=_ok_response({'keys': []})),
            self.assertLogs('apps.authapi.jwks_client', level='WARNING') as logs,
        ):
            key = client.get_signing_key(token)
        self.assertIsNone(key)
        self.assertIn('JWKS has no keys', '\n'.join(logs.output))

    def test_kid_mismatch_with_multiple_keys_logs_available_kids(self):
        first = _sample_jwks(kid='kid-1')
        second = _sample_jwks(kid='kid-2')
        document = {'keys': first['keys'] + second['keys']}
        token = jwt.encode(
            {'exp': 2**31 - 1},
            'secret',
            algorithm='HS256',
            headers={'kid': 'missing-kid'},
        )
        client = JWKSClient(static_document=document)
        with self.assertLogs('apps.authapi.jwks_client', level='WARNING') as logs:
            with self.assertRaises(jwt.InvalidTokenError) as ctx:
                client.get_signing_key(token)
        self.assertIn('missing-kid', str(ctx.exception))
        joined = '\n'.join(logs.output)
        self.assertIn('missing-kid', joined)
        self.assertIn('kid-1', joined)
        self.assertIn('kid-2', joined)
