"""JWKS fetch retries and stale-cache behaviour."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import Client, SimpleTestCase, override_settings
from jwt.algorithms import RSAAlgorithm
from requests.exceptions import HTTPError, ReadTimeout
from rest_framework.exceptions import AuthenticationFailed

from apps.authapi.authentication import IdentityJWKSAuthentication
from apps.authapi.jwks_client import JWKSClient


def _rsa_material(*, kid: str) -> tuple[dict, rsa.RSAPrivateKey]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    jwk.update({'kid': kid, 'use': 'sig', 'alg': 'RS256'})
    return jwk, private


def _sample_jwks(*, kid: str = 'kid-1') -> dict:
    jwk, _private = _rsa_material(kid=kid)
    return {'keys': [jwk]}


def _signed(private, kid: str | None, **extra) -> str:
    payload = {
        'sub': '1',
        'user_id': 1,
        'company_id': 10,
        'email': 'user@example.com',
        'user_metadata': {'is_staff': False, 'is_company_owner': False},
        'exp': 2**31 - 1,
    }
    payload.update(extra)
    headers = {'kid': kid} if kid is not None else None
    return jwt.encode(payload, private, algorithm='RS256', headers=headers)


def _decode(token: str, key) -> dict:
    return jwt.decode(
        token,
        key.key,
        algorithms=['RS256'],
        options={'verify_aud': False, 'verify_iss': False},
    )


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

    def test_empty_keys_with_kid_fails_closed(self):
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
            self.assertRaises(jwt.InvalidTokenError) as ctx,
        ):
            client.get_signing_key(token)
        self.assertIn('kid-1', str(ctx.exception))
        self.assertIn('JWKS has no keys', '\n'.join(logs.output))

    def test_empty_keys_without_kid_returns_none_and_logs(self):
        token = jwt.encode({'exp': 2**31 - 1}, 'secret', algorithm='HS256')
        self.assertNotIn('kid', jwt.get_unverified_header(token))
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
        self.assertIn('refusing another key', joined)

    def test_unknown_kid_does_not_fall_back_to_sole_key(self):
        jwk, private = _rsa_material(kid='kid-1')
        token = _signed(private, 'not-loaded')
        client = JWKSClient(static_document={'keys': [jwk]})
        with self.assertLogs('apps.authapi.jwks_client', level='WARNING') as logs:
            with self.assertRaises(jwt.InvalidTokenError) as ctx:
                client.get_signing_key(token)
        self.assertIn('not-loaded', str(ctx.exception))
        self.assertIn('refusing another key', '\n'.join(logs.output))
        # The sole key did sign this token. Returning it would verify the signature.
        verified = _decode(token, jwt.PyJWK.from_dict(jwk))
        self.assertEqual(verified['user_id'], 1)

    def test_current_kid_verifies(self):
        jwk, private = _rsa_material(kid='kid-1')
        token = _signed(private, 'kid-1')
        client = JWKSClient(static_document={'keys': [jwk]})
        key = client.get_signing_key(token)
        self.assertEqual(_decode(token, key)['company_id'], 10)

    def test_token_without_kid_still_uses_sole_key(self):
        jwk, private = _rsa_material(kid='kid-1')
        token = _signed(private, None)
        self.assertNotIn('kid', jwt.get_unverified_header(token))
        client = JWKSClient(static_document={'keys': [jwk]})
        key = client.get_signing_key(token)
        self.assertEqual(_decode(token, key)['user_id'], 1)

    def test_rotation_accepts_new_kid_and_keeps_current(self):
        old_jwk, old_private = _rsa_material(kid='kid-old')
        new_jwk, new_private = _rsa_material(kid='kid-new')
        client = JWKSClient('https://id.example/.well-known/jwks.json', ttl=900)
        with patch.object(client._session, 'get', return_value=_ok_response({'keys': [old_jwk]})):
            client._refresh()
        current = _signed(old_private, 'kid-old')
        rotated = _signed(new_private, 'kid-new')
        with patch.object(
            client._session,
            'get',
            return_value=_ok_response({'keys': [old_jwk, new_jwk]}),
        ) as mock_get:
            current_key = client.get_signing_key(current)
            mock_get.assert_not_called()
            new_key = client.get_signing_key(rotated)
            self.assertGreaterEqual(mock_get.call_count, 1)
        self.assertEqual(_decode(current, current_key)['user_id'], 1)
        self.assertEqual(_decode(rotated, new_key)['user_id'], 1)
        self.assertEqual(_decode(current, client.get_signing_key(current))['company_id'], 10)

    def test_unknown_kid_still_fails_after_refresh(self):
        jwk, private = _rsa_material(kid='kid-1')
        client = JWKSClient('https://id.example/.well-known/jwks.json', ttl=900)
        with patch.object(client._session, 'get', return_value=_ok_response({'keys': [jwk]})):
            client._refresh()
        token = _signed(private, 'bogus')
        with patch.object(client._session, 'get', return_value=_ok_response({'keys': [jwk]})) as mock_get:
            with self.assertRaises(jwt.InvalidTokenError):
                client.get_signing_key(token)
        self.assertGreaterEqual(mock_get.call_count, 1)


_AUTH_SETTINGS = dict(
    JWT_HS256_FALLBACK_SECRET=None,
    ALLOW_JWT_HS256_FALLBACK=False,
    JWT_ALGORITHMS=['RS256'],
    IDENTITY_AUDIENCE='',
    IDENTITY_ISSUER='',
)


@override_settings(**_AUTH_SETTINGS)
class JWKSAuthenticationFlowTests(SimpleTestCase):
    """Bearer verification for a real RS256 key, not a mocked signing key."""

    def test_current_kid_authenticates_and_unknown_kid_does_not(self):
        jwk, private = _rsa_material(kid='kid-1')
        good = _signed(private, 'kid-1', pat_agm=True)
        bogus = _signed(private, 'not-loaded')
        jwks = JWKSClient(static_document={'keys': [jwk]})
        auth = IdentityJWKSAuthentication()
        with patch('apps.authapi.authentication.get_jwks_client', return_value=jwks):
            principal = auth.authenticate_credentials(good)
            self.assertEqual(principal.user_id, 1)
            self.assertEqual(principal.company_id, 10)
            self.assertTrue(principal.access_global_metrics)
            with self.assertRaises(AuthenticationFailed):
                auth.authenticate_credentials(bogus)

    def test_health_accepts_current_kid_and_rejects_unknown_kid(self):
        jwk, private = _rsa_material(kid='kid-1')
        good = _signed(private, 'kid-1')
        bogus = _signed(private, 'not-loaded')
        jwks = JWKSClient(static_document={'keys': [jwk]})
        with patch('apps.authapi.authentication.get_jwks_client', return_value=jwks):
            ok = Client().get('/storage/v1/health', HTTP_AUTHORIZATION=f'Bearer {good}')
            rejected = Client().get('/storage/v1/health', HTTP_AUTHORIZATION=f'Bearer {bogus}')
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json()['status'], 'ok')
        self.assertIn('storage_backend', ok.json())
        self.assertEqual(rejected.status_code, 401)
        self.assertNotIn('storage_backend', rejected.json())
