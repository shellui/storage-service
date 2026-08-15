"""Unit tests for JWT authentication — expired tokens must never become principals."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import jwt
from django.test import SimpleTestCase, override_settings
from rest_framework.exceptions import AuthenticationFailed

from apps.authapi.authentication import IdentityJWKSAuthentication


@override_settings(
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    IDENTITY_AUDIENCE='',
    IDENTITY_ISSUER='',
    JWT_ALGORITHMS=['RS256'],
    DEBUG=True,
)
class ExpiredTokenAuthenticationTests(SimpleTestCase):
    def setUp(self):
        self.auth = IdentityJWKSAuthentication()
        self.jwks_patch = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = self.jwks_patch.start()
        mock_client.return_value.get_signing_key.return_value = None
        self.addCleanup(self.jwks_patch.stop)

    def _token(self, *, exp: int) -> str:
        return jwt.encode(
            {
                'sub': '1',
                'user_id': 1,
                'company_id': 10,
                'email': 'user@example.com',
                'user_metadata': {'is_staff': False, 'is_company_owner': False},
                'exp': exp,
            },
            'test-secret',
            algorithm='HS256',
        )

    def test_expired_token_raises_authentication_failed(self):
        with self.assertRaises(AuthenticationFailed) as ctx:
            self.auth.authenticate_credentials(self._token(exp=1))
        self.assertIn('expired', str(ctx.exception.detail).lower())

    def test_valid_token_returns_principal(self):
        principal = self.auth.authenticate_credentials(self._token(exp=2**31 - 1))
        self.assertEqual(principal.user_id, 1)
        self.assertEqual(principal.company_id, 10)
        self.assertTrue(principal.is_authenticated)
        self.assertFalse(principal.access_global_metrics)

    def test_pat_agm_claim_sets_access_global_metrics(self):
        raw = jwt.encode(
            {
                'sub': '1',
                'user_id': 1,
                'company_id': 10,
                'email': 'user@example.com',
                'user_metadata': {'is_staff': False, 'is_company_owner': True},
                'pat_agm': True,
                'exp': 2**31 - 1,
            },
            'test-secret',
            algorithm='HS256',
        )
        principal = self.auth.authenticate_credentials(raw)
        self.assertTrue(principal.access_global_metrics)
        self.assertTrue(principal.is_company_owner)

    def test_missing_exp_rejected(self):
        raw = jwt.encode(
            {
                'sub': '1',
                'user_id': 1,
                'company_id': 10,
                'email': 'user@example.com',
                'user_metadata': {},
            },
            'test-secret',
            algorithm='HS256',
        )
        with self.assertRaises(AuthenticationFailed):
            self.auth.authenticate_credentials(raw)

    def test_rs256_expired_token_raises_before_hs256_fallback(self):
        """ExpiredSignatureError from JWKS path must not fall through to a success."""
        expired = self._token(exp=1)
        mock_key = MagicMock()
        mock_key.key = 'unused'

        with patch('apps.authapi.authentication.get_jwks_client') as get_client:
            get_client.return_value.get_signing_key.return_value = mock_key
            with patch(
                'apps.authapi.authentication.jwt.decode',
                side_effect=jwt.ExpiredSignatureError('expired'),
            ):
                with self.assertRaises(AuthenticationFailed) as ctx:
                    self.auth.authenticate_credentials(expired)
        self.assertIn('expired', str(ctx.exception.detail).lower())
