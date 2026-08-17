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
        jwks = mock_client.return_value
        jwks.get_signing_key.return_value = None
        jwks.key_count.return_value = 0
        jwks.key_ids.return_value = []
        jwks.url = 'http://jwks.test/.well-known/jwks.json'
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
            get_client.return_value.key_count.return_value = 1
            get_client.return_value.key_ids.return_value = ['kid-1']
            with patch(
                'apps.authapi.authentication.jwt.decode',
                side_effect=jwt.ExpiredSignatureError('expired'),
            ):
                with self.assertRaises(AuthenticationFailed) as ctx:
                    self.auth.authenticate_credentials(expired)
        self.assertIn('expired', str(ctx.exception.detail).lower())

    def test_expired_token_logs_unverified_claims(self):
        with self.assertLogs('apps.authapi.authentication', level='INFO') as logs:
            with self.assertRaises(AuthenticationFailed):
                self.auth.authenticate_credentials(self._token(exp=1))
        joined = '\n'.join(logs.output)
        self.assertIn('JWT expired', joined)
        self.assertIn('exp=1', joined)
        self.assertIn("alg='HS256'", joined)

    def test_invalid_token_logs_jwks_context(self):
        raw = jwt.encode(
            {
                'sub': '1',
                'user_id': 1,
                'company_id': 10,
                'exp': 2**31 - 1,
            },
            'wrong-secret',
            algorithm='HS256',
        )
        with self.assertLogs('apps.authapi.authentication', level='WARNING') as logs:
            with self.assertRaises(AuthenticationFailed) as ctx:
                self.auth.authenticate_credentials(raw)
        self.assertIn('Token is invalid', str(ctx.exception.detail))
        joined = '\n'.join(logs.output)
        self.assertIn('JWT authentication failed', joined)
        self.assertIn("alg='HS256'", joined)
        self.assertIn('jwks_source=', joined)

    def test_malformed_token_logs_header_error(self):
        with self.assertLogs('apps.authapi.authentication', level='WARNING') as logs:
            with self.assertRaises(AuthenticationFailed):
                self.auth.authenticate_credentials('not-a-jwt')
        joined = '\n'.join(logs.output)
        self.assertIn('JWT', joined)
        self.assertIn('header_error=', joined)

    def test_debug_response_includes_underlying_reason(self):
        with self.assertRaises(AuthenticationFailed) as ctx:
            self.auth.authenticate_credentials('not-a-jwt')
        self.assertIn('DecodeError', str(ctx.exception.detail))

    def test_hs256_without_fallback_logs_hint(self):
        raw = self._token(exp=2**31 - 1)
        with override_settings(
            DEBUG=False,
            JWT_HS256_FALLBACK_SECRET=None,
            ALLOW_JWT_HS256_FALLBACK=False,
        ):
            with self.assertLogs('apps.authapi.authentication', level='WARNING') as logs:
                with self.assertRaises(AuthenticationFailed) as ctx:
                    self.auth.authenticate_credentials(raw)
        self.assertEqual(
            str(ctx.exception.detail),
            'Token is invalid or could not be verified against identity JWKS.',
        )
        self.assertIn('HS256 fallback is disabled', '\n'.join(logs.output))


class RequestIdResponseTests(SimpleTestCase):
    def test_exception_handler_adds_request_id(self):
        from django.test import RequestFactory

        from config.exceptions import exception_handler

        request = RequestFactory().get('/storage/v1/bucket')
        request.request_id = 'abc123def456'
        response = exception_handler(
            AuthenticationFailed('Token is invalid or could not be verified against identity JWKS.'),
            {'request': request},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['request_id'], 'abc123def456')

    def test_middleware_sets_request_id_header(self):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from config.request_context import RequestIdMiddleware

        middleware = RequestIdMiddleware(lambda request: HttpResponse('ok'))
        response = middleware(RequestFactory().get('/storage/v1/health'))
        self.assertTrue(response['X-Request-ID'])
        self.assertEqual(len(response['X-Request-ID']), 12)

    def test_middleware_honors_inbound_request_id(self):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from config.request_context import RequestIdMiddleware, request_id_var

        captured = {}

        def get_response(request):
            captured['id'] = request_id_var.get()
            return HttpResponse('ok')

        middleware = RequestIdMiddleware(get_response)
        request = RequestFactory().get('/storage/v1/health', HTTP_X_REQUEST_ID='from-proxy')
        response = middleware(request)
        self.assertEqual(response['X-Request-ID'], 'from-proxy')
        self.assertEqual(captured['id'], 'from-proxy')

    def test_invalid_bearer_http_includes_request_id(self):
        from django.test import Client

        with patch('apps.authapi.authentication.get_jwks_client') as get_client:
            jwks = get_client.return_value
            jwks.get_signing_key.return_value = None
            jwks.key_count.return_value = 0
            jwks.key_ids.return_value = []
            response = Client().get(
                '/storage/v1/bucket',
                HTTP_AUTHORIZATION='Bearer not-a.jwt.token',
            )
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn('request_id', data)
        self.assertEqual(response['X-Request-ID'], data['request_id'])
        self.assertIn('Token is invalid', data['detail'])
