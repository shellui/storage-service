"""Agent access tokens stay on POST /mcp and are not company owners."""

from __future__ import annotations

from unittest.mock import patch

import jwt
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.agent_tokens import authenticate_agent_bearer, principal_from_agent_claims
from apps.authapi.principal import StoragePrincipal


def _encode(payload: dict) -> str:
    body = {'exp': 2**31 - 1, **payload}
    return jwt.encode(body, 'test-secret', algorithm='HS256')


@override_settings(
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    IDENTITY_AUDIENCE='',
    IDENTITY_ISSUER='',
    DEBUG=True,
    STORAGE_BACKEND='filesystem',
)
class AgentTokenBoundaryTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        jwks = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = jwks.start()
        mock_client.return_value.get_signing_key.return_value = None
        mock_client.return_value.key_count.return_value = 0
        mock_client.return_value.key_ids.return_value = []
        self.addCleanup(jwks.stop)

    def test_principal_uses_owner_and_never_owner_role(self):
        principal = principal_from_agent_claims(
            {
                'sub': 'agent:abc',
                'agent_id': 'abc',
                'company_id': 10,
                'owner_user_id': 7,
                'email': 'ada@example.com',
                'user_metadata': {
                    'is_company_owner': True,
                    'is_staff': True,
                    'email': 'ignored@example.com',
                },
                'pat_agm': True,
            }
        )
        self.assertEqual(principal.user_id, 7)
        self.assertEqual(principal.company_id, 10)
        self.assertEqual(principal.email, 'ada@example.com')
        self.assertFalse(principal.is_company_owner)
        self.assertFalse(principal.is_staff)
        self.assertFalse(principal.access_global_metrics)

    def test_bool_owner_user_id_is_not_a_user(self):
        principal = principal_from_agent_claims(
            {
                'sub': 'agent:abc',
                'agent_id': 'abc',
                'company_id': 10,
                'owner_user_id': True,
            }
        )
        self.assertEqual(principal.user_id, 0)
        self.assertFalse(principal.is_company_owner)

    def test_refresh_token_is_not_a_bearer(self):
        token = _encode(
            {
                'sub': '1',
                'user_id': 1,
                'company_id': 10,
                'token_type': 'refresh',
                'user_metadata': {'is_staff': False, 'is_company_owner': True},
            }
        )
        response = self.client.get(
            '/storage/v1/bucket',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 401)

    def test_agent_token_rejected_outside_mcp(self):
        token = _encode(
            {
                'sub': 'agent:abc',
                'agent_id': 'abc',
                'user_id': 1,
                'owner_user_id': 1,
                'company_id': 10,
                'token_type': 'access',
                'pat_agm': True,
                'scope': 'storage',
                'user_metadata': {'is_staff': False, 'is_company_owner': True},
            }
        )
        response = self.client.get(
            '/storage/v1/metrics/all',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 401)

    def test_mcp_refuses_refresh_token(self):
        token = _encode(
            {
                'sub': 'agent:abc',
                'agent_id': 'abc',
                'company_id': 10,
                'scope': 'storage',
                'aud': 'http://127.0.0.1/mcp',
                'token_type': 'refresh',
            }
        )
        result = authenticate_agent_bearer(
            token,
            expected_resource='http://127.0.0.1/mcp',
        )
        self.assertIsNone(result)

    def test_global_refused_blocks_agent_even_with_global_metrics(self):
        user = StoragePrincipal(
            user_id=1,
            company_id=10,
            username='agent:abc',
            access_global_metrics=True,
            claims={'agent_id': 'abc', 'sub': 'agent:abc', 'token_type': 'access'},
        )
        self.client.force_authenticate(user=user)
        response = self.client.get('/storage/v1/metrics/all')
        self.assertEqual(response.status_code, 403)

    def test_access_token_without_agent_claim_still_works(self):
        token = _encode(
            {
                'sub': '1',
                'user_id': 1,
                'company_id': 10,
                'token_type': 'access',
                'user_metadata': {'is_staff': False, 'is_company_owner': False},
            }
        )
        response = self.client.get(
            '/storage/v1/bucket',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 200)
