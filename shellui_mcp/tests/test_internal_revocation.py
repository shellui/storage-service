import time
import unittest
import uuid

import jwt

from shellui_mcp.internal import (
    REVOCATION_AUDIENCE,
    REVOCATION_CACHE_SECONDS,
    REVOCATION_LIST_SCOPE,
    InternalAssertionError,
    parse_trusted_revocation_poll_response,
    verify_mcp_revocation_list_response,
)
from shellui_mcp.tests.rs256_helpers import generate_test_rsa_jwks, sign_test_revocation_list_assertion

TEST_ISSUER = 'https://identity.example.com'


class RevocationListJwksVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jwks, cls.private_pem, cls.kid = generate_test_rsa_jwks()

    def _signed_payload(self, *, ids=None, agents=None):
        ids = ids if ids is not None else ['agent-1']
        assertion = sign_test_revocation_list_assertion(
            private_pem=self.private_pem,
            kid=self.kid,
            issuer=TEST_ISSUER,
            revoked_agent_ids=ids,
            agents=agents or [],
            cache_seconds=REVOCATION_CACHE_SECONDS,
        )
        return {
            'revoked_agent_ids': ids,
            'agents': agents or [],
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_assertion': assertion,
        }

    def test_verify_accepts_matching_payload(self):
        agents = [{'agent_id': 'a', 'company_id': 1, 'is_active': False, 'paused': True}]
        payload = self._signed_payload(ids=['a', 'b'], agents=agents)
        trusted = verify_mcp_revocation_list_response(
            payload,
            expected_issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        self.assertEqual(trusted['revoked_agent_ids'], ['a', 'b'])
        ids, cache, rows = parse_trusted_revocation_poll_response(
            payload,
            expected_issuer=TEST_ISSUER,
            jwks=self.jwks,
        )
        self.assertEqual(ids, frozenset({'a', 'b'}))
        self.assertEqual(cache, REVOCATION_CACHE_SECONDS)
        self.assertEqual(rows, agents)

    def test_missing_assertion_fails_closed(self):
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(
                {'revoked_agent_ids': []},
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_body_tamper_fails_closed(self):
        payload = self._signed_payload(ids=['a'])
        payload['revoked_agent_ids'] = ['b']
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )

    def test_hs256_assertion_rejected(self):
        now = int(time.time())
        hs256_token = jwt.encode(
            {
                'iss': TEST_ISSUER,
                'aud': REVOCATION_AUDIENCE,
                'sub': 'identity',
                'scope': REVOCATION_LIST_SCOPE,
                'revoked_agent_ids': ['a'],
                'agents': [],
                'cache_seconds': REVOCATION_CACHE_SECONDS,
                'iat': now,
                'exp': now + REVOCATION_CACHE_SECONDS,
                'jti': uuid.uuid4().hex,
            },
            'test-hs256-secret',
            algorithm='HS256',
        )
        hs256_token = hs256_token.decode('utf-8') if isinstance(hs256_token, bytes) else hs256_token
        payload = {
            'revoked_agent_ids': ['a'],
            'agents': [],
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_assertion': hs256_token,
        }
        with self.assertRaises(InternalAssertionError) as ctx:
            verify_mcp_revocation_list_response(
                payload,
                expected_issuer=TEST_ISSUER,
                jwks=self.jwks,
            )
        self.assertIn('RS256', str(ctx.exception))
