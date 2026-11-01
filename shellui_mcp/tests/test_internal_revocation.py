from django.test import TestCase, override_settings

from shellui_mcp.internal import (
    InternalAssertionError,
    REVOCATION_CACHE_SECONDS,
    build_mcp_revocation_list_response_assertion,
    parse_trusted_revocation_poll_response,
    verify_mcp_revocation_list_response,
)


@override_settings(JWT_ISSUER='https://identity.test')
class RevocationListResponseAssertionTests(TestCase):
    def _signed_payload(self, *, ids=None):
        ids = ids if ids is not None else ['agent-1']
        assertion = build_mcp_revocation_list_response_assertion(
            revoked_agent_ids=ids,
            cache_seconds=REVOCATION_CACHE_SECONDS,
        )
        return {
            'revoked_agent_ids': ids,
            'cache_seconds': REVOCATION_CACHE_SECONDS,
            'revocation_assertion': assertion,
        }

    def test_verify_accepts_matching_payload(self):
        payload = self._signed_payload(ids=['a', 'b'])
        trusted = verify_mcp_revocation_list_response(payload, expected_issuer='https://identity.test')
        self.assertEqual(trusted['revoked_agent_ids'], ['a', 'b'])
        ids, cache = parse_trusted_revocation_poll_response(payload, expected_issuer='https://identity.test')
        self.assertEqual(ids, frozenset({'a', 'b'}))
        self.assertEqual(cache, REVOCATION_CACHE_SECONDS)

    def test_missing_assertion_fails_closed(self):
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response({'revoked_agent_ids': []})

    def test_body_tamper_fails_closed(self):
        payload = self._signed_payload(ids=['a'])
        payload['revoked_agent_ids'] = ['b']
        with self.assertRaises(InternalAssertionError):
            verify_mcp_revocation_list_response(payload, expected_issuer='https://identity.test')
