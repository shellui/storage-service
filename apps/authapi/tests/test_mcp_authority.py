"""Delegated regional MCP authority: live Identity lookup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.authapi.mcp_authority import (
    clear_delegated_authority_cache,
    delegated_regional_authority_live_ok,
)
from apps.storage.tests.rs256_helpers import MCP_SIGNING_TEST_SETTINGS

_GCC = '18e20f88-286e-46ea-858e-1d75bca615ff'

_CLAIMS_DELEGATED = {
    'sub': 'agent:a1',
    'agent_id': 'a1',
    'company_id': 10,
    'scope': 'storage',
    'mcp_access': 'read_only',
    'aud': 'http://127.0.0.1/mcp',
    'iss': 'https://identity.test',
    'global_company_id': _GCC,
    'company_binding_version': 0,
    'grant_version': 0,
    'mcp_authority': 'delegated',
}
_RES = 'http://127.0.0.1/mcp'


def _ok_body():
    return {
        'authorized': True,
        'revoked': False,
        'paused': False,
        'row': {
            'agent_id': 'a1',
            'company_id': 10,
            'global_company_id': _GCC,
            'grant_version': 0,
            'company_binding_version': 0,
        },
    }


@override_settings(
    **MCP_SIGNING_TEST_SETTINGS,
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
)
class DelegatedAuthorityTests(SimpleTestCase):
    def setUp(self):
        clear_delegated_authority_cache()

    def test_personal_skips_lookup(self):
        claims = {**_CLAIMS_DELEGATED}
        del claims['global_company_id']
        del claims['company_binding_version']
        del claims['grant_version']
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            self.assertTrue(delegated_regional_authority_live_ok(claims, expected_resource=_RES))
        mock_post.assert_not_called()

    def test_wrong_issuer_skips_network(self):
        claims = {**_CLAIMS_DELEGATED, 'iss': 'https://evil.example'}
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            self.assertFalse(delegated_regional_authority_live_ok(claims, expected_resource=_RES))
        mock_post.assert_not_called()

    def test_posts_exact_json_body_on_allow(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=_ok_body)
            self.assertTrue(delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES))
        kwargs = mock_post.call_args.kwargs
        self.assertEqual(
            kwargs['json'],
            {
                'agent_id': 'a1',
                'company_id': 10,
                'global_company_id': _GCC,
                'grant_version': 0,
                'company_binding_version': 0,
            },
        )
        self.assertTrue(kwargs['headers']['Authorization'].startswith('Bearer '))

    def test_denies_when_identity_says_no(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {**_ok_body(), 'authorized': False, 'row': _ok_body()['row']},
            )
            self.assertFalse(delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES))

    def test_row_triplet_mismatch_overrides_ok(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            body = _ok_body()
            body['row']['grant_version'] = 1
            mock_post.return_value = MagicMock(status_code=200, json=lambda b=body: b)
            self.assertFalse(delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES))
