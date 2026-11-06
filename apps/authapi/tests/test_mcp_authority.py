"""Delegated regional MCP authority: live Identity lookup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.authapi.mcp_authority import (
    DelegatedAuthorityDenied,
    clear_delegated_authority_cache,
    delegated_regional_authority_live_ok,
)
from apps.storage.tests.rs256_helpers import MCP_SIGNING_TEST_SETTINGS

_GCC = '18e20f88-286e-46ea-858e-1d75bca615ff'
_GAI = '28e20f88-286e-46ea-858e-1d75bca615ff'
_AID = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'


def _identity_ok(
    *,
    agent_id: str = _AID,
    company_id: int = 10,
    global_company_id: str = _GCC,
    global_agent_id: str = _GAI,
    grant_version: int = 0,
    company_binding_version: int = 0,
    authorized: bool = True,
    revoked: bool = False,
    paused: bool = False,
) -> dict:
    """Identity ``mcp-agent-delegated-authority`` HTTP 200 body (PR #135 head, no extra keys)."""
    return {
        'authorized': authorized,
        'revoked': revoked,
        'paused': paused,
        'agent_id': agent_id,
        'company_id': company_id,
        'global_company_id': global_company_id,
        'global_agent_id': global_agent_id,
        'grant_version': grant_version,
        'company_binding_version': company_binding_version,
    }


_CLAIMS_DELEGATED = {
    'sub': f'agent:{_AID}',
    'agent_id': _AID,
    'company_id': 10,
    'global_agent_id': _GAI,
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
        del claims['mcp_authority']
        del claims['global_agent_id']
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            self.assertTrue(delegated_regional_authority_live_ok(claims, expected_resource=_RES))
        mock_post.assert_not_called()

    def test_wrong_issuer_skips_network(self):
        claims = {**_CLAIMS_DELEGATED, 'iss': 'https://evil.example'}
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            self.assertFalse(delegated_regional_authority_live_ok(claims, expected_resource=_RES))
        mock_post.assert_not_called()

    def test_posts_body_without_global_agent_id_in_json(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: _identity_ok())
            self.assertTrue(delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES))
        kwargs = mock_post.call_args.kwargs
        self.assertEqual(
            kwargs['json'],
            {
                'agent_id': _AID,
                'company_id': 10,
                'global_company_id': _GCC,
                'grant_version': 0,
                'company_binding_version': 0,
            },
        )
        self.assertNotIn('global_agent_id', kwargs['json'])
        self.assertTrue(kwargs['headers']['Authorization'].startswith('Bearer '))

    def test_global_agent_id_from_identity_must_match_jwt(self):
        claims = {**_CLAIMS_DELEGATED, 'global_agent_id': _GAI}
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: _identity_ok())
            self.assertTrue(delegated_regional_authority_live_ok(claims, expected_resource=_RES))
        self.assertNotIn('global_agent_id', mock_post.call_args.kwargs['json'])

    def test_token_global_agent_mismatch_raises(self):
        other_gai = '38e20f88-286e-46ea-858e-1d75bca615ff'
        claims = {**_CLAIMS_DELEGATED, 'global_agent_id': _GAI}
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: _identity_ok(global_agent_id=other_gai))
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(claims, expected_resource=_RES)

    def test_http_403_raises_denied(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=403, json=dict)
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)

    def test_unauthorized_raises_denied(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: _identity_ok(authorized=False),
            )
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)

    def test_revoked_true_raises_denied(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: _identity_ok(revoked=True),
            )
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)

    def test_paused_true_raises_denied(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: _identity_ok(paused=True),
            )
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)

    def test_string_booleans_fail_closed(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            bad = _identity_ok()
            bad['authorized'] = 'true'
            mock_post.return_value = MagicMock(status_code=200, json=lambda: bad)
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)

    def test_extra_top_level_key_raises_denied(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            bad = _identity_ok()
            bad['services_allowed'] = ['storage']
            mock_post.return_value = MagicMock(status_code=200, json=lambda: bad)
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)

    def test_soft_ok_flag_insufficient(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {'ok': True, 'authorized': True})
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)

    def test_grant_version_mismatch_raises_denied(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: _identity_ok(grant_version=1))
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)

    def test_missing_global_agent_id_in_response_raises_denied(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            body = _identity_ok()
            del body['global_agent_id']
            mock_post.return_value = MagicMock(status_code=200, json=lambda b=body: b)
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)

    def test_strict_ok_cached_within_ttl(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: _identity_ok())
            self.assertTrue(delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES))
            self.assertTrue(delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES))
            self.assertEqual(mock_post.call_count, 1)

    def test_negative_not_cached(self):
        with patch('apps.authapi.mcp_authority.requests.post') as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: _identity_ok(authorized=False),
            )
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)
            with self.assertRaises(DelegatedAuthorityDenied):
                delegated_regional_authority_live_ok(_CLAIMS_DELEGATED, expected_resource=_RES)
            self.assertEqual(mock_post.call_count, 2)
