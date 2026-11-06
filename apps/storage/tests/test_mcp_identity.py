"""Identity MCP integration: fail-closed revocation and approval calls."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings

from apps.storage.tests.rs256_helpers import (
    MCP_SIGNING_TEST_SETTINGS,
    generate_test_rsa_jwks,
    sign_test_revocation_list_assertion,
)

from apps.storage.mcp_identity import (
    agent_is_revoked,
    approval_state,
    consume_approval,
    identity_revocation_unavailable,
)

_TEST_ISSUER = 'https://identity.test'
_JWKS, _PRIVATE_PEM, _KID = generate_test_rsa_jwks()


def _claims_write(
    *,
    company_id: int = 1,
    grant_version: int = 0,
    global_company_id: int | None = 1,
    company_binding_version: int | None = 1,
) -> dict:
    return {
        'mcp_access': 'ask',
        'company_id': company_id,
        'grant_version': grant_version,
        'global_company_id': global_company_id,
        'company_binding_version': company_binding_version,
    }


def _signed_revocation_body(*, revoked_ids=None, agents=None, max_gv=0):
    revoked_ids = revoked_ids or []
    agents = agents or []
    assertion = sign_test_revocation_list_assertion(
        private_pem=_PRIVATE_PEM,
        kid=_KID,
        issuer=_TEST_ISSUER,
        revoked_agent_ids=revoked_ids,
        agents=agents,
        cache_seconds=30,
        max_active_grant_version=max_gv,
    )
    return {
        'revoked_agent_ids': revoked_ids,
        'agents': agents,
        'cache_seconds': 30,
        'revocation_assertion': assertion,
    }


@override_settings(
    **MCP_SIGNING_TEST_SETTINGS,
    IDENTITY_SERVICE_URL='https://identity.test',
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_JWKS_DOCUMENT=_JWKS,
)
class McpIdentityFailClosedTests(SimpleTestCase):
    def setUp(self):
        cache.delete('mcp:revoked_trusted_payload')
        cache.delete('mcp:revoked_list_trusted')
        cache.delete('mcp:revoked_signed_context')

    def test_identity_unavailable_when_revocation_returns_404(self):
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=404)
            self.assertTrue(identity_revocation_unavailable())
            self.assertTrue(agent_is_revoked('agent-1', 10))

    def test_identity_unavailable_when_revocation_unreachable(self):
        with patch(
            'apps.storage.mcp_identity.requests.get',
            side_effect=requests.RequestException('network'),
        ):
            self.assertTrue(identity_revocation_unavailable())
            self.assertTrue(agent_is_revoked('agent-1', 10))

    def test_revocation_poll_sends_signed_assertion(self):
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: _signed_revocation_body(),
            )
            self.assertFalse(agent_is_revoked('agent-1', 10))
        auth = mock_get.call_args.kwargs['headers']['Authorization']
        self.assertRegex(auth, r'^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')

    def test_revoked_agent_requires_matching_company_in_agents_list(self):
        body = _signed_revocation_body(
            revoked_ids=['agent-x'],
            agents=[{'agent_id': 'agent-x', 'company_id': 99}],
        )
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertFalse(agent_is_revoked('agent-x', 10))

    def test_revoked_agent_when_company_matches(self):
        body = _signed_revocation_body(
            revoked_ids=['agent-x'],
            agents=[{'agent_id': 'agent-x', 'company_id': 10}],
        )
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertTrue(agent_is_revoked('agent-x', 10))

    def test_grant_row_mismatch_revokes_when_claims_provided(self):
        body = _signed_revocation_body(
            revoked_ids=[],
            agents=[{'agent_id': 'a1', 'company_id': 1, 'grant_version': 1}],
            max_gv=1,
        )
        claims = _claims_write(company_id=1, grant_version=0)
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertTrue(agent_is_revoked('a1', 1, claims))

    def test_approval_state_none_on_404(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=404)
            self.assertIsNone(approval_state(payload, _claims_write()))

    def test_approval_state_error_on_400(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=400)
            self.assertEqual(approval_state(payload, _claims_write()), 'error')

    def test_approval_state_returns_expired_for_consumed_row(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {'status': 'expired'})
            self.assertEqual(approval_state(payload, _claims_write()), 'expired')

    def test_approval_state_posts_empty_json_body(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=404)
            approval_state(payload, _claims_write())
        self.assertEqual(mock_post.call_args.kwargs['json'], {})

    def test_consume_approval_false_on_error(self):
        with patch(
            'apps.storage.mcp_identity.requests.post',
            side_effect=requests.RequestException('down'),
        ):
            self.assertFalse(
                consume_approval(
                    'approval-1',
                    {
                        'agent_id': 'a1',
                        'company_id': 1,
                        'service': 'storage',
                        'action': 'write',
                        'arguments_hash': 'hash',
                    },
                    _claims_write(),
                )
            )

    def test_consume_approval_false_when_consumed_missing(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {})
            self.assertFalse(consume_approval('approval-1', payload, _claims_write()))

    def test_consume_approval_sends_approval_id_and_assertion(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {'consumed': True})
            self.assertTrue(consume_approval('approval-1', payload, _claims_write()))
        self.assertEqual(mock_post.call_args.kwargs['json'], {'approval_id': 'approval-1'})
        self.assertTrue(mock_post.call_args.kwargs['headers']['Authorization'].startswith('Bearer '))
