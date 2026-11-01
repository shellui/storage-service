"""Identity MCP integration: fail-closed revocation and approval calls."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings

from apps.storage.mcp_identity import agent_is_revoked, approval_state, consume_approval


@override_settings(
    IDENTITY_SERVICE_URL='https://identity.test',
    IDENTITY_ISSUER='https://identity.test',
)
class McpIdentityFailClosedTests(SimpleTestCase):
    def setUp(self):
        cache.delete('mcp:revoked_agent_ids')
        cache.delete('mcp:revoked_list_trusted')

    def test_agent_revoked_when_identity_returns_404(self):
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=404)
            self.assertTrue(agent_is_revoked('agent-1'))

    def test_agent_revoked_when_identity_unreachable(self):
        with patch(
            'apps.storage.mcp_identity.requests.get',
            side_effect=requests.RequestException('network'),
        ):
            self.assertTrue(agent_is_revoked('agent-1'))

    def test_revocation_poll_sends_signed_assertion(self):
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {'revoked_agent_ids': []},
            )
            self.assertFalse(agent_is_revoked('agent-1'))
        auth = mock_get.call_args.kwargs['headers']['Authorization']
        self.assertRegex(auth, r'^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')

    def test_approval_state_pending_on_404(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=404)
            self.assertEqual(approval_state(payload), 'pending')

    def test_consume_approval_false_on_error(self):
        with patch(
            'apps.storage.mcp_identity.requests.post',
            side_effect=requests.RequestException('down'),
        ):
            self.assertFalse(consume_approval('approval-1'))
