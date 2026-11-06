"""Identity MCP integration: fail-closed revocation and approval calls."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import jwt
import requests
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings

from apps.storage.tests.rs256_helpers import (
    MCP_SIGNING_TEST_SETTINGS,
    generate_test_rsa_jwks,
    signed_revocation_poll_response_body,
)

from apps.storage.mcp_identity import (
    agent_is_revoked,
    approval_state,
    consume_approval,
    identity_revocation_unavailable,
)

_TEST_ISSUER = 'https://identity.test'
_JWKS, _PRIVATE_PEM, _KID = generate_test_rsa_jwks()
_SAMPLE_GLOBAL = '18e20f88-286e-46ea-858e-1d75bca615ff'


def _claims_write(
    *,
    company_id: int = 1,
    grant_version: int = 0,
    global_company_id: str | None = _SAMPLE_GLOBAL,
    company_binding_version: int | None = 0,
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
    return signed_revocation_poll_response_body(
        private_pem=_PRIVATE_PEM,
        kid=_KID,
        issuer=_TEST_ISSUER,
        revoked_agent_ids=revoked_ids,
        agents=agents,
        cache_seconds=30,
        max_active_grant_version=max_gv,
    )


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
        cache.delete('mcp:revoked_verified_claims')

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

    def test_grant_row_accepts_zero_as_valid_snapshot(self):
        body = _signed_revocation_body(
            revoked_ids=[],
            agents=[{'agent_id': 'a1', 'company_id': 1, 'grant_version': 0}],
            max_gv=0,
        )
        claims = _claims_write(company_id=1, grant_version=0)
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertFalse(agent_is_revoked('a1', 1, claims))

    def test_global_snapshot_matches_on_uuid_not_regional_id(self):
        body = _signed_revocation_body(
            revoked_ids=[],
            agents=[
                {
                    'agent_id': 'a1',
                    'global_company_id': _SAMPLE_GLOBAL,
                    'company_binding_version': 0,
                    'grant_version': 0,
                }
            ],
            max_gv=0,
        )
        claims = _claims_write(company_id=1, grant_version=0, global_company_id=_SAMPLE_GLOBAL)
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertFalse(agent_is_revoked('a1', 1, claims))

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

    def test_approval_state_error_on_unknown_status(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {'status': 'weird'})
            self.assertEqual(approval_state(payload, _claims_write()), 'error')

    def test_approval_state_error_when_approved_missing_id(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {'status': 'approved'})
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
                    str(uuid.uuid4()),
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
            self.assertFalse(
                consume_approval(str(uuid.uuid4()), payload, _claims_write()),
            )

    def test_consume_approval_false_when_http200_but_consumed_false(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {'consumed': False})
            self.assertFalse(
                consume_approval(str(uuid.uuid4()), payload, _claims_write()),
            )

    def test_consume_approval_rejects_non_uuid(self):
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        self.assertFalse(consume_approval('not-a-uuid', payload, _claims_write()))

    def test_consume_approval_sends_approval_id_and_assertion(self):
        aid = str(uuid.uuid4())
        payload = {
            'agent_id': 'a1',
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200, json=lambda: {'consumed': True})
            self.assertTrue(consume_approval(aid, payload, _claims_write()))
        self.assertEqual(mock_post.call_args.kwargs['json'], {'approval_id': aid})
        self.assertTrue(mock_post.call_args.kwargs['headers']['Authorization'].startswith('Bearer '))

    def test_forward_call_log_drops_unapproved_keys(self):
        from apps.storage.mcp_identity import forward_call_log

        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            forward_call_log(
                {
                    'tool': 'x',
                    'evil': 'payload',
                    'arguments': {'secret': 'no'},
                    'agent_id': 'a1',
                    'company_id': 1,
                    'grant_version': 0,
                    'global_company_id': _SAMPLE_GLOBAL,
                    'company_binding_version': 0,
                    'service': 'storage',
                    'operation_title': 't',
                    'method': 'GET',
                    'path': '/p',
                    'access_kind': 'read',
                    'destructive': False,
                    'read_level': 'safe',
                    'outcome': 'allowed',
                    'status': 200,
                    'duration_ms': 1,
                    'result_shape': 'dict',
                }
            )
        body = mock_post.call_args.kwargs['json']
        self.assertNotIn('evil', body)
        self.assertNotIn('arguments', body)
