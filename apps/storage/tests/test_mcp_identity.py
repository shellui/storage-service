"""Identity MCP integration: fail-closed revocation and approval calls."""

from __future__ import annotations

import uuid
from contextlib import contextmanager
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

from apps.authapi.mcp_authority import clear_delegated_authority_cache

from apps.storage.mcp_identity import (
    agent_is_revoked,
    approval_state,
    clear_mcp_openapi_schema_cache,
    consume_approval,
    create_approval_request,
    grant_versions_compatible,
    identity_revocation_unavailable,
)

_TEST_ISSUER = 'https://identity.test'
_JWKS, _PRIVATE_PEM, _KID = generate_test_rsa_jwks()
_SAMPLE_GLOBAL = '18e20f88-286e-46ea-858e-1d75bca615ff'
_SAMPLE_GLOBAL_AGENT = '28e20f88-286e-46ea-858e-1d75bca615ff'
_AGENT_A = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
_MCP_RESOURCE = 'http://127.0.0.1/mcp'


def _identity_authority_response(*, agent_id: str, company_id: int, global_company_id: str, grant_version: int, company_binding_version: int):
    return {
        'authorized': True,
        'active': True,
        'revoked': False,
        'paused': False,
        'agent_id': agent_id,
        'company_id': company_id,
        'global_company_id': global_company_id,
        'global_agent_id': _SAMPLE_GLOBAL_AGENT,
        'grant_version': grant_version,
        'company_binding_version': company_binding_version,
        'access_mode': 'ask',
        'read_level': 'safe',
        'allow_destructive': False,
        'services_allowed': ['storage'],
        'revoked_at': None,
    }


def _delegated_authority_ok_from_json(body: dict) -> dict:
    return _identity_authority_response(
        agent_id=str(body.get('agent_id') or ''),
        company_id=int(body['company_id']),
        global_company_id=str(body.get('global_company_id') or ''),
        grant_version=int(body['grant_version']),
        company_binding_version=int(body['company_binding_version']),
    )


def _post_mcp_shared_side_effect(*responses):
    """One side_effect for both Identity client modules: authority URL first, then sequential inner mocks."""

    seq = list(responses)
    idx = {'n': 0}

    def _fn(*args, **kwargs):
        url = str(args[0]) if args else ''
        if 'mcp-agent-delegated-authority' in url:
            body = kwargs.get('json') if isinstance(kwargs.get('json'), dict) else {}
            data = _delegated_authority_ok_from_json(body)
            return MagicMock(status_code=200, json=lambda d=data: d)
        r = seq[idx['n']]
        idx['n'] += 1
        return r() if callable(r) else r

    return _fn


@contextmanager
def _patch_identity_posts(*responses):
    """Patch ``requests.post`` in mcp_authority and mcp_identity with shared call sequencing."""
    side = _post_mcp_shared_side_effect(*responses)
    with (
        patch('apps.authapi.mcp_authority.requests.post', side_effect=side),
        patch('apps.storage.mcp_identity.requests.post', side_effect=side) as mock_identity_post,
    ):
        yield mock_identity_post


def _claims_write(
    *,
    agent_id: str = _AGENT_A,
    company_id: int = 1,
    grant_version: int = 0,
    global_company_id: str | None = _SAMPLE_GLOBAL,
    company_binding_version: int | None = 0,
    global_agent_id: str | None = _SAMPLE_GLOBAL_AGENT,
) -> dict:
    out = {
        'agent_id': agent_id,
        'mcp_access': 'ask',
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'scope': 'storage',
        'company_id': company_id,
        'grant_version': grant_version,
        'global_company_id': global_company_id,
        'company_binding_version': company_binding_version,
        'mcp_authority': 'delegated',
        'iss': _TEST_ISSUER,
        'aud': _MCP_RESOURCE,
    }
    if global_agent_id is not None:
        out['global_agent_id'] = global_agent_id
    return out


def _claims_personal(*, company_id: int = 1, grant_version: int = 0) -> dict:
    return {
        'mcp_access': 'ask',
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'scope': 'storage',
        'company_id': company_id,
        'grant_version': grant_version,
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
        clear_delegated_authority_cache()
        cache.delete('mcp:revoked_trusted_payload')
        cache.delete('mcp:revoked_list_trusted')
        cache.delete('mcp:revoked_verified_claims')
        clear_mcp_openapi_schema_cache()

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
            agents=[{'agent_id': _AGENT_A, 'company_id': 1, 'grant_version': 1}],
            max_gv=1,
        )
        claims = _claims_personal(company_id=1, grant_version=0)
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertTrue(agent_is_revoked(_AGENT_A, 1, claims))

    def test_grant_row_accepts_zero_as_valid_snapshot(self):
        body = _signed_revocation_body(
            revoked_ids=[],
            agents=[{'agent_id': _AGENT_A, 'company_id': 1, 'grant_version': 0}],
            max_gv=0,
        )
        claims = _claims_personal(company_id=1, grant_version=0)
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertFalse(agent_is_revoked(_AGENT_A, 1, claims))

    def test_global_snapshot_matches_on_uuid_not_regional_id(self):
        body = _signed_revocation_body(
            revoked_ids=[],
            agents=[
                {
                    'agent_id': _AGENT_A,
                    'company_id': 1,
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
            self.assertFalse(agent_is_revoked(_AGENT_A, 1, claims))

    def test_delegated_no_authoritative_row_revokes(self):
        body = _signed_revocation_body(revoked_ids=[], agents=[], max_gv=0)
        claims = _claims_write()
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertTrue(agent_is_revoked(_AGENT_A, 1, claims))

    def test_delegated_does_not_match_across_regional_company(self):
        body = _signed_revocation_body(
            revoked_ids=[],
            agents=[
                {
                    'agent_id': _AGENT_A,
                    'company_id': 2,
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
            self.assertTrue(agent_is_revoked(_AGENT_A, 1, claims))

    def test_delegated_ambiguous_rows_revokes(self):
        row = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'global_company_id': _SAMPLE_GLOBAL,
            'company_binding_version': 0,
            'grant_version': 0,
        }
        body = _signed_revocation_body(revoked_ids=[], agents=[row, dict(row)], max_gv=0)
        claims = _claims_write()
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertTrue(agent_is_revoked(_AGENT_A, 1, claims))

    def test_delegated_absent_snapshot_revokes(self):
        body = _signed_revocation_body(revoked_ids=[], agents=[], max_gv=0)
        claims = _claims_write()
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertTrue(agent_is_revoked(_AGENT_A, 1, claims))

    def test_personal_absent_snapshot_not_revoked(self):
        body = _signed_revocation_body(revoked_ids=[], agents=[], max_gv=0)
        claims = _claims_personal()
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertFalse(agent_is_revoked(_AGENT_A, 1, claims))

    def test_grant_versions_personal_ok_when_no_snapshot_row(self):
        body = _signed_revocation_body(revoked_ids=[], agents=[], max_gv=1)
        claims = _claims_personal(company_id=1, grant_version=0)
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertTrue(grant_versions_compatible(claims))

    def test_delegated_company_binding_mismatch_revokes(self):
        body = _signed_revocation_body(
            revoked_ids=[],
            agents=[
                {
                    'agent_id': _AGENT_A,
                    'company_id': 1,
                    'global_company_id': _SAMPLE_GLOBAL,
                    'company_binding_version': 1,
                    'grant_version': 0,
                }
            ],
            max_gv=0,
        )
        claims = _claims_write(company_binding_version=0)
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
            self.assertTrue(agent_is_revoked(_AGENT_A, 1, claims))

    def test_approval_state_none_on_404(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=404)) as mock_post:
            self.assertIsNone(approval_state(payload, _claims_write()))
        self.assertTrue(mock_post.call_count >= 1)

    def test_approval_state_error_on_400(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=400)):
            self.assertEqual(approval_state(payload, _claims_write()), 'error')

    def test_approval_state_error_on_unknown_status(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=200, json=lambda: {'status': 'weird'})):
            self.assertEqual(approval_state(payload, _claims_write()), 'error')

    def test_create_approval_request_maps_409_out_of_sync(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(
            lambda: MagicMock(
                status_code=409,
                json=lambda: {'error_code': 'out_of_sync', 'message': 'Use the AI gateway.'},
            )
        ):
            r = create_approval_request(payload, _claims_personal())
        self.assertEqual(r, {'_approval_error': True, 'error_code': 'out_of_sync', 'message': 'Use the AI gateway.'})

    def test_create_approval_request_delegated_preflight_out_of_sync_no_http(self):
        """Exchange-delegated agents must not POST {} to Identity; fail closed before HTTP."""
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with patch('apps.storage.mcp_identity.requests.post') as mock_post:
            r = create_approval_request(payload, _claims_write())
        mock_post.assert_not_called()
        self.assertIsInstance(r, dict)
        self.assertEqual(r.get('error_code'), 'out_of_sync')
        self.assertTrue(r.get('_approval_error'))

    def test_create_approval_request_sends_destructive_boolean(self):
        """Identity #138 rejects a destructive call log unless the approval row is destructive."""
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'storage_v1_object_destroy',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
            'is_destructive': True,
        }
        with _patch_identity_posts(
            lambda: MagicMock(status_code=200, json=lambda: {'id': str(uuid.uuid4()), 'status': 'pending'})
        ) as mock_post:
            created = create_approval_request(payload, _claims_personal())
        self.assertIsInstance(created, dict)
        self.assertNotIn('_approval_error', created)
        create_calls = [c for c in mock_post.call_args_list if 'mcp-approval-requests' in str(c)]
        self.assertTrue(create_calls)
        self.assertEqual(create_calls[-1].kwargs['json'], {'is_destructive': True})

    def test_create_approval_request_omits_destructive_flag_when_unset(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(
            lambda: MagicMock(status_code=200, json=lambda: {'id': str(uuid.uuid4()), 'status': 'pending'})
        ) as mock_post:
            create_approval_request(payload, _claims_personal())
        create_calls = [c for c in mock_post.call_args_list if 'mcp-approval-requests' in str(c)]
        self.assertEqual(create_calls[-1].kwargs['json'], {})

    def test_approval_state_returns_denied(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=200, json=lambda: {'status': 'denied'})):
            self.assertEqual(approval_state(payload, _claims_write()), 'denied')

    def test_approval_state_error_when_approved_missing_id(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=200, json=lambda: {'status': 'approved'})):
            self.assertEqual(approval_state(payload, _claims_write()), 'error')

    def test_approval_state_returns_expired_for_consumed_row(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=200, json=lambda: {'status': 'expired'})):
            self.assertEqual(approval_state(payload, _claims_write()), 'expired')

    def test_approval_state_posts_empty_json_body(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=404)) as mock_post:
            approval_state(payload, _claims_write())
        last = [c for c in mock_post.call_args_list if 'mcp-approval-state' in str(c)]
        self.assertTrue(last)
        self.assertEqual(last[-1].kwargs['json'], {})

    def test_consume_approval_false_on_error(self):
        def _fail_consume(*_a, **_k):
            raise requests.RequestException('down')

        with _patch_identity_posts(_fail_consume):
            ok, meta = consume_approval(
                str(uuid.uuid4()),
                {
                    'agent_id': _AGENT_A,
                    'company_id': 1,
                    'service': 'storage',
                    'action': 'write',
                    'arguments_hash': 'hash',
                    'mcp_expected_resource': _MCP_RESOURCE,
                },
                _claims_write(),
            )
        self.assertFalse(ok)
        self.assertEqual(meta.get('error_code'), 'upstream_error')

    def test_consume_approval_false_when_consumed_missing(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=200, json=lambda: {})):
            ok, _meta = consume_approval(str(uuid.uuid4()), payload, _claims_write())
        self.assertFalse(ok)

    def test_consume_approval_false_when_http200_but_consumed_false(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=200, json=lambda: {'consumed': False})):
            ok, _meta = consume_approval(str(uuid.uuid4()), payload, _claims_write())
        self.assertFalse(ok)

    def test_consume_approval_rejects_non_uuid(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        ok, _meta = consume_approval('not-a-uuid', payload, _claims_write())
        self.assertFalse(ok)

    def test_consume_approval_sends_approval_id_and_assertion(self):
        aid = str(uuid.uuid4())
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(lambda: MagicMock(status_code=200, json=lambda: {'consumed': True})) as mock_post:
            ok, meta = consume_approval(aid, payload, _claims_write())
        self.assertTrue(ok)
        self.assertEqual(meta.get('approval_id'), aid)
        consume_calls = [c for c in mock_post.call_args_list if 'mcp-approval-consume' in str(c)]
        self.assertTrue(consume_calls)
        self.assertEqual(consume_calls[-1].kwargs['json'], {'approval_id': aid})
        self.assertTrue(consume_calls[-1].kwargs['headers']['Authorization'].startswith('Bearer '))

    def test_consume_approval_identity136_already_consumed_http200_message(self):
        payload = {
            'agent_id': _AGENT_A,
            'company_id': 1,
            'service': 'storage',
            'action': 'write',
            'arguments_hash': 'hash',
            'mcp_expected_resource': _MCP_RESOURCE,
        }
        with _patch_identity_posts(
            lambda: MagicMock(
                status_code=200,
                json=lambda: {'consumed': False, 'detail': 'Approval already consumed.'},
            )
        ):
            ok, meta = consume_approval(str(uuid.uuid4()), payload, _claims_write())
        self.assertFalse(ok)
        self.assertEqual(meta.get('outcome'), 'denied')
        self.assertEqual(meta.get('status'), 409)
        self.assertEqual(meta.get('error_code'), 'expired')
