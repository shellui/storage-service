"""Contract shape for MCP call logs forwarded to identity-service (PR #135 / d7fe351 ingest)."""

from __future__ import annotations

from django.test import SimpleTestCase, override_settings

from apps.storage.mcp_identity import _sanitize_call_log_entry

_AGENT = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
_GLOBAL = '18e20f88-286e-46ea-858e-1d75bca615ff'
_GLOBAL_AGENT = '28e20f88-286e-46ea-858e-1d75bca615ff'
_APPROVAL = 'da0eebc9-9c0b-4ef8-bb6d-6bb9bd380a11'

# Identity McpInternalCallLogView body (plus optional client_ip); storage does not send IP.
_IDENTITY_CALL_LOG_KEYS = frozenset(
    {
        'agent_id',
        'company_id',
        'service',
        'tool',
        'method',
        'path',
        'access_kind',
        'outcome',
        'status',
        'duration_ms',
        'result',
        'error_code',
        'grant_version',
        'company_binding_version',
        'global_company_id',
        'global_agent_id',
        'approval_id',
    }
)


@override_settings(STORAGE_PUBLIC_URL='')
class McpCallLogContractTests(SimpleTestCase):
    def test_sanitize_outputs_post_mcp_for_identity_ingest(self):
        """Wire JSON-RPC envelope: ``method`` ``POST``, ``path`` ``/mcp``; inner REST validated via registry only."""
        raw = {
            'agent_id': _AGENT,
            'company_id': 1,
            'service': 'storage',
            'tool': 'api_v1_actions_deliveries_list',
            'http_method': 'GET',
            'resource_path': '/api/v1/actions/deliveries',
            'access_kind': 'destructive',
            'outcome': 'allowed',
            'status': 200,
            'duration_ms': 5,
            'grant_version': 0,
            'company_binding_version': 0,
            'global_company_id': _GLOBAL,
            'global_agent_id': _GLOBAL_AGENT,
            'approval_id': _APPROVAL,
            'error_code': 'upstream_error',
        }
        safe = _sanitize_call_log_entry(raw)
        self.assertTrue(safe)
        self.assertEqual(safe.get('method'), 'POST')
        self.assertEqual(safe.get('path'), '/mcp')
        self.assertEqual(safe.get('access_kind'), 'destructive')
        self.assertNotIn('http_method', safe)
        self.assertNotIn('resource_path', safe)
        forbidden = {'arguments', 'arguments_redacted', 'operation_title', 'resource_label', 'email', 'body'}
        self.assertFalse(forbidden & set(safe.keys()))
        extra = set(safe.keys()) - _IDENTITY_CALL_LOG_KEYS
        self.assertFalse(extra, f'unexpected keys: {extra}')

    @override_settings(STORAGE_PUBLIC_URL='https://storage.example/prefix')
    def test_sanitize_path_uses_public_url_prefix(self):
        raw = {
            'agent_id': _AGENT,
            'company_id': 1,
            'service': 'storage',
            'tool': 'api_v1_actions_deliveries_list',
            'http_method': 'GET',
            'resource_path': '/api/v1/actions/deliveries',
            'access_kind': 'read',
            'outcome': 'allowed',
            'status': 200,
            'duration_ms': 5,
            'grant_version': 0,
            'company_binding_version': 0,
            'global_company_id': _GLOBAL,
            'global_agent_id': _GLOBAL_AGENT,
        }
        safe = _sanitize_call_log_entry(raw)
        self.assertEqual(safe.get('path'), '/prefix/mcp')

    def test_sanitize_strips_query_fragment_from_registry_path_only(self):
        raw = {
            'agent_id': _AGENT,
            'company_id': 1,
            'service': 'storage',
            'tool': 'api_v1_actions_deliveries_list',
            'http_method': 'GET',
            'resource_path': '/api/v1/actions/deliveries?q=1#frag',
            'access_kind': 'read',
            'outcome': 'allowed',
            'status': 200,
            'duration_ms': 5,
            'grant_version': 0,
            'company_binding_version': 0,
            'global_company_id': _GLOBAL,
            'global_agent_id': _GLOBAL_AGENT,
        }
        safe = _sanitize_call_log_entry(raw)
        self.assertEqual(safe.get('path'), '/mcp')

    def test_sanitize_requires_grant_version_int(self):
        raw = {
            'agent_id': _AGENT,
            'company_id': 1,
            'service': 'storage',
            'tool': 'api_v1_actions_deliveries_list',
            'http_method': 'GET',
            'resource_path': '/api/v1/actions/deliveries',
            'access_kind': 'read',
            'outcome': 'allowed',
            'status': 200,
            'duration_ms': 5,
            'global_company_id': _GLOBAL,
            'company_binding_version': 0,
            'global_agent_id': _GLOBAL_AGENT,
        }
        self.assertFalse(_sanitize_call_log_entry(raw))

    def test_sanitize_maps_pending_approval_to_waiting(self):
        raw = {
            'agent_id': _AGENT,
            'company_id': 1,
            'service': 'storage',
            'tool': 'api_v1_actions_deliveries_list',
            'http_method': 'GET',
            'resource_path': '/api/v1/actions/deliveries',
            'access_kind': 'write',
            'outcome': 'pending_approval',
            'status': 202,
            'duration_ms': 5,
            'grant_version': 0,
            'company_binding_version': 0,
            'global_company_id': _GLOBAL,
            'global_agent_id': _GLOBAL_AGENT,
            'approval_id': _APPROVAL,
        }
        safe = _sanitize_call_log_entry(raw)
        self.assertEqual(safe.get('outcome'), 'waiting_approval')

    def test_sanitize_personal_omits_global_binding_fields(self):
        raw = {
            'agent_id': _AGENT,
            'company_id': 1,
            'service': 'storage',
            'tool': 'api_v1_actions_deliveries_list',
            'http_method': 'GET',
            'resource_path': '/api/v1/actions/deliveries',
            'access_kind': 'read',
            'outcome': 'allowed',
            'status': 200,
            'duration_ms': 5,
            'grant_version': 0,
        }
        safe = _sanitize_call_log_entry(raw)
        self.assertTrue(safe)
        self.assertNotIn('global_company_id', safe)
        self.assertNotIn('company_binding_version', safe)
        self.assertNotIn('global_agent_id', safe)

    def test_sanitize_delegated_requires_company_binding_version(self):
        raw = {
            'agent_id': _AGENT,
            'company_id': 1,
            'service': 'storage',
            'tool': 'api_v1_actions_deliveries_list',
            'http_method': 'GET',
            'resource_path': '/api/v1/actions/deliveries',
            'access_kind': 'read',
            'outcome': 'allowed',
            'status': 200,
            'duration_ms': 5,
            'grant_version': 0,
            'global_company_id': _GLOBAL,
            'global_agent_id': _GLOBAL_AGENT,
        }
        self.assertFalse(_sanitize_call_log_entry(raw))

    def test_sanitize_destructive_success_requires_approval_id(self):
        raw = {
            'agent_id': _AGENT,
            'company_id': 1,
            'service': 'storage',
            'tool': 'api_v1_actions_deliveries_list',
            'http_method': 'GET',
            'resource_path': '/api/v1/actions/deliveries',
            'access_kind': 'destructive',
            'outcome': 'allowed',
            'status': 200,
            'duration_ms': 5,
            'grant_version': 0,
            'company_binding_version': 0,
            'global_company_id': _GLOBAL,
            'global_agent_id': _GLOBAL_AGENT,
        }
        self.assertFalse(_sanitize_call_log_entry(raw))
