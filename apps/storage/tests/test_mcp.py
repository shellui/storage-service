"""Shellui MCP endpoint and OpenAPI tool exposure."""

from __future__ import annotations

import json
import uuid
from unittest.mock import patch

import jwt
from django.test import Client, TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator

from apps.storage.access import COMPANY_BUCKET_NAME
from apps.authapi.mcp_openapi import MCP_EXCLUDED_PATH_PREFIXES, validate_mcp_schema
from shellui_django.mcp.openapi_tools import tools_from_schema
from shellui_django.mcp.write_gate import ACCESS_ASK, ACCESS_READ_ONLY, decide_write


def _mcp_audience() -> str:
    # RFC 8707 allows http only on loopback; Django's default testserver host is rejected.
    return 'http://127.0.0.1/mcp'


def _mcp_host_kwargs() -> dict[str, str]:
    return {'HTTP_HOST': '127.0.0.1'}


def _agent_token(
    *,
    agent_id: str | None = None,
    company_id: int = 10,
    mcp_access: str = 'read_only',
    scope: str = 'storage',
    aud: str | None = None,
    secret: str = 'test-secret',
) -> str:
    agent_id = agent_id or str(uuid.uuid4())
    payload = {
        'sub': f'agent:{agent_id}',
        'agent_id': agent_id,
        'company_id': company_id,
        'scope': scope,
        'mcp_access': mcp_access,
        'mcp_read': 'safe',
        'mcp_destructive': False,
        'aud': aud if aud is not None else _mcp_audience(),
        'iss': 'https://identity.test',
        'exp': 2**31 - 1,
    }
    return jwt.encode(payload, secret, algorithm='HS256')


@override_settings(
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
)
class McpEndpointTests(TestCase):
    def setUp(self):
        self.client = Client()
        import apps.storage.mcp_views as mcp_views

        mcp_views._server = None

    def test_untagged_internal_path_not_in_openapi(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        for prefix in MCP_EXCLUDED_PATH_PREFIXES:
            for path in schema.get('paths', {}):
                self.assertFalse(path.startswith(prefix), path)
        validate_mcp_schema(schema)

    def test_mcp_requires_agent_token(self):
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
            content_type='application/json',
            **_mcp_host_kwargs(),
        )
        self.assertEqual(response.status_code, 401)

    def test_staff_claims_on_agent_token_rejected(self):
        agent_id = str(uuid.uuid4())
        payload = {
            'sub': f'agent:{agent_id}',
            'agent_id': agent_id,
            'company_id': 10,
            'scope': 'storage',
            'mcp_access': 'read_only',
            'aud': _mcp_audience(),
            'iss': 'https://identity.test',
            'exp': 2**31 - 1,
            'user_metadata': {'is_staff': True},
        }
        token = jwt.encode(payload, 'test-secret', algorithm='HS256')
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            **_mcp_host_kwargs(),
        )
        self.assertEqual(response.status_code, 401)

    def test_legacy_shared_audience_rejected(self):
        token = _agent_token(aud='shellui-mcp')
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            **_mcp_host_kwargs(),
        )
        self.assertEqual(response.status_code, 401)

    def test_revocation_list_failure_refuses_agent(self):
        from django.core.cache import cache

        cache.delete('mcp:revoked_trusted_payload')
        cache.delete('mcp:revoked_list_trusted')
        token = _agent_token()
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value.status_code = 404
            mock_get.return_value.json.side_effect = ValueError('no body')
            response = self.client.post(
                '/mcp',
                data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
                **_mcp_host_kwargs(),
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()['error'], 'identity_unavailable')
        auth_header = mock_get.call_args.kwargs.get('headers', {}).get('Authorization', '')
        self.assertTrue(auth_header.startswith('Bearer '))

    def test_revoked_agent_refused(self):
        agent_id = str(uuid.uuid4())
        token = _agent_token(agent_id=agent_id)
        with patch('apps.storage.mcp_views.identity_revocation_unavailable', return_value=False):
            with patch('apps.storage.mcp_views.agent_is_revoked', return_value=True):
                response = self.client.post(
                    '/mcp',
                    data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
                    content_type='application/json',
                    HTTP_AUTHORIZATION=f'Bearer {token}',
                    **_mcp_host_kwargs(),
                )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['error'], 'agent_revoked')

    def test_read_only_blocks_write_tool(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = tools_from_schema(schema)
        write_tool = next(t for t in tools if t['name'] == 'storage_v1_object_destroy')
        token = _agent_token(mcp_access=ACCESS_READ_ONLY)
        body = {
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'tools/call',
            'params': {
                'name': write_tool['name'],
                'arguments': {
                    'path': write_tool['_meta']['path'],
                    'method': write_tool['_meta']['method'],
                    'path_params': {
                        'bucket_id': COMPANY_BUCKET_NAME,
                        'object_path': 'nowhere.txt',
                    },
                    'query': {},
                    'body': {},
                },
            },
        }
        with patch('apps.storage.mcp_views.identity_revocation_unavailable', return_value=False):
            with patch('apps.storage.mcp_views.agent_is_revoked', return_value=False):
                response = self.client.post(
                    '/mcp',
                    data=json.dumps(body),
                    content_type='application/json',
                    HTTP_AUTHORIZATION=f'Bearer {token}',
                    **_mcp_host_kwargs(),
                )
        payload = response.json()
        self.assertIn('result', payload)
        self.assertTrue(payload['result'].get('isError'))

    def test_ask_mode_requires_approval_before_write(self):
        decision = decide_write(
            method='POST',
            access_mode=ACCESS_ASK,
            destructive=False,
            allow_destructive_without_asking=False,
        )
        self.assertTrue(decision.needs_approval)
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = tools_from_schema(schema)
        tool = next(t for t in tools if t['name'] == 'storage_v1_access_grant_create')
        token = _agent_token(mcp_access=ACCESS_ASK)
        body = {
            'jsonrpc': '2.0',
            'id': 3,
            'method': 'tools/call',
            'params': {
                'name': tool['name'],
                'arguments': {
                    'path': tool['_meta']['path'],
                    'method': tool['_meta']['method'],
                    'query': {},
                    'body': {},
                },
            },
        }
        with patch('apps.storage.mcp_views.identity_revocation_unavailable', return_value=False):
            with patch('apps.storage.mcp_views.agent_is_revoked', return_value=False):
                with patch(
                    'apps.storage.mcp_views.create_approval_request',
                    return_value={'id': 'approval-1'},
                ):
                    response = self.client.post(
                        '/mcp',
                        data=json.dumps(body),
                        content_type='application/json',
                        HTTP_AUTHORIZATION=f'Bearer {token}',
                        **_mcp_host_kwargs(),
                    )
        payload = response.json()['result']
        self.assertTrue(payload.get('isError'))
        meta = payload.get('meta') or {}
        self.assertTrue(meta.get('status') == 'pending' or meta.get('approval_id'))

    def test_wrong_service_scope_forbidden(self):
        token = _agent_token(scope='email')
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            **_mcp_host_kwargs(),
        )
        self.assertEqual(response.status_code, 401)

    def test_share_token_never_returned_from_tool_redaction(self):
        from shellui_django.mcp.masking import redact_mapping

        redacted = redact_mapping({'token': 'secret-link-token', 'path': 'a/b'}, read_sensitive=False)
        self.assertEqual(redacted['token'], '[redacted]')
