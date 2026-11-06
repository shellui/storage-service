"""Shellui MCP endpoint and OpenAPI tool exposure."""

from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock, patch

import jwt
from django.http import JsonResponse
from django.test import Client, TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator

from apps.storage.access import COMPANY_BUCKET_NAME
from apps.storage.tests.rs256_helpers import (
    MCP_SIGNING_TEST_SETTINGS,
    generate_test_rsa_jwks,
    signed_revocation_poll_response_body,
)
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
    grant_version: int | None = 0,
    omit_grant_version: bool = False,
    global_company_id: str | None = None,
    company_binding_version: int | None = None,
    global_agent_id: str | None = None,
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
    if not omit_grant_version and grant_version is not None:
        payload['grant_version'] = grant_version
    if global_company_id is not None:
        payload['global_company_id'] = global_company_id
    if company_binding_version is not None:
        payload['company_binding_version'] = company_binding_version
    if global_agent_id is not None:
        payload['global_agent_id'] = global_agent_id
    return jwt.encode(payload, secret, algorithm='HS256')


_TEST_ISSUER = 'https://identity.test'
_TEST_JWKS, _TEST_ID_PEM, _TEST_ID_KID = generate_test_rsa_jwks()


def _signed_revocation_for_tests(*, agents=None, revoked=None, max_gv=0):
    return signed_revocation_poll_response_body(
        private_pem=_TEST_ID_PEM,
        kid=_TEST_ID_KID,
        issuer=_TEST_ISSUER,
        revoked_agent_ids=revoked or [],
        agents=agents or [],
        cache_seconds=30,
        max_active_grant_version=max_gv,
    )


@override_settings(
    **MCP_SIGNING_TEST_SETTINGS,
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    IDENTITY_JWKS_DOCUMENT=_TEST_JWKS,
)
class McpEndpointTests(TestCase):
    def setUp(self):
        self.client = Client()
        import apps.storage.mcp_views as mcp_views

        mcp_views._server = None
        from django.core.cache import cache

        cache.delete('mcp:revoked_trusted_payload')
        cache.delete('mcp:revoked_list_trusted')
        cache.delete('mcp:revoked_verified_claims')

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
            'grant_version': 0,
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

    def _initialize(self, token: str):
        return self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            **_mcp_host_kwargs(),
        )

    @override_settings(STORAGE_PUBLIC_URL='http://localhost:8002')
    def test_public_url_sets_the_resource_on_an_internal_host(self):
        # The ai gateway calls an internal host; the token targets the public resource, so it
        # authenticates (any later 503 is the unmocked revocation poll, not the audience).
        self.assertNotEqual(self._initialize(_agent_token(aud='http://localhost:8002/mcp')).status_code, 401)

    @override_settings(STORAGE_PUBLIC_URL='http://localhost:8002')
    def test_public_url_refuses_a_token_for_the_request_host(self):
        self.assertEqual(self._initialize(_agent_token()).status_code, 401)

    def test_personal_token_may_omit_grant_version(self):
        token = _agent_token(omit_grant_version=True)
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: _signed_revocation_for_tests())
            response = self.client.post(
                '/mcp',
                data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
                **_mcp_host_kwargs(),
            )
        self.assertNotEqual(response.status_code, 401)

    def test_delegated_token_requires_grant_version(self):
        agent_id = str(uuid.uuid4())
        payload = {
            'sub': f'agent:{agent_id}',
            'agent_id': agent_id,
            'company_id': 10,
            'scope': 'storage',
            'mcp_access': 'read_only',
            'global_company_id': '18e20f88-286e-46ea-858e-1d75bca615ff',
            'company_binding_version': 0,
            'aud': _mcp_audience(),
            'iss': 'https://identity.test',
            'exp': 2**31 - 1,
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
        self.assertEqual(response.json()['error'], 'identity_invalid')

    def test_global_company_id_int_rejected(self):
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {_agent_token(global_company_id=10)}',
            **_mcp_host_kwargs(),
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['error'], 'identity_invalid')

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
        body = _signed_revocation_for_tests(
            revoked=[agent_id],
            agents=[{'agent_id': agent_id, 'company_id': 10, 'grant_version': 0}],
        )
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: body)
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
        claims = jwt.decode(token, options={'verify_signature': False})
        aid = str(claims['agent_id'])
        cid = int(claims['company_id'])
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
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: _signed_revocation_for_tests(
                    agents=[{'agent_id': aid, 'company_id': cid, 'grant_version': 0}],
                ),
            )
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
        token = _agent_token(
            mcp_access=ACCESS_ASK,
            grant_version=0,
            global_company_id='18e20f88-286e-46ea-858e-1d75bca615ff',
            company_binding_version=0,
        )
        claims = jwt.decode(token, options={'verify_signature': False})
        aid = str(claims['agent_id'])
        cid = int(claims['company_id'])
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
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: _signed_revocation_for_tests(
                    agents=[
                        {
                            'agent_id': aid,
                            'company_id': cid,
                            'global_company_id': '18e20f88-286e-46ea-858e-1d75bca615ff',
                            'company_binding_version': 0,
                            'grant_version': 0,
                        }
                    ],
                ),
            )
            with (
                patch('apps.storage.mcp_views._approval_state_for_mcp', return_value=None),
                patch(
                    'apps.storage.mcp_views.create_approval_request',
                    return_value={'id': 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'},
                ),
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

    def test_ask_approval_create_pending_approve_consume_reuse_revoke(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = tools_from_schema(schema)
        tool = next(t for t in tools if t['name'] == 'storage_v1_access_grant_create')
        agent_id = str(uuid.uuid4())
        company_id = 10
        appr_id = str(uuid.uuid4())
        req_id = str(uuid.uuid4())
        token = _agent_token(
            agent_id=agent_id,
            company_id=company_id,
            mcp_access=ACCESS_ASK,
            grant_version=0,
            global_company_id='18e20f88-286e-46ea-858e-1d75bca615ff',
            company_binding_version=0,
        )
        body = {
            'jsonrpc': '2.0',
            'id': 1,
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
        row = {
            'agent_id': agent_id,
            'company_id': company_id,
            'global_company_id': '18e20f88-286e-46ea-858e-1d75bca615ff',
            'company_binding_version': 0,
            'grant_version': 0,
        }
        state_calls = {'n': 0}

        def fake_state(payload, claims):
            state_calls['n'] += 1
            if state_calls['n'] == 1:
                return None
            if state_calls['n'] == 2:
                return 'pending'
            if state_calls['n'] == 3:
                payload['approval_id'] = appr_id
                return 'approved'
            if state_calls['n'] == 4:
                payload['approval_id'] = appr_id
                return 'expired'
            return 'error'

        def fake_consume(approval_id, payload, claims):
            return str(approval_id) == appr_id and state_calls['n'] == 3

        create_calls = {'n': 0}

        def fake_create(payload, claims):
            create_calls['n'] += 1
            return {'id': req_id}

        op_calls = {'n': 0}

        def fake_resolve(path, urlconf):
            op_calls['n'] += 1
            return MagicMock(func=lambda request, *a, **kw: JsonResponse({'ok': True}, status=200), args=(), kwargs={})

        rev_calls = {'n': 0}

        def fake_revoked(aid, cid, claims=None):
            rev_calls['n'] += 1
            return rev_calls['n'] >= 5

        with (
            patch('apps.storage.mcp_identity.requests.get') as mock_get,
            patch('apps.storage.mcp_views._approval_state_for_mcp', side_effect=fake_state),
            patch('apps.storage.mcp_views.create_approval_request', side_effect=fake_create),
            patch('apps.storage.mcp_views.consume_approval', side_effect=fake_consume),
            patch('apps.storage.mcp_views.agent_is_revoked', side_effect=fake_revoked),
            patch('django.urls.resolve', side_effect=fake_resolve),
        ):
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: _signed_revocation_for_tests(agents=[row]),
            )
            r1 = self.client.post(
                '/mcp',
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
                **_mcp_host_kwargs(),
            )
            r2 = self.client.post(
                '/mcp',
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
                **_mcp_host_kwargs(),
            )
            r3 = self.client.post(
                '/mcp',
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
                **_mcp_host_kwargs(),
            )
            r4 = self.client.post(
                '/mcp',
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
                **_mcp_host_kwargs(),
            )
            r5 = self.client.post(
                '/mcp',
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
                **_mcp_host_kwargs(),
            )

        self.assertEqual(create_calls['n'], 1)
        self.assertEqual(op_calls['n'], 1)
        m1 = r1.json()['result'].get('meta') or {}
        self.assertEqual(m1.get('status'), 'pending')
        self.assertEqual(m1.get('approval_id'), req_id)
        self.assertTrue(r2.json()['result'].get('isError'))
        self.assertIn('pending', r2.json()['result']['content'][0]['text'].lower())
        self.assertFalse(r3.json()['result'].get('isError'))
        self.assertTrue(r4.json()['result'].get('isError'))
        self.assertIn('used', r4.json()['result']['content'][0]['text'].lower())
        self.assertEqual(r5.json().get('error'), 'agent_revoked')
