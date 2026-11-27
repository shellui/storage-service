"""Shellui MCP endpoint and OpenAPI tool exposure."""

from __future__ import annotations

import json
import inspect
import uuid
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import jwt
from django.http import JsonResponse
from django.test import Client, TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator

from apps.storage.access import COMPANY_BUCKET_NAME
from apps.storage.models import StorageAccessGrant
from apps.storage.tests.rs256_helpers import (
    MCP_SIGNING_TEST_SETTINGS,
    generate_test_rsa_jwks,
    signed_revocation_poll_response_body,
)
from apps.authapi.mcp_openapi import MCP_EXCLUDED_PATH_PREFIXES, validate_mcp_schema
from apps.storage.mcp_tool_names import apply_published_tool_names
from shellui_django.mcp.openapi_tools import tools_from_schema
from shellui_django.mcp.write_gate import ACCESS_ASK, ACCESS_FULL, ACCESS_READ_ONLY, decide_write

_AUTH_POST = 'apps.authapi.mcp_authority.requests.post'


def _mcp_audience() -> str:
    # RFC 8707 allows http only on loopback; Django's default testserver host is rejected.
    return 'http://127.0.0.1/mcp'


def _mcp_host_kwargs() -> dict[str, str]:
    return {'HTTP_HOST': '127.0.0.1'}


ASK_WRITE_OPERATION = 'storage_v1_quota_company_update'


def _grant_create_call_arguments(tool: dict) -> dict:
    """Arguments for a write tool that is not agent-refused (company quota update).

    The name is kept from when this called the grant tool. Agents can no longer create grants.
    """
    return {
        'path': tool['_meta']['path'],
        'method': tool['_meta']['method'],
        'query': {},
        'path_params': {'company_id': 10},
        'body': {'max_bytes': 1048576},
    }


_DELEGATED_OK_GAI = '28e20f88-286e-46ea-858e-1d75bca615ff'


def _agent_token(
    *,
    agent_id: str | None = None,
    company_id: int = 10,
    mcp_access: str = 'read_only',
    mcp_read: str = 'safe',
    mcp_destructive: bool = False,
    scope: str = 'storage',
    aud: str | None = None,
    grant_version: int | None = 0,
    omit_grant_version: bool = False,
    global_company_id: str | None = None,
    company_binding_version: int | None = None,
    global_agent_id: str | None = None,
    mcp_authority: str | None = None,
    secret: str = 'test-secret',
    owner_user_id: int | None = None,
) -> str:
    agent_id = agent_id or str(uuid.uuid4())
    payload = {
        'sub': f'agent:{agent_id}',
        'token_type': 'access',
        'agent_id': agent_id,
        'company_id': company_id,
        'scope': scope,
        'mcp_access': mcp_access,
        'mcp_read': mcp_read,
        'mcp_destructive': mcp_destructive,
        'aud': aud if aud is not None else _mcp_audience(),
        'iss': 'https://identity.test',
        'exp': 2**31 - 1,
    }
    if owner_user_id is not None:
        payload['owner_user_id'] = owner_user_id
    if not omit_grant_version and grant_version is not None:
        payload['grant_version'] = grant_version
    if global_company_id is not None:
        payload['global_company_id'] = global_company_id
    if company_binding_version is not None:
        payload['company_binding_version'] = company_binding_version
    if global_agent_id is not None:
        payload['global_agent_id'] = global_agent_id
    elif global_company_id is not None:
        payload['global_agent_id'] = _DELEGATED_OK_GAI
    if global_company_id is not None or global_agent_id is not None:
        payload['mcp_authority'] = mcp_authority or 'delegated'
    elif mcp_authority is not None:
        payload['mcp_authority'] = mcp_authority
    return jwt.encode(payload, secret, algorithm='HS256')


def _delegated_identity_authority_ok(*, body: dict, claims: dict) -> dict:
    """Minimal Identity 200 for ``mcp-agent-delegated-authority`` (identity-service d7fe351: 15 keys)."""
    scope_parts = sorted(p for p in str(claims.get('scope') or '').split() if p)
    if not scope_parts:
        scope_parts = ['storage']
    return {
        'authorized': True,
        'active': True,
        'revoked': False,
        'paused': False,
        'agent_id': str(body.get('agent_id') or ''),
        'company_id': int(body['company_id']),
        'global_company_id': str(body.get('global_company_id') or ''),
        'global_agent_id': _DELEGATED_OK_GAI,
        'grant_version': int(body['grant_version']),
        'company_binding_version': int(body['company_binding_version']),
        'access_mode': str(claims.get('mcp_access') or 'read_only').strip() or 'read_only',
        'read_level': str(claims.get('mcp_read') or 'safe').strip() or 'safe',
        'allow_destructive': bool(claims.get('mcp_destructive')),
        'services_allowed': sorted(set(scope_parts)),
        'revoked_at': None,
    }


def _agent_claims_from_delegated_authority_stack() -> dict:
    """``requests.post`` for delegated authority sends a service assertion, not the agent JWT."""
    for fr in inspect.stack():
        if fr.function == 'delegated_regional_authority_live_ok':
            c = fr.frame.f_locals.get('claims')
            if isinstance(c, dict):
                return c
    return {}


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
        import apps.authapi.mcp_authority as mcp_authority

        mcp_authority.clear_delegated_authority_cache()
        import apps.storage.mcp_views as mcp_views

        mcp_views._server = None
        from django.core.cache import cache

        cache.delete('mcp:revoked_trusted_payload')
        cache.delete('mcp:revoked_list_trusted')
        cache.delete('mcp:revoked_verified_claims')
        self._p_auth_post = patch(_AUTH_POST)
        mock_post = self._p_auth_post.start()
        self.addCleanup(self._p_auth_post.stop)
        def _post_side_effect(*args, **kwargs):
            url = str(args[0]) if args else ''
            if 'mcp-agent-delegated-authority' in url:
                body = kwargs.get('json')
                if isinstance(body, dict):
                    claims = _agent_claims_from_delegated_authority_stack()
                    return MagicMock(
                        status_code=200,
                        json=lambda b=body, c=claims: _delegated_identity_authority_ok(body=b, claims=c),
                    )
            return MagicMock(status_code=200, json=lambda: {'authorized': True})

        mock_post.side_effect = _post_side_effect

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
            'token_type': 'access',
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

    def test_personal_token_requires_grant_version_int(self):
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
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['error'], 'identity_invalid')

    def test_delegated_token_requires_grant_version(self):
        agent_id = str(uuid.uuid4())
        payload = {
            'sub': f'agent:{agent_id}',
            'token_type': 'access',
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
        tools = apply_published_tool_names(tools_from_schema(schema))
        write_tool = next(t for t in tools if t['_meta']['operationId'] == 'storage_v1_object_destroy')
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
        tools = apply_published_tool_names(tools_from_schema(schema))
        tool = next(t for t in tools if t['_meta']['operationId'] == ASK_WRITE_OPERATION)
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
                'arguments': _grant_create_call_arguments(tool),
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

    def _rpc_as_agent(self, method, params=None, *, creator_status=None, approved=False, **token_kwargs):
        """POST to /mcp as an agent. ``creator_status`` is what Identity's snapshot says."""
        token = _agent_token(**token_kwargs)
        claims = jwt.decode(token, options={'verify_signature': False})
        row = {
            'agent_id': str(claims['agent_id']),
            'company_id': int(claims['company_id']),
            'grant_version': 0,
        }
        if creator_status is not None:
            row['creator_status'] = creator_status
        body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}
        from django.core.cache import cache

        cache.delete('mcp:revoked_trusted_payload')
        cache.delete('mcp:revoked_list_trusted')
        cache.delete('mcp:revoked_verified_claims')
        with ExitStack() as stack:
            mock_get = stack.enter_context(patch('apps.storage.mcp_identity.requests.get'))
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: _signed_revocation_for_tests(agents=[row]),
            )
            if approved:

                def _state(payload, _claims):
                    payload['approval_id'] = str(uuid.uuid4())
                    return 'approved'

                stack.enter_context(patch('apps.storage.mcp_views._approval_state_for_mcp', side_effect=_state))
                stack.enter_context(
                    patch('apps.storage.mcp_views.consume_approval', return_value=(True, {'approval_id': 'x'}))
                )
            return self.client.post(
                '/mcp',
                data=json.dumps(body),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token}',
                **_mcp_host_kwargs(),
            )

    def test_sharing_tools_are_not_listed_for_agents(self):
        from apps.storage.mcp_server_strict import AGENT_REFUSED_OPERATIONS

        response = self._rpc_as_agent('tools/list', mcp_access=ACCESS_FULL)
        self.assertEqual(response.status_code, 200, response.content)
        listed = {
            str((tool.get('_meta') or {}).get('operationId') or tool['name'])
            for tool in response.json()['result']['tools']
        }
        self.assertTrue(listed)
        self.assertTrue(AGENT_REFUSED_OPERATIONS.isdisjoint(listed), AGENT_REFUSED_OPERATIONS & listed)
        # Narrowing and reading sharing stays available.
        self.assertIn('storage_v1_access_grant_list', listed)
        self.assertIn('storage_v1_share_link_destroy', listed)

    def test_agent_cannot_call_a_sharing_tool_even_with_full_access(self):
        from apps.storage.mcp_server_strict import AGENT_REFUSED_OPERATIONS

        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = apply_published_tool_names(tools_from_schema(schema))
        by_op = {t['_meta']['operationId']: t for t in tools}
        for op in sorted(AGENT_REFUSED_OPERATIONS):
            response = self._rpc_as_agent(
                'tools/call',
                {'name': by_op[op]['name'], 'arguments': {}},
                mcp_access=ACCESS_FULL,
            )
            self.assertEqual(response.status_code, 200, response.content)
            error = response.json().get('error') or {}
            self.assertEqual(error.get('message'), 'Unknown tool', op)
        self.assertFalse(StorageAccessGrant.objects.exists())

    def _admin_write(self, **kwargs):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = apply_published_tool_names(tools_from_schema(schema))
        tool = next(t for t in tools if t['_meta']['operationId'] == ASK_WRITE_OPERATION)
        params = {'name': tool['name'], 'arguments': _grant_create_call_arguments(tool)}
        from apps.storage.access import ensure_company_bucket

        ensure_company_bucket(company_id=10)
        return self._rpc_as_agent('tools/call', params, mcp_access=ACCESS_FULL, approved=True, **kwargs)

    def test_agent_admin_writes_follow_the_creators_live_role(self):
        member = self._admin_write(owner_user_id=7, creator_status='member').json()['result']
        self.assertTrue(member['isError'], member)
        self.assertIn('permission', json.dumps(member))
        # No status from Identity (an older Identity, or no row field) is a plain member.
        no_status = self._admin_write(owner_user_id=7).json()['result']
        self.assertTrue(no_status['isError'], no_status)
        self.assertIn('permission', json.dumps(no_status))
        ownerless = self._admin_write(creator_status='owner').json()['result']
        self.assertTrue(ownerless['isError'], ownerless)
        owner = self._admin_write(owner_user_id=7, creator_status='owner').json()['result']
        self.assertFalse(owner['isError'], owner)

    def test_a_demoted_owner_is_a_member_with_the_same_token(self):
        # One token, two polls of Identity's snapshot: the role follows the snapshot.
        token = _agent_token(mcp_access=ACCESS_FULL, owner_user_id=7)
        claims = jwt.decode(token, options={'verify_signature': False})
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = apply_published_tool_names(tools_from_schema(schema))
        tool = next(t for t in tools if t['_meta']['operationId'] == ASK_WRITE_OPERATION)
        body = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'tools/call',
            'params': {'name': tool['name'], 'arguments': _grant_create_call_arguments(tool)},
        }
        from apps.storage.access import ensure_company_bucket
        from django.core.cache import cache

        ensure_company_bucket(company_id=10)
        results = []
        for status in ('owner', 'member'):
            for key in ('mcp:revoked_trusted_payload', 'mcp:revoked_list_trusted', 'mcp:revoked_verified_claims'):
                cache.delete(key)
            row = {
                'agent_id': str(claims['agent_id']),
                'company_id': 10,
                'grant_version': 0,
                'creator_status': status,
            }
            with (
                patch('apps.storage.mcp_identity.requests.get') as mock_get,
                patch(
                    'apps.storage.mcp_views._approval_state_for_mcp',
                    side_effect=lambda payload, _c: payload.update(approval_id=str(uuid.uuid4())) or 'approved',
                ),
                patch('apps.storage.mcp_views.consume_approval', return_value=(True, {'approval_id': 'x'})),
            ):
                mock_get.return_value = MagicMock(
                    status_code=200, json=lambda r=row: _signed_revocation_for_tests(agents=[r])
                )
                response = self.client.post(
                    '/mcp',
                    data=json.dumps(body),
                    content_type='application/json',
                    HTTP_AUTHORIZATION=f'Bearer {token}',
                    **_mcp_host_kwargs(),
                )
            results.append(response.json()['result']['isError'])
        self.assertEqual(results, [False, True])

    def test_an_agent_whose_creator_is_gone_is_refused(self):
        for method in ('initialize', 'tools/list'):
            response = self._rpc_as_agent(method, mcp_access=ACCESS_FULL, owner_user_id=7, creator_status='gone')
            self.assertEqual(response.status_code, 401, response.content)
        for status in ('owner', 'member'):
            response = self._rpc_as_agent('initialize', mcp_access=ACCESS_FULL, owner_user_id=7, creator_status=status)
            self.assertEqual(response.status_code, 200, response.content)

    def test_an_agent_listed_as_revoked_by_identity_is_refused_when_its_creator_is_gone(self):
        # Identity also lists a gone creator's agent in revoked_agent_ids. A service that
        # reads the list and not the new field refuses it the same way.
        token = _agent_token(mcp_access=ACCESS_FULL, owner_user_id=7)
        claims = jwt.decode(token, options={'verify_signature': False})
        from django.core.cache import cache

        for key in ('mcp:revoked_trusted_payload', 'mcp:revoked_list_trusted', 'mcp:revoked_verified_claims'):
            cache.delete(key)
        row = {'agent_id': str(claims['agent_id']), 'company_id': 10, 'grant_version': 0, 'creator_status': 'gone'}
        with patch('apps.storage.mcp_identity.requests.get') as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: _signed_revocation_for_tests(agents=[row], revoked=[str(claims['agent_id'])]),
            )
            response = self._initialize(token)
        self.assertIn(response.status_code, (401, 403))

    def test_a_global_token_carrying_owner_claims_is_a_plain_member(self):
        # A delegated (global) token that carries owner-looking claims never acts as an owner,
        # even when the snapshot row says "owner".
        from apps.authapi.agent_tokens import principal_from_agent_claims

        token = _agent_token(
            mcp_access=ACCESS_FULL,
            owner_user_id=7,
            global_company_id='18e20f88-286e-46ea-858e-1d75bca615ff',
            company_binding_version=0,
        )
        claims = jwt.decode(token, options={'verify_signature': False})
        claims['owner_is_company_owner'] = True
        claims['is_company_owner'] = True
        claims['user_metadata'] = {'is_company_owner': True}
        for status in ('owner', 'member', None):
            principal = principal_from_agent_claims(claims, creator_status=status)
            self.assertFalse(principal.is_company_owner, status)
            self.assertFalse(principal.is_staff)

    def _tool_call(self, operation_id: str, *, path_params=None, body=None, query=None, **kwargs):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = apply_published_tool_names(tools_from_schema(schema))
        tool = next(t for t in tools if t['_meta']['operationId'] == operation_id)
        arguments = {
            'path': tool['_meta']['path'],
            'method': tool['_meta']['method'],
            'query': query or {},
            'path_params': path_params or {},
            'body': body or {},
        }
        from apps.storage.access import ensure_company_bucket

        ensure_company_bucket(company_id=10)
        params = {'name': tool['name'], 'arguments': arguments}
        with (
            patch('apps.storage.mcp_views._approval_state_for_mcp', return_value=None),
            patch(
                'apps.storage.mcp_views.create_approval_request',
                return_value={'id': 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'},
            ),
        ):
            return self._rpc_as_agent('tools/call', params, **kwargs)

    def _assert_needs_approval(self, response):
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn('result', response.json(), response.content)
        result = response.json()['result']
        self.assertTrue(result['isError'], result)
        meta = result.get('meta') or {}
        self.assertTrue(meta.get('status') == 'pending' or meta.get('approval_id'), result)

    def test_full_access_agent_needs_approval_for_quota_changes(self):
        for operation, path_params in (
            ('storage_v1_quota_company_update', {'company_id': 10}),
            ('storage_v1_quota_company_user_update', {'company_id': 10, 'user_id': 7}),
        ):
            with self.subTest(operation=operation):
                response = self._tool_call(
                    operation,
                    path_params=path_params,
                    body={'max_bytes': 1048576},
                    mcp_access=ACCESS_FULL,
                    owner_user_id=7,
                    creator_status='owner',
                )
                self._assert_needs_approval(response)

    def test_full_access_agent_needs_approval_for_an_actions_webhook(self):
        body = {
            'name': 'hook',
            'url': 'https://example.com/hook',
            'event_type': 'storage.object.uploaded',
            'enabled': True,
        }
        response = self._tool_call(
            'api_v1_actions_rules_create', body=body, mcp_access=ACCESS_FULL, owner_user_id=7, creator_status='owner'
        )
        self._assert_needs_approval(response)
        response = self._tool_call(
            'api_v1_actions_rules_partial_update',
            path_params={'id': str(uuid.uuid4())},
            body={'url': 'https://example.com/other'},
            mcp_access=ACCESS_FULL,
            owner_user_id=7,
            creator_status='owner',
        )
        self._assert_needs_approval(response)

    def test_full_access_agent_needs_approval_to_mount_an_outside_bucket(self):
        body = {
            'name': 'outside',
            'connector_provider': 's3',
            'credential': 'not-a-real-secret',
            'connector_settings': {'bucket': 'b'},
        }
        response = self._tool_call(
            'storage_v1_connector_create', body=body, mcp_access=ACCESS_FULL, owner_user_id=7, creator_status='owner'
        )
        self._assert_needs_approval(response)

    def test_read_only_agent_is_refused_outright_for_these_changes(self):
        response = self._tool_call(
            'storage_v1_quota_company_update',
            path_params={'company_id': 10},
            body={'max_bytes': 1},
            mcp_access=ACCESS_READ_ONLY,
            owner_user_id=7,
            creator_status='owner',
        )
        result = response.json()['result']
        self.assertTrue(result['isError'])
        self.assertIn('read only', json.dumps(result))
        self.assertNotEqual((result.get('meta') or {}).get('status'), 'pending')

    def test_copy_that_shows_a_file_to_more_people_needs_approval(self):
        import io

        from apps.storage.access import ensure_company_bucket
        from apps.storage.models import FOLDER_PLACEHOLDER_NAME, StorageObject
        from apps.storage.services import upload_object

        bucket = ensure_company_bucket(company_id=10)
        upload_object(
            bucket=bucket, path='mine.txt', fileobj=io.BytesIO(b'x'), owner_id=7, content_type='text/plain'
        )
        marker = StorageObject.objects.create(
            bucket=bucket,
            company_id=10,
            name=f'team/{FOLDER_PLACEHOLDER_NAME}',
            size=0,
            mime_type='application/x-directory',
            storage_key='k/team',
        )
        StorageAccessGrant.objects.create(
            company_id=10,
            bucket=bucket,
            object=marker,
            resource_type=StorageAccessGrant.ResourceType.FOLDER,
            subject_type=StorageAccessGrant.SubjectType.COMPANY,
            subject_id='10',
            permission=StorageAccessGrant.Permission.READ,
            effect=StorageAccessGrant.Effect.ALLOW,
        )
        wider = self._tool_call(
            'storage_v1_object_copy_create',
            body={'sourceKey': f'{COMPANY_BUCKET_NAME}/mine.txt', 'destinationKey': f'{COMPANY_BUCKET_NAME}/team/mine.txt'},
            mcp_access=ACCESS_FULL,
            owner_user_id=7,
            creator_status='member',
        )
        self._assert_needs_approval(wider)
        self.assertFalse(StorageObject.objects.filter(bucket=bucket, name='team/mine.txt').exists())
        # A copy that stays private to the same person goes through without asking.
        same = self._tool_call(
            'storage_v1_object_copy_create',
            body={'sourceKey': f'{COMPANY_BUCKET_NAME}/mine.txt', 'destinationKey': f'{COMPANY_BUCKET_NAME}/mine-2.txt'},
            mcp_access=ACCESS_FULL,
            owner_user_id=7,
            creator_status='member',
        )
        result = same.json()['result']
        self.assertFalse(result['isError'], result)
        self.assertTrue(StorageObject.objects.filter(bucket=bucket, name='mine-2.txt').exists())

    def test_mcp_refuses_the_scheduled_job_routes(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        tools = apply_published_tool_names(tools_from_schema(schema))
        names = {t['name'] for t in tools}
        listed_paths = {str((t.get('_meta') or {}).get('path') or '') for t in tools}
        self.assertFalse(any('scheduled-job' in path for path in listed_paths), listed_paths)
        response = self._rpc_as_agent(
            'tools/call',
            {'name': 'storage_list_scheduled_jobs', 'arguments': {}},
            mcp_access=ACCESS_FULL,
        )
        self.assertEqual((response.json().get('error') or {}).get('message'), 'Unknown tool')
        self.assertNotIn('storage_list_scheduled_jobs', names)

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
        tools = apply_published_tool_names(tools_from_schema(schema))
        tool = next(t for t in tools if t['_meta']['operationId'] == ASK_WRITE_OPERATION)
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
                'arguments': _grant_create_call_arguments(tool),
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
            ok = str(approval_id) == appr_id and state_calls['n'] == 3
            return (ok, {'approval_id': str(approval_id)})

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
        self.assertIn('not reusable', r4.json()['result']['content'][0]['text'].lower())
        self.assertEqual(r5.json().get('error'), 'agent_revoked')
