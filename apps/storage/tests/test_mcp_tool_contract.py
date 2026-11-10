"""MCP tools/list contract and one happy-path tools/call per tool.

Renaming a tool, dropping one, or changing its input schema fails the snapshot.
Each ``test_<operation_id>`` calls ``POST /mcp`` ``tools/call`` with an agent token.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import jwt
from django.core.files.storage import default_storage
from django.test import Client, TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator

from apps.actions.models import ActionOutbox, ActionRule, EventLog
from apps.actions.webhook_transport import WebhookPostResult
from apps.authapi.mcp_openapi import MCP_REQUIRED_OPERATION_IDS
from apps.storage.access import COMPANY_BUCKET_NAME
from apps.storage.mcp_server_strict import materialize_storage_mcp_path
from apps.storage.models import Bucket, ObjectShareLink, StorageAccessGrant, StorageObject
from apps.storage.tests.rs256_helpers import MCP_SIGNING_TEST_SETTINGS
from apps.storage.tests.test_mcp import (
    _TEST_JWKS,
    _agent_token,
    _mcp_host_kwargs,
    _signed_revocation_for_tests,
)
from apps.storage.mcp_tool_names import MCP_PUBLISHED_TOOL_NAMES
from apps.storage.mcp_tool_schema import published_mcp_tools
from shellui_django.mcp.routing import McpToolArgumentError

_FIXTURE = Path(__file__).resolve().parent / 'fixtures' / 'mcp_tools_contract.json'
_COMPANY = 10
_APPROVAL_ID = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
_RULE_SECRET = 'whsec-audit-known'
_FILE_BYTES = b'hello-notes'


def _canon(value):
    return json.loads(json.dumps(value, sort_keys=True))


def _access_row(tool: dict) -> dict:
    meta = tool['_meta']
    return {
        'name': tool['name'],
        'read_only': bool(meta.get('read_only')),
        'destructive': bool(meta.get('destructive')),
        # Destructive tools always wait for a single-use approval, including mcp_access=full.
        'needs_approval': bool(meta.get('destructive')),
        'method': meta.get('method'),
        'path': meta.get('path'),
    }


def _contract_document(public_tools: list, internal_tools: list) -> dict:
    by_name = {tool['name']: tool for tool in internal_tools}
    access = [_access_row(by_name[tool['name']]) for tool in public_tools]
    return {'tools': public_tools, 'access': access}


def _owner_token() -> str:
    return jwt.encode(
        {
            'sub': '0',
            'user_id': 0,
            'company_id': _COMPANY,
            'email': 'owner@example.com',
            'aud': 'shellui',
            'user_metadata': {'is_staff': False, 'is_company_owner': True},
            'iss': 'https://identity.test',
            'exp': 2**31 - 1,
        },
        'test-secret',
        algorithm='HS256',
    )


def _approved(payload, _claims):
    payload['approval_id'] = _APPROVAL_ID
    return 'approved'


def _consume(approval_id, _payload, _claims):
    return True, {'approval_id': str(approval_id)}


@override_settings(
    **MCP_SIGNING_TEST_SETTINGS,
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_AUDIENCE='shellui',
    IDENTITY_SERVICE_URL='https://identity.test',
    IDENTITY_JWKS_DOCUMENT=_TEST_JWKS,
    DEFAULT_COMPANY_QUOTA_BYTES=50 * 1024 * 1024,
)
class McpToolContractTests(TestCase):
    def setUp(self):
        import apps.storage.mcp_views as mcp_views

        mcp_views._server = None
        self.client = Client()
        from django.core.cache import cache

        cache.delete('mcp:revoked_trusted_payload')
        cache.delete('mcp:revoked_list_trusted')
        cache.delete('mcp:revoked_verified_claims')
        self.token = _agent_token(company_id=_COMPANY, mcp_access='full', mcp_read='sensitive')
        claims = jwt.decode(self.token, options={'verify_signature': False})
        body = _signed_revocation_for_tests(
            agents=[{'agent_id': str(claims['agent_id']), 'company_id': _COMPANY, 'grant_version': 0}],
        )
        self._revocation = patch(
            'apps.storage.mcp_identity.requests.get',
            return_value=MagicMock(status_code=200, json=lambda: body),
        )
        self._revocation.start()
        self.addCleanup(self._revocation.stop)

    def _tools_list(self) -> list:
        response = self.client.post(
            '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
            **_mcp_host_kwargs(),
        )
        self.assertEqual(response.status_code, 200, response.content[:500])
        payload = response.json()
        self.assertIn('result', payload, payload)
        return payload['result']['tools']

    def test_tools_list_matches_snapshot(self):
        public_tools = self._tools_list()
        internal = published_mcp_tools(SchemaGenerator().get_schema(request=None, public=True))
        self.assertEqual([tool['name'] for tool in public_tools], [tool['name'] for tool in internal])
        self.assertEqual(
            {tool['name'] for tool in public_tools},
            set(MCP_PUBLISHED_TOOL_NAMES.values()),
        )
        for public, internal_tool in zip(public_tools, internal, strict=True):
            self.assertEqual(public['name'], internal_tool['name'])
            self.assertEqual(public['description'], internal_tool['description'])
            self.assertEqual(public['inputSchema'], internal_tool['inputSchema'])
            meta = internal_tool['_meta']
            self.assertEqual(public['annotations']['readOnlyHint'], bool(meta['read_only']))
            self.assertEqual(public['annotations']['destructiveHint'], bool(meta['destructive']))
            self.assertEqual(set(public), {'name', 'description', 'inputSchema', 'annotations'})
        document = _contract_document(public_tools, internal)
        self.assertTrue(_FIXTURE.is_file(), f'missing MCP contract snapshot {_FIXTURE}')
        expected = json.loads(_FIXTURE.read_text())
        self.assertEqual(_canon(document), _canon(expected))

    def test_every_listed_tool_has_a_happy_path_test(self):
        published_to_op = {published: op for op, published in MCP_PUBLISHED_TOOL_NAMES.items()}
        ops = {published_to_op[tool['name']] for tool in self._tools_list()}
        methods = {
            name[5:]
            for name in dir(McpToolHappyPathTests)
            if name.startswith('test_storage_v1_') or name.startswith('test_api_v1_')
        }
        self.assertEqual(ops, methods)

    def test_tool_names_use_storage_prefix(self):
        for tool in self._tools_list():
            name = tool['name']
            self.assertFalse(name.startswith('api_v1_'), name)
            self.assertTrue(name.startswith('storage_'), name)

    def test_nested_object_path_is_a_single_parameter(self):
        path = materialize_storage_mcp_path(
            '/storage/v1/object/{bucket_id}/{object_path}',
            {'bucket_id': 'company', 'object_path': 'notes/a.txt'},
        )
        self.assertEqual(path, '/storage/v1/object/company/notes/a.txt')

    def test_bucket_id_rejects_a_slash(self):
        with self.assertRaises(McpToolArgumentError):
            materialize_storage_mcp_path('/storage/v1/bucket/{bucket_id}', {'bucket_id': 'a/b'})

    def test_unknown_flat_argument_is_rejected(self):
        response = self.client.post(
            '/mcp',
            data=json.dumps(
                {
                    'jsonrpc': '2.0',
                    'id': 9,
                    'method': 'tools/call',
                    'params': {'name': 'storage_list_bucket', 'arguments': {'method': 'GET'}},
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
            **_mcp_host_kwargs(),
        )
        self.assertEqual(response.status_code, 200, response.content[:500])
        self.assertEqual(response.json()['error']['code'], -32602)

    def test_legacy_method_path_envelope_still_runs(self):
        response = self.client.post(
            '/mcp',
            data=json.dumps(
                {
                    'jsonrpc': '2.0',
                    'id': 10,
                    'method': 'tools/call',
                    'params': {
                        'name': 'storage_list_bucket',
                        'arguments': {
                            'path': '/storage/v1/bucket',
                            'method': 'GET',
                            'query': {},
                            'body': {},
                        },
                    },
                }
            ),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
            **_mcp_host_kwargs(),
        )
        self.assertEqual(response.status_code, 200, response.content[:500])
        body = response.json()
        self.assertIn('result', body, body)
        self.assertFalse(body['result'].get('isError'), body['result'])


@override_settings(
    **MCP_SIGNING_TEST_SETTINGS,
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_AUDIENCE='shellui',
    IDENTITY_SERVICE_URL='https://identity.test',
    IDENTITY_JWKS_DOCUMENT=_TEST_JWKS,
    DEFAULT_COMPANY_QUOTA_BYTES=50 * 1024 * 1024,
)
class McpToolHappyPathTests(TestCase):
    def setUp(self):
        import apps.authapi.mcp_authority as mcp_authority
        import apps.storage.mcp_views as mcp_views

        mcp_authority.clear_delegated_authority_cache()
        mcp_views._server = None
        from django.core.cache import cache

        cache.delete('mcp:revoked_trusted_payload')
        cache.delete('mcp:revoked_list_trusted')
        cache.delete('mcp:revoked_verified_claims')
        self.client = Client()
        self.owner_token = _owner_token()
        self.token = _agent_token(company_id=_COMPANY, mcp_access='full', mcp_read='sensitive')
        claims = jwt.decode(self.token, options={'verify_signature': False})
        self.agent_id = str(claims['agent_id'])
        body = _signed_revocation_for_tests(
            agents=[{'agent_id': self.agent_id, 'company_id': _COMPANY, 'grant_version': 0}],
        )
        self._patches = [
            patch(
                'apps.storage.mcp_identity.requests.get',
                return_value=MagicMock(status_code=200, json=lambda: body),
            ),
            patch('apps.storage.mcp_identity.requests.post', return_value=MagicMock(status_code=204)),
            patch('apps.storage.mcp_views._approval_state_for_mcp', side_effect=_approved),
            patch('apps.storage.mcp_views.consume_approval', side_effect=_consume),
        ]
        started = []
        for item in self._patches:
            started.append(item.start())
            self.addCleanup(item.stop)
        self.call_log = started[1]
        schema = SchemaGenerator().get_schema(request=None, public=True)
        self.tools = {
            tool['_meta']['operationId']: tool
            for tool in published_mcp_tools(schema)
        }
        self._seed()

    def _rest(self, method: str, path: str, *, body=None, content: bytes | None = None, content_type: str | None = None):
        kwargs = {'HTTP_AUTHORIZATION': f'Bearer {self.owner_token}'}
        if content is not None:
            kwargs['data'] = content
            kwargs['content_type'] = content_type or 'text/plain'
        elif body is not None:
            kwargs['data'] = json.dumps(body)
            kwargs['content_type'] = 'application/json'
        response = getattr(self.client, method)(path, **kwargs)
        self.assertLess(response.status_code, 400, response.content[:800])
        return response

    def _upload(self, object_path: str, content: bytes):
        return self._rest(
            'post',
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/{object_path}',
            content=content,
        )

    def _seed(self):
        uploaded = self._upload('notes/a.txt', _FILE_BYTES)
        self.object_id = uploaded.json()['Id']
        self._upload('batch.txt', b'batch')
        self._upload('single.txt', b'single')
        self._upload('foldera/file.txt', b'folder-byte')
        self._upload('trash/file.txt', b'trash-byte')
        self._upload('move-src.txt', b'move-byte')
        self._upload('copy-src.txt', b'copy-byte')
        self._upload('sign-me.txt', b'sign-byte')
        share = self._rest(
            'post',
            f'/storage/v1/share/{COMPANY_BUCKET_NAME}/notes/a.txt',
            body={'max_downloads': 5},
        )
        self.share_token = share.json()['token']
        grant = self._rest(
            'post',
            '/storage/v1/access/grant',
            body={
                'subject_type': 'user',
                'subject_id': '7',
                'resource_type': 'object',
                'resource_id': 'notes/a.txt',
            },
        )
        self.grant_id = grant.json()['id']
        connector = self._rest(
            'post',
            '/storage/v1/connector',
            body={
                'name': 'sp-mount',
                'connector_provider': 'sharepoint',
                'connector_settings': {'_dev_simulation': {'mode': 'ok'}},
                'credential': 'oauth-refresh-token',
            },
        )
        self.assertEqual(connector.json().get('connector_configuration_status'), 'configured')
        self.rule = ActionRule.objects.create(
            company_id=_COMPANY,
            name='audit-rule',
            event_type='storage.object.uploaded',
            enabled=True,
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://hooks.example.com/audit', 'secret': _RULE_SECRET},
        )
        self.event = EventLog.objects.create(
            company_id=_COMPANY,
            user_id=1,
            event_type='storage.object.uploaded',
            data={'marker': 'audit-event-marker'},
        )
        self.delivery = ActionOutbox.objects.create(
            company_id=_COMPANY,
            action_rule=self.rule,
            delivery_kind=ActionOutbox.KIND_WEBHOOK,
            event_type='storage.object.uploaded',
            envelope={'id': 'env-audit', 'type': 'storage.object.uploaded'},
            status=ActionOutbox.STATUS_FAILED,
            last_error='timeout',
        )

    def _call(self, name: str, *, path_params=None, query=None, body=None, token: str | None = None):
        tool = self.tools[name]
        arguments: dict = {}
        if path_params:
            arguments.update(path_params)
        if query:
            arguments.update(query)
        if body:
            arguments.update(body)
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'tools/call',
            'params': {'name': tool['name'], 'arguments': arguments},
        }
        extra = []
        if name == 'api_v1_actions_rules_send_test':
            extra.append(
                patch(
                    'apps.actions.handlers.webhook.post_webhook_url',
                    return_value=WebhookPostResult(status=200, excerpt='ok'),
                )
            )
        for item in extra:
            item.start()
        try:
            return self.client.post(
                '/mcp',
                data=json.dumps(payload),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {token or self.token}',
                **_mcp_host_kwargs(),
            )
        finally:
            for item in extra:
                item.stop()

    def _ok(self, response, name: str):
        self.assertEqual(response.status_code, 200, response.content[:800])
        body = response.json()
        self.assertIn('result', body, body)
        result = body['result']
        self.assertFalse(result.get('isError'), f'{name}: {result}')
        return json.loads(result['content'][0]['text'])

    def _object_bytes(self, object_path: str) -> bytes:
        obj = StorageObject.objects.get(company_id=_COMPANY, name=object_path)
        with default_storage.open(obj.storage_key, 'rb') as handle:
            return handle.read()

    def _b64(self, content: bytes) -> str:
        return base64.b64encode(content).decode('ascii')

    def _exercise(self, name: str):
        case = self._cases()[name]
        response = self._call(name, **case.get('call', {}))
        payload = self._ok(response, name)
        case['check'](payload)

    def _cases(self) -> dict:
        bucket = COMPANY_BUCKET_NAME
        return {
            'storage_v1_bucket_list': {
                'check': lambda payload: self.assertIn(bucket, json.dumps(payload)),
            },
            'storage_v1_bucket_retrieve': {
                'call': {'path_params': {'bucket_id': bucket}},
                'check': lambda payload: self.assertEqual(payload.get('name') or payload.get('id'), bucket),
            },
            'storage_v1_bucket_empty_create': {
                'call': {'path_params': {'bucket_id': bucket}},
                'check': lambda payload: self.assertFalse(
                    StorageObject.objects.filter(company_id=_COMPANY, bucket__name=bucket).exists()
                ),
            },
            'storage_v1_connector_list': {
                'check': lambda payload: self.assertIn('sp-mount', json.dumps(payload)),
            },
            'storage_v1_connector_retrieve': {
                'call': {'path_params': {'connector_id': 'sp-mount'}},
                'check': lambda payload: self.assertEqual(payload.get('connector_configuration_status'), 'configured'),
            },
            'storage_v1_connector_create': {
                'call': {
                    'body': {
                        'name': 'backup',
                        'connector_provider': 'sharepoint',
                        'connector_settings': {'_dev_simulation': {'mode': 'ok'}},
                        'credential': 'oauth-refresh-token',
                    }
                },
                'check': lambda payload: (
                    self.assertEqual(payload.get('name'), 'backup'),
                    self.assertNotIn('oauth-refresh-token', json.dumps(payload)),
                ),
            },
            'storage_v1_connector_update': {
                'call': {
                    'path_params': {'connector_id': 'sp-mount'},
                    'body': {
                        'connector_settings': {
                            'display_name': 'Audit mount',
                            '_dev_simulation': {'mode': 'ok'},
                        }
                    },
                },
                'check': lambda payload: self.assertEqual(
                    (payload.get('connector_settings') or {}).get('display_name'),
                    'Audit mount',
                ),
            },
            'storage_v1_connector_partial_update': {
                'call': {
                    'path_params': {'connector_id': 'sp-mount'},
                    'body': {'connector_settings': {'display_name': 'Patched mount'}},
                },
                'check': lambda payload: self.assertEqual(
                    (payload.get('connector_settings') or {}).get('display_name'),
                    'Patched mount',
                ),
            },
            'storage_v1_connector_destroy': {
                'call': {'path_params': {'connector_id': 'sp-mount'}},
                'check': lambda payload: self.assertFalse(Bucket.objects.filter(company_id=_COMPANY, name='sp-mount').exists()),
            },
            'storage_v1_connector_configuration_check_create': {
                'call': {'path_params': {'connector_id': 'sp-mount'}},
                'check': lambda payload: self.assertEqual(payload.get('connector_configuration_status'), 'configured'),
            },
            'storage_v1_connector_configuration_validate_create': {
                'call': {'path_params': {'connector_id': 'sp-mount'}},
                'check': lambda payload: self.assertEqual(payload.get('name'), 'sp-mount'),
            },
            'storage_v1_connector_configuration_retry_create': {
                'call': {'path_params': {'connector_id': 'sp-mount'}},
                'check': lambda payload: self.assertEqual(payload.get('connector_configuration_status'), 'configured'),
            },
            'storage_v1_object_list_create': {
                'call': {'path_params': {'bucket_id': bucket}, 'body': {'prefix': 'notes', 'limit': 20}},
                'check': lambda payload: self.assertIn('"name": "a.txt"', json.dumps(payload)),
            },
            'storage_v1_object_id_retrieve': {
                'call': {'path_params': {'object_id': self.object_id}},
                'check': lambda payload: self.assertEqual(payload.get('path') or payload.get('name'), 'notes/a.txt'),
            },
            'storage_v1_object_retrieve': {
                'call': {'path_params': {'bucket_id': bucket, 'object_path': 'notes/a.txt'}},
                'check': lambda payload: self.assertEqual(base64.b64decode(payload['content_base64']), _FILE_BYTES),
            },
            'storage_v1_object_authenticated_retrieve': {
                'call': {'path_params': {'bucket_id': bucket, 'object_path': 'notes/a.txt'}},
                'check': lambda payload: self.assertEqual(base64.b64decode(payload['content_base64']), _FILE_BYTES),
            },
            'storage_v1_object_info_authenticated_retrieve': {
                'call': {'path_params': {'bucket_id': bucket, 'object_path': 'notes/a.txt'}},
                'check': lambda payload: self.assertEqual(payload.get('name'), 'notes/a.txt'),
            },
            'storage_v1_object_create': {
                'call': {
                    'path_params': {'bucket_id': bucket, 'object_path': 'inbox/mcp-new.txt'},
                    'body': {'content_base64': self._b64(b'mcp-bytes'), 'content_type': 'text/plain'},
                },
                'check': lambda payload: self.assertEqual(self._object_bytes('inbox/mcp-new.txt'), b'mcp-bytes'),
            },
            'storage_v1_object_update': {
                'call': {
                    'path_params': {'bucket_id': bucket, 'object_path': 'notes/a.txt'},
                    'body': {'content_base64': self._b64(b'updated-notes'), 'content_type': 'text/plain'},
                },
                'check': lambda payload: self.assertEqual(
                    self._object_bytes('notes/a.txt'),
                    b'updated-notes',
                    payload,
                ),
            },
            'storage_v1_object_destroy': {
                'call': {'path_params': {'bucket_id': bucket, 'object_path': 'single.txt'}},
                'check': lambda payload: self.assertFalse(
                    StorageObject.objects.filter(company_id=_COMPANY, name='single.txt').exists()
                ),
            },
            'storage_v1_object_delete_many': {
                'call': {'path_params': {'bucket_id': bucket}, 'body': {'prefixes': ['batch.txt']}},
                'check': lambda payload: self.assertFalse(
                    StorageObject.objects.filter(company_id=_COMPANY, name='batch.txt').exists()
                ),
            },
            'storage_v1_object_prefix_retrieve': {
                'call': {'path_params': {'bucket_id': bucket}, 'query': {'prefix': 'notes'}},
                'check': lambda payload: self.assertGreaterEqual(payload.get('file_count', 0), 1),
            },
            'storage_v1_object_prefix_create': {
                'call': {
                    'path_params': {'bucket_id': bucket},
                    'body': {'from': 'foldera', 'to': 'folderb'},
                },
                'check': lambda payload: self.assertTrue(
                    StorageObject.objects.filter(company_id=_COMPANY, name='folderb/file.txt').exists()
                ),
            },
            'storage_v1_object_prefix_destroy': {
                'call': {'path_params': {'bucket_id': bucket}, 'body': {'prefix': 'trash'}},
                'check': lambda payload: self.assertGreaterEqual(payload.get('count', 0), 1),
            },
            'storage_v1_object_move_create': {
                'call': {
                    'body': {
                        'sourceKey': f'{bucket}/move-src.txt',
                        'destinationKey': f'{bucket}/moved.txt',
                    }
                },
                'check': lambda payload: self.assertIn('moved', json.dumps(payload).lower()),
            },
            'storage_v1_object_copy_create': {
                'call': {
                    'body': {
                        'sourceKey': f'{bucket}/copy-src.txt',
                        'destinationKey': f'{bucket}/copied.txt',
                    }
                },
                'check': lambda payload: self.assertTrue(
                    StorageObject.objects.filter(company_id=_COMPANY, name='copied.txt').exists()
                ),
            },
            'storage_v1_object_sign_create': {
                'call': {'path_params': {'bucket_id': bucket}, 'body': {'path': 'sign-me.txt', 'expiresIn': 60}},
                'check': lambda payload: self.assertTrue(payload.get('signedURL') and payload['signedURL'] != '[redacted]'),
            },
            'storage_v1_object_sign_path_create': {
                'call': {'path_params': {'bucket_id': bucket, 'object_path': 'sign-me.txt'}, 'body': {'expiresIn': 60}},
                'check': lambda payload: self.assertTrue(payload.get('signedUrl') and payload['signedUrl'] != '[redacted]'),
            },
            'storage_v1_access_grant_list': {
                'call': {'query': {'bucket': bucket, 'resource_type': 'object'}},
                'check': lambda payload: self.assertIn(self.grant_id, json.dumps(payload)),
            },
            'storage_v1_access_grant_create': {
                'call': {
                    'body': {
                        'subject_type': 'user',
                        'subject_id': '8',
                        'resource_type': 'object',
                        'resource_id': 'notes/a.txt',
                        'bucket': bucket,
                    }
                },
                'check': lambda payload: self.assertEqual(payload.get('subject_id'), '8'),
            },
            'storage_v1_access_grant_destroy': {
                'call': {'path_params': {'grant_id': self.grant_id}},
                'check': lambda payload: self.assertFalse(StorageAccessGrant.objects.filter(id=self.grant_id).exists()),
            },
            'storage_v1_share_list': {
                'call': {'path_params': {'bucket_id': bucket, 'object_path': 'notes/a.txt'}},
                'check': self._check_share_list,
            },
            'storage_v1_share_create': {
                'call': {
                    'path_params': {'bucket_id': bucket, 'object_path': 'sign-me.txt'},
                    'body': {'max_downloads': 2},
                },
                'check': self._check_share_create,
            },
            'storage_v1_share_link_destroy': {
                'call': {'path_params': {'token': self.share_token}},
                'check': self._check_share_destroy,
            },
            'storage_v1_quota_retrieve': {
                'check': lambda payload: self.assertEqual(payload.get('company_id'), _COMPANY),
            },
            'storage_v1_quota_company_update': {
                'call': {'path_params': {'company_id': str(_COMPANY)}, 'body': {'max_bytes': 40_000_000}},
                'check': lambda payload: self.assertEqual(payload.get('max_bytes'), 40_000_000),
            },
            'storage_v1_quota_company_user_update': {
                'call': {
                    'path_params': {'company_id': str(_COMPANY), 'user_id': '7'},
                    'body': {'max_bytes': 1_000_000},
                },
                'check': lambda payload: self.assertEqual(payload.get('max_bytes'), 1_000_000),
            },
            'storage_v1_stats_retrieve': {
                'call': {'query': {'days': 14}},
                'check': lambda payload: self.assertIn('notes/a.txt', json.dumps(payload)),
            },
            'api_v1_actions_events_list': {
                'check': lambda payload: self.assertIn('storage.object.uploaded', json.dumps(payload)),
            },
            'api_v1_actions_rules_list': {
                'check': lambda payload: self.assertIn('audit-rule', json.dumps(payload)),
            },
            'api_v1_actions_rules_create': {
                'call': {
                    'body': {
                        'name': 'mcp-created-rule',
                        'event_type': 'storage.object.uploaded',
                        'url': 'https://hooks.example.com/mcp',
                    }
                },
                'check': self._check_rule_create,
            },
            'api_v1_actions_rules_retrieve': {
                'call': {'path_params': {'id': str(self.rule.pk)}},
                'check': lambda payload: self.assertNotIn(_RULE_SECRET, json.dumps(payload)),
            },
            'api_v1_actions_rules_partial_update': {
                'call': {'path_params': {'id': str(self.rule.pk)}, 'body': {'name': 'audit-rule-renamed'}},
                'check': lambda payload: self.assertEqual(payload.get('name'), 'audit-rule-renamed'),
            },
            'api_v1_actions_rules_destroy': {
                'call': {'path_params': {'id': str(self.rule.pk)}},
                'check': lambda payload: self.assertFalse(ActionRule.objects.filter(pk=self.rule.pk).exists()),
            },
            'api_v1_actions_rules_rotate_secret': {
                'call': {'path_params': {'id': str(self.rule.pk)}},
                'check': self._check_rotate,
            },
            'api_v1_actions_rules_send_test': {
                'call': {'path_params': {'id': str(self.rule.pk)}},
                'check': lambda payload: self.assertTrue(payload.get('ok')),
            },
            'api_v1_actions_deliveries_list': {
                'check': lambda payload: self.assertIn(str(self.delivery.pk), json.dumps(payload)),
            },
            'api_v1_actions_deliveries_retrieve': {
                'call': {'path_params': {'delivery_id': str(self.delivery.pk)}},
                'check': lambda payload: self.assertEqual(payload.get('status'), 'failed'),
            },
            'api_v1_actions_deliveries_requeue': {
                'call': {'path_params': {'delivery_id': str(self.delivery.pk)}},
                'check': lambda payload: self.assertEqual(payload.get('status'), 'pending'),
            },
            'api_v1_actions_event_log_list': {
                'check': lambda payload: self.assertIn('audit-event-marker', json.dumps(payload)),
            },
            'api_v1_actions_event_log_retrieve': {
                'call': {'path_params': {'id': str(self.event.pk)}},
                'check': lambda payload: self.assertIn('audit-event-marker', json.dumps(payload)),
            },
            'api_v1_actions_event_log_types_list': {
                'check': lambda payload: self.assertIn('storage.object.uploaded', json.dumps(payload)),
            },
            'api_v1_actions_event_log_retention_retrieve': {
                'check': lambda payload: self.assertIn('data_retention_days', payload),
            },
        }

    def _check_share_list(self, payload):
        text = json.dumps(payload)
        self.assertNotIn(self.share_token, text)
        self.assertIn('notes/a.txt', text)
        self.assertIn('[redacted]', text)

    def _check_share_destroy(self, payload):
        self.assertNotIn(self.share_token, json.dumps(payload))
        link = ObjectShareLink.objects.get(token=self.share_token)
        self.assertIsNotNone(link.revoked_at)

    def _check_share_create(self, payload):
        token = payload.get('token')
        self.assertTrue(token and token != '[redacted]')
        self.assertEqual(payload.get('path_url'), '[redacted]')
        self.assertNotIn(token, payload.get('path_url') or '')

    def _check_rule_create(self, payload):
        self.assertEqual(payload.get('name'), 'mcp-created-rule')
        self.assertEqual(payload.get('secret'), '[redacted]')
        self.assertNotIn('whsec_', json.dumps(payload))
        stored = (ActionRule.objects.get(name='mcp-created-rule').config or {}).get('secret')
        self.assertTrue(stored and stored != '[redacted]')

    def _check_rotate(self, payload):
        self.assertEqual(payload.get('secret'), '[redacted]')
        text = json.dumps(payload)
        self.assertNotIn(_RULE_SECRET, text)
        self.assertNotIn('whsec_', text)
        stored = (ActionRule.objects.get(pk=self.rule.pk).config or {}).get('secret')
        self.assertTrue(stored and stored not in {'[redacted]', _RULE_SECRET})

    def test_stats_safe_read_redacts_recent_filenames(self):
        token = _agent_token(company_id=_COMPANY, mcp_access='read_only', mcp_read='safe')
        claims = jwt.decode(token, options={'verify_signature': False})
        body = _signed_revocation_for_tests(
            agents=[{'agent_id': str(claims['agent_id']), 'company_id': _COMPANY, 'grant_version': 0}],
        )
        with patch(
            'apps.storage.mcp_identity.requests.get',
            return_value=MagicMock(status_code=200, json=lambda: body),
        ):
            response = self._call('storage_v1_stats_retrieve', query={'days': 14}, token=token)
        payload = self._ok(response, 'storage_v1_stats_retrieve')
        text = json.dumps(payload)
        self.assertNotIn('notes/a.txt', text)
        self.assertIn('[redacted]', text)
        self.assertIn('object_count', text)

    def test_bucket_list_forwards_a_call_log(self):
        self._exercise('storage_v1_bucket_list')
        self.assertTrue(self.call_log.called)
        posted = self.call_log.call_args.kwargs['json']
        self.assertEqual(posted['tool'], 'storage_list_bucket')
        self.assertEqual(posted['method'], 'POST')
        self.assertEqual(posted['path'], '/mcp')
        self.assertEqual(posted['outcome'], 'allowed')


def _bind_happy_path(name: str):
    def test(self, tool_name=name):
        self._exercise(tool_name)

    test.__name__ = f'test_{name}'
    test.__doc__ = f'Happy-path tools/call for {name}.'
    return test


for _tool_name in sorted(MCP_REQUIRED_OPERATION_IDS):
    setattr(McpToolHappyPathTests, f'test_{_tool_name}', _bind_happy_path(_tool_name))
