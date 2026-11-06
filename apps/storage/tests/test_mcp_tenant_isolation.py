"""MCP ``tools/call`` must not cross company boundaries."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import jwt
from django.test import Client, TestCase, override_settings
from drf_spectacular.generators import SchemaGenerator

from apps.actions.models import ActionRule, EventLog
from apps.storage.access import COMPANY_BUCKET_NAME, ensure_company_bucket
from apps.storage.models import ObjectShareLink, StorageAccessGrant, StorageObject
from apps.storage.tests.rs256_helpers import MCP_SIGNING_TEST_SETTINGS, generate_test_rsa_jwks
from apps.storage.tests.test_mcp import _agent_token, _mcp_host_kwargs, _signed_revocation_for_tests
from shellui_django.mcp.openapi_tools import tools_from_schema

COMPANY_A = 10
COMPANY_B = 20
SECRET_B_MARKER = 'tenant-b-leak-marker-7f3a'


def _owner_token(*, company_id: int, user_id: int) -> str:
    return jwt.encode(
        {
            'sub': str(user_id),
            'user_id': user_id,
            'company_id': company_id,
            'email': f'owner-{company_id}@example.com',
            'user_metadata': {'is_staff': False, 'is_company_owner': True},
            'iss': 'https://identity.test',
            'exp': 2**31 - 1,
        },
        'test-secret',
        algorithm='HS256',
    )


_TEST_JWKS, _, _ = generate_test_rsa_jwks()


@override_settings(
    **MCP_SIGNING_TEST_SETTINGS,
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_ISSUER='https://identity.test',
    IDENTITY_SERVICE_URL='https://identity.test',
    IDENTITY_JWKS_DOCUMENT=_TEST_JWKS,
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
)
class McpTenantIsolationTests(TestCase):
    def setUp(self):
        import apps.storage.mcp_views as mcp_views

        mcp_views._server = None
        self.client = Client()
        from django.core.cache import cache

        cache.delete('mcp:revoked_trusted_payload')
        cache.delete('mcp:revoked_list_trusted')
        cache.delete('mcp:revoked_signed_context')
        self.agent_token = _agent_token(company_id=COMPANY_A)
        claims = jwt.decode(self.agent_token, options={'verify_signature': False})
        self._agent_id = str(claims['agent_id'])
        self._company_id = int(claims['company_id'])
        self._revocation_patch = patch(
            'apps.storage.mcp_identity.requests.get',
            return_value=MagicMock(
                status_code=200,
                json=lambda: _signed_revocation_for_tests(
                    agents=[
                        {
                            'agent_id': self._agent_id,
                            'company_id': self._company_id,
                            'grant_version': 0,
                        }
                    ],
                ),
            ),
        )
        ensure_company_bucket(company_id=COMPANY_A)
        ensure_company_bucket(company_id=COMPANY_B)
        b_auth = {'HTTP_AUTHORIZATION': f'Bearer {_owner_token(company_id=COMPANY_B, user_id=2)}'}
        upload = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/secret-b.txt',
            data=SECRET_B_MARKER.encode(),
            content_type='text/plain',
            **b_auth,
        )
        self.assertEqual(upload.status_code, 200)
        self.obj_b = StorageObject.objects.get(company_id=COMPANY_B, name='secret-b.txt')
        self.bucket_b = self.obj_b.bucket
        self.storage_key_b = self.obj_b.storage_key

        share_resp = self.client.post(
            f'/storage/v1/share/{COMPANY_BUCKET_NAME}/secret-b.txt',
            data=json.dumps({'max_downloads': 5}),
            content_type='application/json',
            **b_auth,
        )
        self.assertEqual(share_resp.status_code, 201)
        self.share_token = share_resp.json()['token']

        self.grant_b = StorageAccessGrant.objects.filter(company_id=COMPANY_B).first()
        self.assertIsNotNone(self.grant_b)

        rule_resp = self.client.post(
            f'/api/v1/actions/rules?company_id={COMPANY_B}',
            data=json.dumps(
                {
                    'name': 'b-rule',
                    'event_type': 'storage.object.uploaded',
                    'url': 'https://hooks.example.com/b',
                    'secret': 'whsec_b',
                }
            ),
            content_type='application/json',
            **b_auth,
        )
        self.assertEqual(rule_resp.status_code, 201)
        self.rule_b = ActionRule.objects.get(pk=rule_resp.json()['id'])

        self.event_b = EventLog.objects.create(
            company_id=COMPANY_B,
            user_id=2,
            event_type='storage.object.uploaded',
            data={'path': 'secret-b.txt', 'storage_key': self.storage_key_b},
        )

        schema = SchemaGenerator().get_schema(request=None, public=True)
        self.tools = {t['name']: t for t in tools_from_schema(schema)}

    def _mcp_tools_call(self, tool_name: str, *, path_params=None, query=None, body=None):
        tool = self.tools[tool_name]
        arguments = {
            'path': tool['_meta']['path'],
            'method': tool['_meta']['method'],
            'query': query or {},
            'body': body or {},
        }
        if path_params is not None:
            arguments['path_params'] = path_params
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'tools/call',
            'params': {'name': tool_name, 'arguments': arguments},
        }
        with self._revocation_patch:
            return self.client.post(
                '/mcp',
                data=json.dumps(payload),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {self.agent_token}',
                **_mcp_host_kwargs(),
            )

    def _assert_blocked_no_leak(self, response):
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn('result', body)
        result = body['result']
        self.assertTrue(result.get('isError'))
        text = json.dumps(result)
        self.assertNotIn(SECRET_B_MARKER, text)
        self.assertNotIn(self.storage_key_b, text)
        self.assertNotIn(str(self.share_token), text)

    def test_agent_cannot_retrieve_company_b_object_by_uuid(self):
        tool = 'storage_v1_object_id_retrieve'
        response = self._mcp_tools_call(
            tool,
            path_params={'object_id': str(self.obj_b.id)},
        )
        self._assert_blocked_no_leak(response)

    def test_agent_cannot_read_company_b_object_by_path(self):
        tool = 'storage_v1_object_retrieve'
        response = self._mcp_tools_call(
            tool,
            path_params={
                'bucket_id': COMPANY_BUCKET_NAME,
                'object_path': 'secret-b.txt',
            },
        )
        self._assert_blocked_no_leak(response)

    def test_agent_cannot_destroy_company_b_share_link(self):
        tool = 'storage_v1_share_link_destroy'
        response = self._mcp_tools_call(
            tool,
            path_params={'token': self.share_token},
        )
        self._assert_blocked_no_leak(response)
        self.assertTrue(ObjectShareLink.objects.filter(token=self.share_token, revoked_at__isnull=True).exists())

    def test_agent_cannot_destroy_company_b_access_grant(self):
        tool = 'storage_v1_access_grant_destroy'
        response = self._mcp_tools_call(
            tool,
            path_params={'grant_id': str(self.grant_b.id)},
        )
        self._assert_blocked_no_leak(response)
        self.assertTrue(StorageAccessGrant.objects.filter(pk=self.grant_b.pk).exists())

    def test_agent_cannot_retrieve_company_b_action_rule(self):
        tool = 'api_v1_actions_rules_retrieve'
        response = self._mcp_tools_call(
            tool,
            path_params={'id': str(self.rule_b.pk)},
        )
        self._assert_blocked_no_leak(response)

    def test_agent_cannot_retrieve_company_b_event_log(self):
        tool = 'api_v1_actions_event_log_retrieve'
        response = self._mcp_tools_call(
            tool,
            path_params={'id': str(self.event_b.pk)},
        )
        self._assert_blocked_no_leak(response)

    def test_agent_rejects_mismatched_company_id_query_on_rules_list(self):
        tool = 'api_v1_actions_rules_list'
        response = self._mcp_tools_call(
            tool,
            query={'company_id': str(COMPANY_B)},
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()['result']
        self.assertTrue(result.get('isError'))
        text = json.dumps(result)
        self.assertNotIn('b-rule', text)
        self.assertNotIn(str(self.rule_b.pk), text)

    def test_s3_keys_stay_under_company_prefix(self):
        self.assertIn(f'/{COMPANY_B}/', self.storage_key_b)
        tool = 'storage_v1_object_id_retrieve'
        self._mcp_tools_call(tool, path_params={'object_id': str(self.obj_b.id)})
        obj_a_keys = set(
            StorageObject.objects.filter(company_id=COMPANY_A).values_list('storage_key', flat=True)
        )
        for key in obj_a_keys:
            self.assertIn(f'/{COMPANY_A}/', key)
            self.assertNotIn(f'/{COMPANY_B}/', key)
