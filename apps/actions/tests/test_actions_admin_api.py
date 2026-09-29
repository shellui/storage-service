from unittest.mock import patch

import jwt
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.actions.models import ActionOutbox, ActionRule


def _owner_token(*, company_id: int = 10) -> str:
    return jwt.encode(
        {
            'sub': '1',
            'user_id': 1,
            'company_id': company_id,
            'email': 'owner@example.com',
            'user_metadata': {'is_staff': False, 'is_company_owner': True},
            'exp': 2**31 - 1,
        },
        'test-secret',
        algorithm='HS256',
    )


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
)
class ActionsAdminApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.company_id = 10
        token = _owner_token(company_id=self.company_id)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

    def _url(self, path: str) -> str:
        return f'{path}?company_id={self.company_id}'

    def test_events_catalog_payload_fields(self):
        response = self.client.get(self._url('/api/v1/actions/events'))
        self.assertEqual(response.status_code, 200)
        row = next(r for r in response.data['results'] if r['type'] == 'storage.object.uploaded')
        self.assertIn('payload_fields', row)
        self.assertEqual(row['supported_action_kinds'], ['webhook'])
        self.assertIn('sample_envelope', row)

    def test_create_webhook_rule(self):
        response = self.client.post(
            self._url('/api/v1/actions/rules'),
            {
                'name': 'n8n',
                'event_type': 'storage.object.uploaded',
                'url': 'https://hooks.example.com/upload',
                'secret': 'whsec_test',
            },
            format='json',
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['action_kind'], 'webhook')
        self.assertTrue(response.data['config']['secret_set'])

    def test_list_deliveries_and_requeue(self):
        rule = ActionRule.objects.create(
            company_id=self.company_id,
            name='Hook',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=rule,
            event_type='storage.object.uploaded',
            envelope={'id': '1', 'type': 'storage.object.uploaded', 'data': {}},
            status=ActionOutbox.STATUS_DEAD,
            last_error='fail',
        )
        listed = self.client.get(self._url('/api/v1/actions/deliveries'))
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data['count'], 1)

        detail = self.client.get(self._url(f'/api/v1/actions/deliveries/{row.pk}'))
        self.assertEqual(detail.status_code, 200)
        self.assertIn('attempts', detail.data)

        requeue = self.client.post(self._url(f'/api/v1/actions/deliveries/{row.pk}/requeue'))
        self.assertEqual(requeue.status_code, 200)
        self.assertEqual(requeue.data['status'], 'pending')

    @patch('apps.actions.webhook_test_send.deliver_webhook_action')
    def test_send_test_webhook(self, mock_deliver):
        rule = ActionRule.objects.create(
            company_id=self.company_id,
            name='Hook',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        response = self.client.post(self._url(f'/api/v1/actions/rules/{rule.pk}/send-test'))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['ok'])
        mock_deliver.assert_called_once()
