import uuid
from unittest.mock import patch

from django.test import TestCase

from apps.actions.models import ActionRule
from apps.actions.webhook_test_send import send_webhook_test_for_rule


class WebhookTestSendSampleDataTests(TestCase):
    @patch('apps.actions.webhook_test_send.deliver_webhook_action')
    def test_consecutive_test_sends_use_distinct_object_ids(self, mock_deliver):
        company_id = 42
        rule = ActionRule.objects.create(
            company_id=company_id,
            name='Upload hook',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )
        send_webhook_test_for_rule(rule=rule, company_id=company_id)
        first_envelope = mock_deliver.call_args.kwargs['envelope']
        send_webhook_test_for_rule(rule=rule, company_id=company_id)
        second_envelope = mock_deliver.call_args.kwargs['envelope']

        first_object_id = first_envelope['data']['object_id']
        second_object_id = second_envelope['data']['object_id']
        self.assertNotEqual(first_object_id, second_object_id)
        uuid.UUID(first_object_id)
        uuid.UUID(second_object_id)
        self.assertNotEqual(first_envelope['id'], second_envelope['id'])
