import base64
import hashlib
import hmac
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.actions.delivery import deliver_outbox_row
from apps.actions.handlers.webhook import deliver_webhook_action
from apps.actions.models import ActionOutbox, ActionRule
from apps.actions.webhook_retry import (
    compute_retry_delay_seconds,
    is_permanent_http_status,
    parse_retry_after_header,
)
from apps.actions.webhook_signing import (
    encode_webhook_envelope,
    generate_webhook_signing_secret,
    normalize_webhook_signing_secret,
    sign_webhook_body,
)
from apps.actions.webhook_transport import WebhookPostResult


class RetryClassificationTests(TestCase):
    def test_permanent_statuses(self):
        for code in (400, 401, 403, 405, 410, 413, 422):
            self.assertTrue(is_permanent_http_status(code))

    def test_n8n_404_is_retryable(self):
        self.assertFalse(is_permanent_http_status(404))

    def test_429_retryable(self):
        self.assertFalse(is_permanent_http_status(429))

    def test_5xx_retryable(self):
        self.assertFalse(is_permanent_http_status(503))

    def test_retry_after_seconds(self):
        self.assertEqual(parse_retry_after_header('120'), 120)

    def test_retry_after_honored_on_429(self):
        delay = compute_retry_delay_seconds(
            attempt_number=1,
            http_status=429,
            retry_after_seconds=900,
            base_backoff_seconds=30,
        )
        self.assertEqual(delay, 900)

    def test_retry_after_capped_at_one_hour(self):
        delay = compute_retry_delay_seconds(
            attempt_number=1,
            http_status=503,
            retry_after_seconds=99999,
            base_backoff_seconds=30,
        )
        self.assertEqual(delay, 3600)


class WebhookSigningTests(TestCase):
    def test_whsec_secret_matches_plain_when_configured(self):
        raw = b'super-secret-key-material!!'
        whsec = f'whsec_{base64.b64encode(raw).decode("ascii")}'
        self.assertEqual(normalize_webhook_signing_secret(whsec), raw)
        self.assertEqual(normalize_webhook_signing_secret('plain-text-secret'), b'plain-text-secret')

    def test_generate_whsec_prefix(self):
        self.assertTrue(generate_webhook_signing_secret().startswith('whsec_'))

    def test_unicode_payload_signature(self):
        envelope = {
            'id': 'evt-unicode',
            'type': 'storage.object.uploaded',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': 10, 'slug': '', 'name': ''},
            'data': {'path': 'docs/résumé.pdf'},
        }
        body = encode_webhook_envelope(envelope)
        self.assertIn('résumé.pdf'.encode('utf-8'), body)
        secret = generate_webhook_signing_secret()
        headers = sign_webhook_body(secret=secret, body=body, webhook_id='evt-unicode')
        key = normalize_webhook_signing_secret(secret)
        signed = f"{headers['webhook-id']}.{headers['webhook-timestamp']}.".encode() + body
        expected = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest()).decode()
        self.assertEqual(headers['webhook-signature'], f'v1,{expected}')


class WebhookDeliveryHeadersTests(TestCase):
    def setUp(self):
        self.company_id = 10
        self.rule = ActionRule.objects.create(
            company_id=self.company_id,
            name='n8n',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/hook', 'secret': 'plain-secret'},
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url')
    def test_shellui_headers_and_stable_webhook_id(self, mock_post):
        mock_post.return_value = WebhookPostResult(status=200, excerpt='')
        envelope = {
            'id': '550e8400-e29b-41d4-a716-446655440000',
            'type': 'storage.object.uploaded',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': 10, 'slug': '', 'name': ''},
            'data': {},
        }
        deliver_webhook_action(config=self.rule.config, envelope=envelope, attempt_number=3)
        headers = mock_post.call_args.kwargs['headers']
        self.assertEqual(headers['webhook-id'], envelope['id'])
        self.assertEqual(headers['X-Shellui-Event'], 'storage.object.uploaded')
        self.assertEqual(headers['X-Shellui-Delivery-Attempt'], '3')


class WebhookRetryIntegrationTests(TestCase):
    def setUp(self):
        self.company_id = 10
        self.rule = ActionRule.objects.create(
            company_id=self.company_id,
            name='n8n',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/hook', 'secret': 'sec'},
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url')
    def test_404_schedules_retry(self, mock_post):
        mock_post.return_value = WebhookPostResult(status=404, excerpt='not found')
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': 'x', 'type': 'storage.object.uploaded', 'data': {}},
        )
        deliver_outbox_row(row.pk)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_FAILED)
        self.assertIsNotNone(row.next_attempt_at)

    @patch('apps.actions.handlers.webhook.post_webhook_url')
    def test_403_goes_dead(self, mock_post):
        mock_post.return_value = WebhookPostResult(status=403, excerpt='forbidden')
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': 'x', 'type': 'storage.object.uploaded', 'data': {}},
        )
        deliver_outbox_row(row.pk)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DEAD)

    @patch('apps.actions.handlers.webhook.post_webhook_url')
    def test_429_retry_after(self, mock_post):
        mock_post.return_value = WebhookPostResult(status=429, excerpt='', retry_after_seconds=600)
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': 'x', 'type': 'storage.object.uploaded', 'data': {}},
        )
        before = timezone.now()
        deliver_outbox_row(row.pk)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_FAILED)
        self.assertGreaterEqual(row.next_attempt_at, before + timedelta(seconds=599))
