"""n8n-oriented webhook signing, retry, and header behavior."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.actions.delivery import deliver_outbox_row
from apps.actions.handlers.webhook import deliver_webhook_action
from apps.actions.models import ActionOutbox, ActionRule
from apps.actions.webhook_body import serialize_webhook_envelope
from apps.actions.webhook_retry import (
    is_permanent_http_status,
    next_attempt_delay_seconds,
    parse_retry_after_seconds,
)
from apps.actions.webhook_signing import generate_webhook_signing_secret, sign_webhook_body, webhook_hmac_key


class RetrySemanticsTests(TestCase):
    def test_permanent_statuses(self):
        for code in (400, 401, 403, 405, 410, 413, 422):
            self.assertTrue(is_permanent_http_status(code), code)
        self.assertFalse(is_permanent_http_status(404))
        self.assertFalse(is_permanent_http_status(429))
        self.assertFalse(is_permanent_http_status(503))

    def test_parse_retry_after_seconds(self):
        self.assertEqual(parse_retry_after_seconds('120'), 120)

    def test_retry_after_honored_on_429(self):
        delay = next_attempt_delay_seconds(
            attempt_number=1,
            http_status=429,
            retry_after_seconds=900,
            backoff_seconds=30,
        )
        self.assertEqual(delay, 900)


class WebhookHandlerN8nTests(TestCase):
    def setUp(self):
        self.rule = ActionRule.objects.create(
            company_id=10,
            name='n8n',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/hook', 'secret': 'plain-secret'},
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=(404, 'inactive', None))
    def test_404_is_retryable(self, _mock):
        row = ActionOutbox.objects.create(
            company_id=10,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': 'x', 'type': 'storage.object.uploaded', 'data': {}},
        )
        deliver_outbox_row(row.pk)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_FAILED)
        self.assertIsNotNone(row.next_attempt_at)

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=(401, 'nope', None))
    def test_401_is_dead(self, _mock):
        row = ActionOutbox.objects.create(
            company_id=10,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': 'x', 'type': 'storage.object.uploaded', 'data': {}},
        )
        deliver_outbox_row(row.pk)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DEAD)

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=(200, '', None))
    def test_unicode_body_and_whsec_secret(self, mock_post):
        raw_key = b'\x01' * 32
        secret = 'whsec_' + base64.b64encode(raw_key).decode('ascii')
        envelope = {
            'id': 'evt-unicode',
            'type': 'storage.object.uploaded',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': 10, 'slug': '', 'name': ''},
            'data': {'path': 'docs/résumé.pdf', 'mime_type': 'application/pdf'},
        }
        deliver_webhook_action(
            config={'url': 'https://example.com/h', 'secret': secret},
            envelope=envelope,
            attempt_number=2,
        )
        body = mock_post.call_args.kwargs['body']
        self.assertIn('résumé.pdf'.encode('utf-8'), body)
        headers = mock_post.call_args.kwargs['headers']
        self.assertEqual(headers['webhook-id'], 'evt-unicode')
        self.assertEqual(headers['X-Shellui-Event'], 'storage.object.uploaded')
        self.assertEqual(headers['X-Shellui-Delivery-Attempt'], '2')
        signed = f"{headers['webhook-id']}.{headers['webhook-timestamp']}.".encode() + body
        expected = base64.b64encode(hmac.new(raw_key, signed, hashlib.sha256).digest()).decode()
        self.assertEqual(headers['webhook-signature'], f'v1,{expected}')

    def test_generate_whsec_roundtrip(self):
        secret = generate_webhook_signing_secret()
        self.assertTrue(secret.startswith('whsec_'))
        key = webhook_hmac_key(secret)
        self.assertEqual(len(key), 32)
        body = serialize_webhook_envelope({'ok': True})
        headers = sign_webhook_body(secret=secret, body=body, webhook_id='id-1')
        self.assertTrue(headers['webhook-signature'].startswith('v1,'))

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=(429, 'slow', 180))
    def test_retry_after_on_429_schedules_delay(self, _mock):
        row = ActionOutbox.objects.create(
            company_id=10,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': 'x', 'type': 'storage.object.uploaded', 'data': {}},
        )
        before = timezone.now()
        deliver_outbox_row(row.pk)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_FAILED)
        self.assertGreaterEqual(row.next_attempt_at, before + timedelta(seconds=179))
