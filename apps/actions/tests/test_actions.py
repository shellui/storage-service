import json
from datetime import timedelta
from unittest.mock import patch

from django.core.management import call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.actions.delivery import backoff_seconds, claim_next_pending_outbox, deliver_outbox_row
from apps.actions.emit import emit_event
from apps.actions.handlers.webhook import WebhookDeliveryError
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt
from apps.actions.ssrf import SSRFError, validate_webhook_url
from apps.actions.webhook_signing import encode_webhook_envelope, sign_webhook_body
from apps.actions.webhook_transport import WebhookPostResult


def _mock_ok(*_args, **_kwargs):
    return WebhookPostResult(status=200, excerpt='')


@override_settings(ACTIONS_WEBHOOK_SYNC_DELIVERY=True)
class EmitEventTests(TestCase):
    def setUp(self):
        self.company_a = 10
        self.company_b = 20
        ActionRule.objects.create(
            company_id=self.company_a,
            name='Hook',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/hook', 'secret': 'whsec_test'},
        )

    def test_unknown_event_type_raises(self):
        with self.assertRaises(ValueError):
            emit_event('not.real', self.company_a, {})

    def test_no_rules_returns_empty(self):
        rows = emit_event(
            'storage.object.uploaded',
            self.company_b,
            {'object_id': 'x'},
        )
        self.assertEqual(rows, [])
        self.assertEqual(ActionOutbox.objects.count(), 0)

    @patch('apps.actions.handlers.webhook.post_webhook_url', side_effect=_mock_ok)
    def test_emit_creates_outbox_and_delivers_on_commit(self, _mock_post):
        with self.captureOnCommitCallbacks(execute=True):
            rows = emit_event(
                'storage.object.uploaded',
                self.company_a,
                {'object_id': '9', 'path': 'a.txt', 'created': True},
            )
        self.assertEqual(len(rows), 1)
        row = ActionOutbox.objects.get(pk=rows[0].pk)
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)

    def test_company_isolation(self):
        emit_event('storage.object.uploaded', self.company_b, {'object_id': '1'})
        self.assertEqual(ActionOutbox.objects.count(), 0)


class WebhookHandlerTests(TestCase):
    def setUp(self):
        self.company_id = 10
        self.rule = ActionRule.objects.create(
            company_id=self.company_id,
            name='n8n',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            enabled=True,
            config={
                'url': 'https://example.com/hook',
                'secret': 'whsec_test',
            },
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url', side_effect=_mock_ok)
    def test_webhook_posts_signed_json(self, mock_post):
        envelope = {
            'id': 'evt-1',
            'type': 'storage.object.uploaded',
            'time': '2026-01-01T00:00:00+00:00',
            'company': {'id': self.company_id, 'slug': '', 'name': ''},
            'data': {'object_id': '1'},
        }
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type=envelope['type'],
            envelope=envelope,
        )
        deliver_outbox_row(row.pk)
        mock_post.assert_called_once()
        _args, kwargs = mock_post.call_args
        self.assertEqual(kwargs['body'], encode_webhook_envelope(envelope))
        headers = kwargs['headers']
        self.assertIn('webhook-signature', headers)
        self.assertIn('webhook-id', headers)
        self.assertEqual(headers['webhook-id'], 'evt-1')
        self.assertEqual(headers['X-Shellui-Delivery-Attempt'], '1')
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)

    @patch(
        'apps.actions.handlers.webhook.post_webhook_url',
        return_value=WebhookPostResult(status=500, excerpt='err'),
    )
    def test_webhook_failure_records_attempt(self, _mock_post):
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
        attempt = DeliveryAttempt.objects.get(outbox=row)
        self.assertEqual(attempt.http_status, 500)
        self.assertIn('HTTP 500', attempt.error_message)

    @patch(
        'apps.actions.handlers.webhook.post_webhook_url',
        return_value=WebhookPostResult(status=401, excerpt='unauthorized'),
    )
    def test_permanent_401_goes_dead(self, _mock_post):
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': 'x', 'type': 'storage.object.uploaded', 'data': {}},
        )
        deliver_outbox_row(row.pk)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DEAD)
        self.assertIsNone(row.next_attempt_at)

    def test_ssrf_blocks_private_ip(self):
        with self.assertRaises(SSRFError):
            validate_webhook_url('http://127.0.0.1/hook')
        with self.assertRaises(WebhookDeliveryError):
            from apps.actions.handlers.webhook import deliver_webhook_action

            deliver_webhook_action(
                config={'url': 'http://127.0.0.1/hook', 'secret': 'x'},
                envelope={'id': '1', 'type': 't', 'data': {}},
            )


class BackoffTests(TestCase):
    def test_backoff_sequence(self):
        self.assertEqual(backoff_seconds(1), 30)
        self.assertEqual(backoff_seconds(2), 60)
        self.assertEqual(backoff_seconds(3), 120)
        self.assertEqual(backoff_seconds(10), 3600)


@override_settings(ACTIONS_OUTBOX_MAX_ATTEMPTS=3)
class RetryDeliveryTests(TestCase):
    def setUp(self):
        self.company_id = 10
        self.rule = ActionRule.objects.create(
            company_id=self.company_id,
            name='hook',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url', return_value=WebhookPostResult(status=500, excerpt=''))
    def test_dead_after_max_attempts(self, _mock):
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': '1', 'type': 'storage.object.uploaded', 'data': {}},
        )
        for _ in range(3):
            deliver_outbox_row(row.pk)
            row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DEAD)


class RetryCommandTests(TestCase):
    def setUp(self):
        self.company_id = 10
        self.rule = ActionRule.objects.create(
            company_id=self.company_id,
            name='hook',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/h', 'secret': 's'},
        )

    @patch('apps.actions.handlers.webhook.post_webhook_url', side_effect=_mock_ok)
    def test_retry_command_processes_batch(self, _mock):
        ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': '1', 'type': 'storage.object.uploaded', 'data': {}},
            status=ActionOutbox.STATUS_FAILED,
            next_attempt_at=timezone.now(),
        )
        call_command('retry_webhooks', batch_size=10, max_seconds=5, concurrency=1)
        row = ActionOutbox.objects.get()
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)

    def test_dry_run_claims_without_http(self):
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': '1', 'type': 'storage.object.uploaded', 'data': {}},
            status=ActionOutbox.STATUS_PENDING,
        )
        with patch('apps.actions.delivery.deliver_outbox_row') as mock_deliver:
            call_command('retry_webhooks', batch_size=5, dry_run=True)
            mock_deliver.assert_not_called()
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_PENDING)

    def test_skip_locked_claim(self):
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': '1', 'type': 'storage.object.uploaded', 'data': {}},
            status=ActionOutbox.STATUS_FAILED,
            next_attempt_at=timezone.now(),
            locked_until=timezone.now() + timedelta(minutes=5),
        )
        claimed = claim_next_pending_outbox()
        self.assertIsNone(claimed)
        row.refresh_from_db()
        self.assertIsNotNone(row.locked_until)

    def test_stale_lease_reclaimed(self):
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=self.rule,
            event_type='storage.object.uploaded',
            envelope={'id': '1', 'type': 'storage.object.uploaded', 'data': {}},
            status=ActionOutbox.STATUS_FAILED,
            next_attempt_at=timezone.now(),
            locked_until=timezone.now() - timedelta(seconds=30),
        )
        claimed = claim_next_pending_outbox()
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed.pk, row.pk)

    def test_claim_email_row_without_action_rule_on_postgres(self):
        """FOR UPDATE must not cover the nullable action_rule outer join."""
        if connection.vendor != 'postgresql':
            self.skipTest('SQLite ignores FOR UPDATE')
        row = ActionOutbox.objects.create(
            company_id=self.company_id,
            action_rule=None,
            delivery_kind=ActionOutbox.KIND_EMAIL,
            event_type='storage.object.uploaded',
            envelope={'event_type': 'storage.object.uploaded', 'payload': {}},
            status=ActionOutbox.STATUS_FAILED,
            next_attempt_at=timezone.now(),
        )
        claimed = claim_next_pending_outbox()
        self.assertIsNotNone(claimed)
        self.assertEqual(claimed.pk, row.pk)
        self.assertIsNone(claimed.action_rule_id)
        delivered = deliver_outbox_row(row.pk)
        self.assertIsNotNone(delivered)
        self.assertEqual(delivered.status, ActionOutbox.STATUS_DEAD)
        self.assertIn('not configured', delivered.last_error)


class WebhookSigningTests(TestCase):
    def test_signature_format(self):
        body = b'{"ok":true}'
        headers = sign_webhook_body(secret='secret', body=body, webhook_id='id-1')
        self.assertTrue(headers['webhook-signature'].startswith('v1,'))
