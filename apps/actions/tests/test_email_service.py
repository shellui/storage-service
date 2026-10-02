import json
import logging
import sys
from datetime import timedelta
from unittest.mock import patch

import jwt
import requests
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.actions.company import CompanyContext
from apps.authapi.jwks_client import reset_jwks_client
from apps.actions.delivery import deliver_outbox_row
from apps.actions.email_service import (
    EMAIL_EVENT_ENVELOPE_KEY,
    RedactEmailServiceApiKeyFilter,
    RedactEmailServiceApiKeyFormatter,
    email_failure_is_permanent,
)
from apps.actions.emit import emit_event
from apps.actions.models import ActionOutbox, ActionRule, DeliveryAttempt

_API_KEY = 'esk_test_storage_email_key'  # gitleaks:allow

_EMAIL_SETTINGS = {
    'EMAIL_SERVICE_URL': 'https://email.test',
    'EMAIL_SERVICE_API_KEY': _API_KEY,
    'ACTIONS_WEBHOOK_SYNC_DELIVERY': True,
}


def _response(status, payload=None, headers=None):
    class _Response:
        def __init__(self):
            self.status_code = status
            self._payload = {} if payload is None else payload
            self.headers = headers or {}
            self.text = json.dumps(self._payload)

        def json(self):
            return self._payload

        def close(self):
            return None

    return _Response()


def _owner_token(*, company_id: int = 42) -> str:
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


def _emit(**kwargs):
    payload = {
        'bucket_name': 'company',
        'path': 'docs/report.pdf',
        'mime_type': 'application/pdf',
        'object_id': '550e8400-e29b-41d4-a716-446655440000',
        'size': 4096,
    }
    payload.update(kwargs.pop('payload', {}))
    return emit_event(
        'storage.object.uploaded',
        42,
        payload,
        company=CompanyContext(id=42, name='Acme'),
        actor={'user_id': 7, 'email': 'ada@acme.com'},
        **kwargs,
    )


@override_settings(**_EMAIL_SETTINGS)
class EmailEventForwardTests(TestCase):
    @patch('apps.actions.email_service.requests.post')
    def test_forwards_event_with_contract_shape(self, mock_post):
        mock_post.return_value = _response(202, {'rule_enabled': False, 'skipped_reason': 'rule_disabled', 'messages': []})
        with self.captureOnCommitCallbacks(execute=True):
            rows = _emit()
        self.assertEqual(len(rows), 1)
        row = ActionOutbox.objects.get()
        self.assertIsNone(row.action_rule_id)
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)
        mock_post.assert_called_once()
        _args, kwargs = mock_post.call_args
        self.assertEqual(_args[0], 'https://email.test/api/v1/events')
        self.assertFalse(kwargs['allow_redirects'])
        self.assertEqual(kwargs['headers']['Authorization'], f'Bearer {_API_KEY}')
        self.assertEqual(kwargs['headers']['Content-Type'], 'application/json; charset=utf-8')
        body = json.loads(kwargs['data'])
        self.assertEqual(
            body,
            {
                'company_id': 42,
                'event_type': 'storage.object.uploaded',
                'idempotency_key': str(row.pk),
                'payload': {
                    'bucket_name': 'company',
                    'company_name': 'Acme',
                    'mime_type': 'application/pdf',
                    'object_id': '550e8400-e29b-41d4-a716-446655440000',
                    'path': 'docs/report.pdf',
                    'size': 4096,
                },
                'recipients': [{'email': 'ada@acme.com', 'user_id': 7}],
                'service': 'storage',
            },
        )
        self.assertEqual(row.envelope[EMAIL_EVENT_ENVELOPE_KEY]['idempotency_key'], str(row.pk))

    @patch('apps.actions.email_service.requests.post')
    def test_missing_actor_sends_empty_recipient_hints(self, mock_post):
        mock_post.return_value = _response(202, {'messages': []})
        with self.captureOnCommitCallbacks(execute=True):
            emit_event(
                'storage.bucket.created',
                42,
                {'bucket_name': 'company', 'bucket_kind': 'company'},
            )
        body = json.loads(mock_post.call_args.kwargs['data'])
        self.assertEqual(body['service'], 'storage')
        self.assertEqual(body['event_type'], 'storage.bucket.created')
        self.assertEqual(body['recipients'], [])
        self.assertEqual(body['payload']['bucket_name'], 'company')
        self.assertNotIn('company_name', body['payload'])
        self.assertNotIn('language', body)

    @patch('apps.actions.email_service.requests.post')
    def test_http_waits_until_commit(self, mock_post):
        mock_post.return_value = _response(202, {})
        with self.captureOnCommitCallbacks(execute=False):
            _emit()
        mock_post.assert_not_called()
        self.assertEqual(ActionOutbox.objects.count(), 1)

    @patch('apps.actions.handlers.webhook.post_webhook_url')
    @patch('apps.actions.email_service.requests.post')
    def test_webhook_and_email_both_deliver(self, mock_post, mock_webhook):
        from apps.actions.webhook_transport import WebhookPostResult

        mock_post.return_value = _response(202, {'rule_enabled': True, 'messages': []})
        mock_webhook.return_value = WebhookPostResult(status=200, excerpt='')
        ActionRule.objects.create(
            company_id=42,
            name='Hook',
            event_type='storage.object.uploaded',
            action_kind=ActionRule.ACTION_WEBHOOK,
            config={'url': 'https://example.com/hook', 'secret': 'whsec_test'},
        )
        with self.captureOnCommitCallbacks(execute=True):
            rows = _emit()
        self.assertEqual(len(rows), 2)
        self.assertEqual(ActionOutbox.objects.filter(status=ActionOutbox.STATUS_DELIVERED).count(), 2)
        mock_post.assert_called_once()
        mock_webhook.assert_called_once()

    @patch('apps.actions.email_service.requests.post')
    def test_retry_posts_the_same_body(self, mock_post):
        mock_post.side_effect = [
            _response(500, {'error_code': 'request_failed'}),
            _response(202, {'rule_enabled': False, 'messages': []}),
        ]
        with self.captureOnCommitCallbacks(execute=True):
            _emit()
        row = ActionOutbox.objects.get()
        self.assertEqual(row.status, ActionOutbox.STATUS_FAILED)
        self.assertIsNotNone(row.next_attempt_at)
        row.next_attempt_at = timezone.now() - timedelta(seconds=1)
        row.save(update_fields=['next_attempt_at'])
        call_command('retry_webhooks', batch_size=10, max_seconds=5, concurrency=1)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DELIVERED)
        self.assertEqual(mock_post.call_count, 2)
        first = mock_post.call_args_list[0].kwargs['data']
        second = mock_post.call_args_list[1].kwargs['data']
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)['idempotency_key'], str(row.pk))

    @patch('apps.actions.email_service.requests.post')
    def test_lane_paused_and_rate_limit_retry(self, mock_post):
        mock_post.return_value = _response(409, {'error_code': 'lane_paused'})
        with self.captureOnCommitCallbacks(execute=True):
            _emit()
        row = ActionOutbox.objects.get()
        self.assertEqual(row.status, ActionOutbox.STATUS_FAILED)
        row.status = ActionOutbox.STATUS_PENDING
        row.attempt_count = 0
        row.next_attempt_at = None
        row.save()
        mock_post.return_value = _response(429, {'error_code': 'company_rate_limited'}, headers={'Retry-After': '90'})
        deliver_outbox_row(row.pk)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_FAILED)
        self.assertGreaterEqual(row.next_attempt_at, timezone.now() + timedelta(seconds=60))

    @patch('apps.actions.email_service.requests.post')
    def test_client_error_is_dead_and_not_retried(self, mock_post):
        mock_post.return_value = _response(400, {'error_code': 'validation_failed'})
        with self.captureOnCommitCallbacks(execute=True):
            _emit()
        row = ActionOutbox.objects.get()
        self.assertEqual(row.status, ActionOutbox.STATUS_DEAD)
        call_command('retry_webhooks', batch_size=10, max_seconds=5, concurrency=1)
        self.assertEqual(mock_post.call_count, 1)
        row.refresh_from_db()
        self.assertEqual(row.status, ActionOutbox.STATUS_DEAD)

    @patch('apps.actions.email_service.requests.post')
    def test_connection_error_retries_without_logging_api_key(self, mock_post):
        mock_post.side_effect = requests.ConnectionError(f'connection failed for {_API_KEY}')
        with self.assertLogs('apps.actions.email_service', level='WARNING') as captured:
            with self.captureOnCommitCallbacks(execute=True):
                _emit()
        blob = '\n'.join(captured.output)
        self.assertNotIn(_API_KEY, blob)
        self.assertIn('[redacted]', blob)
        row = ActionOutbox.objects.get()
        self.assertEqual(row.status, ActionOutbox.STATUS_FAILED)
        self.assertNotIn(_API_KEY, row.last_error)
        attempt = DeliveryAttempt.objects.get(outbox=row)
        self.assertNotIn(_API_KEY, attempt.error_message)
        self.assertIsNone(attempt.http_status)

    def test_formatter_redacts_traceback(self):
        formatter = RedactEmailServiceApiKeyFormatter('%(message)s')
        try:
            raise RuntimeError(f'header Bearer {_API_KEY}')
        except RuntimeError:
            record = logging.LogRecord(
                name='apps.actions.email_service',
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg='email_event crashed',
                args=(),
                exc_info=sys.exc_info(),
            )
        rendered = formatter.format(record)
        self.assertNotIn(_API_KEY, rendered)
        self.assertIn('[redacted]', rendered)

    def test_log_filter_redacts_message_and_args(self):
        record = logging.LogRecord(
            name='apps.actions.email_service',
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg='auth %s',
            args=(_API_KEY,),
            exc_info=None,
        )
        self.assertTrue(RedactEmailServiceApiKeyFilter().filter(record))
        self.assertNotIn(_API_KEY, record.getMessage())


class EmailEventUnconfiguredTests(TestCase):
    @override_settings(EMAIL_SERVICE_API_KEY='', EMAIL_SERVICE_URL='https://email.shellui.com')
    @patch('apps.actions.email_service.requests.post')
    def test_no_key_sends_nothing(self, mock_post):
        with self.captureOnCommitCallbacks(execute=True):
            rows = _emit()
        self.assertEqual(rows, [])
        self.assertEqual(ActionOutbox.objects.count(), 0)
        mock_post.assert_not_called()

    @override_settings(EMAIL_SERVICE_API_KEY='   ', ACTIONS_WEBHOOK_SYNC_DELIVERY=True)
    @patch('apps.actions.email_service.requests.post')
    def test_blank_key_sends_nothing(self, mock_post):
        with self.captureOnCommitCallbacks(execute=True):
            _emit()
        mock_post.assert_not_called()

    @override_settings(**_EMAIL_SETTINGS)
    @patch('apps.actions.email_service.requests.post')
    def test_email_rows_are_hidden_from_webhook_delivery_api(self, mock_post):
        mock_post.return_value = _response(202, {})
        with self.captureOnCommitCallbacks(execute=True):
            _emit()
        row = ActionOutbox.objects.get()
        reset_jwks_client()
        try:
            with override_settings(
                ALLOWED_HOSTS=['testserver'],
                JWT_HS256_FALLBACK_SECRET='test-secret',
                ALLOW_JWT_HS256_FALLBACK=True,
                JWKS_RETRIES=0,
                JWKS_TIMEOUT=0.2,
            ):
                client = APIClient()
                client.credentials(HTTP_AUTHORIZATION=f'Bearer {_owner_token()}')
                listed = client.get('/api/v1/actions/deliveries?company_id=42')
                detail = client.get(f'/api/v1/actions/deliveries/{row.pk}?company_id=42')
        finally:
            reset_jwks_client()
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data['count'], 0)
        self.assertEqual(detail.status_code, 404)


class EmailFailureClassificationTests(TestCase):
    def test_permanent_statuses(self):
        self.assertFalse(email_failure_is_permanent(None, ''))
        self.assertFalse(email_failure_is_permanent(202, ''))
        self.assertFalse(email_failure_is_permanent(429, 'company_rate_limited'))
        self.assertFalse(email_failure_is_permanent(409, 'lane_paused'))
        self.assertFalse(email_failure_is_permanent(503, 'request_failed'))
        self.assertTrue(email_failure_is_permanent(400, 'validation_failed'))
        self.assertTrue(email_failure_is_permanent(401, 'unauthorized'))
        self.assertTrue(email_failure_is_permanent(403, 'forbidden'))
        self.assertTrue(email_failure_is_permanent(404, 'unknown_event'))
        self.assertTrue(email_failure_is_permanent(409, 'idempotency_conflict'))
        self.assertTrue(email_failure_is_permanent(422, 'recipient_suppressed'))
        self.assertTrue(email_failure_is_permanent(302, ''))
