from datetime import timedelta
from io import StringIO
from types import SimpleNamespace

import jwt
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.actions.emit import emit_event
from apps.actions.models import ActionOutbox, ActionRule, EventLog
from apps.actions.retention import purge_expired_data, retention_status
from apps.storage.models import FOLDER_PLACEHOLDER_NAME
from apps.storage.signals import storage_object_deleted, storage_object_uploaded


def _log(company_id=10, event_type='storage.object.uploaded', *, days_ago=0.0, user_id=None, data=None):
    return EventLog.objects.create(
        company_id=company_id,
        user_id=user_id,
        event_type=event_type,
        data=data or {},
        created_at=timezone.now() - timedelta(days=days_ago),
    )


def _token(*, company_id=10, owner=True):
    return jwt.encode(
        {
            'sub': '1',
            'user_id': 1,
            'company_id': company_id,
            'email': 'owner@example.com',
            'user_metadata': {'is_staff': False, 'is_company_owner': owner},
            'exp': 2**31 - 1,
        },
        'test-secret',
        algorithm='HS256',
    )


class RecordEventTests(TestCase):
    def test_emit_records_event_without_webhook_rule(self):
        emit_event(
            'storage.object.uploaded',
            10,
            {'object_id': 'abc', 'path': 'a.txt', 'mime_type': '', 'created': False},
            actor={'user_id': 7, 'email': 'ada@example.com'},
        )
        row = EventLog.objects.get()
        self.assertEqual((row.company_id, row.user_id, row.event_type), (10, 7, 'storage.object.uploaded'))
        self.assertEqual(row.data, {'object_id': 'abc', 'path': 'a.txt', 'actor_email': 'ada@example.com'})
        self.assertEqual(ActionOutbox.objects.count(), 0)

    def test_upload_and_delete_signals_are_logged(self):
        request = SimpleNamespace(user=SimpleNamespace(is_authenticated=True, user_id=7, email='ada@example.com'))
        obj = SimpleNamespace(
            id='obj-1',
            name='docs/report.pdf',
            company_id=10,
            bucket=SimpleNamespace(name='company', kind='company'),
            size=12,
            mime_type='application/pdf',
            version=1,
        )
        storage_object_uploaded.send(sender=None, instance=obj, created=True, request=request)
        storage_object_deleted.send(
            sender=None,
            bucket_name='company',
            object_name='docs/report.pdf',
            company_id=10,
            mime_type='application/pdf',
            size=12,
            request=request,
        )
        rows = list(EventLog.objects.order_by('pk').values_list('event_type', 'user_id', 'data__path'))
        self.assertEqual(
            rows,
            [
                ('storage.object.uploaded', 7, 'docs/report.pdf'),
                ('storage.object.deleted', 7, 'docs/report.pdf'),
            ],
        )

    def test_folder_placeholders_are_not_logged(self):
        obj = SimpleNamespace(
            name=f'docs/{FOLDER_PLACEHOLDER_NAME}',
            company_id=10,
            bucket=SimpleNamespace(name='company', kind='company'),
            size=0,
            mime_type='',
        )
        storage_object_uploaded.send(sender=None, instance=obj, created=True)
        self.assertFalse(EventLog.objects.exists())


@override_settings(
    ALLOWED_HOSTS=['testserver'],
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
)
class EventLogApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {_token()}')

    def _get(self, path, **params):
        return self.client.get(f'/api/v1/actions/event-log{path}', params)

    def test_list_newest_first_and_company_scoped(self):
        old = _log(days_ago=2)
        new = _log(event_type='storage.object.deleted')
        _log(company_id=99)
        response = self._get('')
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r['id'] for r in response.data['results']], [new.pk, old.pk])
        self.assertEqual(response.data['results'][0]['label'], 'Object deleted')

    def test_filters(self):
        mine = _log(user_id=7, data={'actor_email': 'ada@example.com'}, days_ago=1)
        deleted = _log(event_type='storage.object.deleted')
        old = _log(days_ago=5)

        def ids(**params):
            return [r['id'] for r in self._get('', **params).data['results']]

        self.assertEqual(ids(user_id=7), [mine.pk])
        self.assertEqual(ids(user='ADA@'), [mine.pk])
        self.assertEqual(ids(event_type='storage.object.deleted'), [deleted.pk])
        self.assertEqual(ids(created_before=(timezone.now() - timedelta(days=3)).isoformat()), [old.pk])
        self.assertEqual(self._get('', event_type='nope').status_code, 400)
        self.assertEqual(self._get('').data['results'][0]['user_email'], None)
        self.assertEqual(self._get('', user_id=7).data['results'][0]['user_email'], 'ada@example.com')

    def test_detail_types_and_retention(self):
        mine = _log()
        theirs = _log(company_id=99)
        self.assertEqual(self._get(f'/{mine.pk}').status_code, 200)
        self.assertEqual(self._get(f'/{theirs.pk}').status_code, 404)
        types = {r['type'] for r in self._get('/types').data['results']}
        self.assertIn('storage.object.uploaded', types)
        self.assertFalse(self._get('/retention').data['stale_events'])
        _log(days_ago=8.5)
        data = self._get('/retention').data
        self.assertTrue(data['stale_events'])
        self.assertEqual(data['data_retention_days'], 7)

    def test_non_owner_is_forbidden(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {_token(owner=False)}')
        self.assertEqual(self._get('').status_code, 403)


class PurgeExpiredDataTests(TestCase):
    def setUp(self):
        rule = ActionRule.objects.create(
            company_id=10,
            name='Hook',
            event_type='storage.object.uploaded',
            config={'url': 'https://example.com/hook'},
        )
        self.done = ActionOutbox.objects.create(
            company_id=10, action_rule=rule, event_type='x', envelope={}, status=ActionOutbox.STATUS_DELIVERED
        )
        self.pending = ActionOutbox.objects.create(
            company_id=10, action_rule=rule, event_type='x', envelope={}, status=ActionOutbox.STATUS_PENDING
        )
        ActionOutbox.objects.update(created_at=timezone.now() - timedelta(days=10))

    def test_purge_deletes_expired_rows_only(self):
        _log(days_ago=8)
        kept = _log(days_ago=6)
        stats = purge_expired_data(batch_size=1)
        self.assertEqual((stats['events'], stats['webhook_deliveries'], stats['complete']), (1, 1, True))
        self.assertEqual(list(EventLog.objects.values_list('pk', flat=True)), [kept.pk])
        self.assertEqual(list(ActionOutbox.objects.values_list('pk', flat=True)), [self.pending.pk])

    @override_settings(EVENT_LOG_RETENTION_DAYS=30)
    def test_retention_setting(self):
        _log(days_ago=8)
        self.assertEqual(purge_expired_data()['events'], 0)
        self.assertEqual(retention_status(10)['data_retention_days'], 30)

    def test_dry_run_and_command(self):
        _log(days_ago=8)
        self.assertEqual(purge_expired_data(dry_run=True)['events'], 1)
        self.assertEqual(EventLog.objects.count(), 1)
        out = StringIO()
        call_command('purge_expired_data', stdout=out)
        self.assertIn('deleted events=1 webhook_deliveries=1 complete=true', out.getvalue())
