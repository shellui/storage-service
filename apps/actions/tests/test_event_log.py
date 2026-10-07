import io
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
        self.assertEqual(list(EventLog.objects.filter(company_id=10).values_list('pk', flat=True)), [kept.pk])
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
        self.assertIn(
            'deleted events=1 webhook_deliveries=1 scheduled_job_runs=0 complete=true',
            out.getvalue(),
        )


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
)
class StorageApiEventTests(TestCase):
    """Each storage REST endpoint that changes objects records its event with the caller."""

    def setUp(self):
        from unittest.mock import patch

        from apps.storage.tests.test_storage import make_token

        self.client = APIClient()
        jwks_patch = patch('apps.authapi.authentication.get_jwks_client')
        jwks_patch.start().return_value.get_signing_key.return_value = None
        self.addCleanup(jwks_patch.stop)
        token = make_token(user_id=7, email='ada@acme.test', is_company_owner=True)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

    def _upload(self, path, method='post'):
        res = getattr(self.client, method)(
            f'/storage/v1/object/company/{path}', data=b'hello', content_type='text/plain'
        )
        self.assertEqual(res.status_code, 200, res.content)

    def test_every_endpoint_records_its_event(self):
        self.assertEqual(self.client.get('/storage/v1/bucket').status_code, 200)
        self._upload('docs/a.txt')
        self._upload('docs/a.txt', method='put')
        res = self.client.post(
            '/storage/v1/object/copy',
            {'sourceKey': 'company/docs/a.txt', 'destinationKey': 'company/docs/b.txt'},
            format='json',
        )
        self.assertEqual(res.status_code, 200, res.content)
        res = self.client.delete('/storage/v1/object/company/docs/b.txt')
        self.assertEqual(res.status_code, 200, res.content)
        res = self.client.delete('/storage/v1/object/company', {'prefixes': ['docs/a.txt']}, format='json')
        self.assertEqual(res.status_code, 200, res.content)
        self._upload('folder/x.txt')
        res = self.client.delete('/storage/v1/object/prefix/company', {'prefix': 'folder'}, format='json')
        self.assertEqual(res.status_code, 200, res.content)
        self._upload('y.txt')
        res = self.client.post('/storage/v1/bucket/company/empty')
        self.assertEqual(res.status_code, 200, res.content)

        self.assertEqual(
            list(EventLog.objects.order_by('pk').values_list('event_type', 'data__path')),
            [
                ('storage.bucket.created', None),
                ('storage.object.uploaded', 'docs/a.txt'),
                ('storage.object.uploaded', 'docs/a.txt'),
                ('storage.object.uploaded', 'docs/b.txt'),
                ('storage.object.deleted', 'docs/b.txt'),
                ('storage.object.deleted', 'docs/a.txt'),
                ('storage.object.uploaded', 'folder/x.txt'),
                ('storage.object.deleted', 'folder/x.txt'),
                ('storage.object.uploaded', 'y.txt'),
                ('storage.object.deleted', 'y.txt'),
            ],
        )
        self.assertEqual(
            set(EventLog.objects.values_list('company_id', 'user_id', 'data__actor_email')),
            {(10, 7, 'ada@acme.test')},
        )


@override_settings(STORAGE_BACKEND='filesystem', DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024)
class DjangoAdminDeleteTests(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model

        from apps.storage.access import ensure_company_bucket
        from apps.storage.services import upload_object

        self.bucket = ensure_company_bucket(company_id=1)
        self.objects = [
            upload_object(bucket=self.bucket, path=name, fileobj=io.BytesIO(b'x'), owner_id=1)
            for name in ('one.txt', 'two.txt', 'three.txt')
        ]
        EventLog.objects.all().delete()
        admin = get_user_model().objects.create_superuser('root', 'root@acme.test', 'pw')
        self.client.force_login(admin)

    def _deleted_paths(self):
        return sorted(EventLog.objects.filter(event_type='storage.object.deleted').values_list('data__path', flat=True))

    def test_object_delete_and_bulk_delete(self):
        one, two, _three = self.objects
        res = self.client.post(f'/admin/storage/storageobject/{one.pk}/delete/', {'post': 'yes'})
        self.assertEqual(res.status_code, 302)
        res = self.client.post(
            '/admin/storage/storageobject/',
            {'action': 'delete_selected', '_selected_action': [two.pk], 'post': 'yes'},
        )
        self.assertEqual(res.status_code, 302)
        self.assertEqual(self._deleted_paths(), ['one.txt', 'two.txt'])

    def test_bucket_delete_deletes_each_file(self):
        res = self.client.post(f'/admin/storage/bucket/{self.bucket.pk}/delete/', {'post': 'yes'})
        self.assertEqual(res.status_code, 302)
        self.assertEqual(self._deleted_paths(), ['one.txt', 'three.txt', 'two.txt'])
