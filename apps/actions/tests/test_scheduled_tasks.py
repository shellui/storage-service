"""Celery tasks for the scheduled jobs, their Redis lock and the beat schedule."""

import time
from datetime import timedelta
from unittest import mock

import redis
from celery.schedules import crontab
from django.conf import settings
from django.test import SimpleTestCase, TestCase, override_settings

from apps.actions import tasks
from config.celery import app as celery_app
from config.task_lock import lock_key, task_lock


class FakeRedis:
    """The two Redis calls the lock uses: SET NX EX and the compare-and-delete script."""

    def __init__(self):
        self.store = {}
        self.set_calls = []

    def _expire(self):
        now = time.monotonic()
        for key in [k for k, (_, exp) in self.store.items() if exp <= now]:
            del self.store[key]

    def set(self, key, value, nx=False, ex=None):
        self.set_calls.append({'key': key, 'nx': nx, 'ex': ex})
        self._expire()
        if nx and key in self.store:
            return None
        self.store[key] = (value, time.monotonic() + (ex or 3600))
        return True

    def eval(self, script, numkeys, key, token):
        self._expire()
        if key in self.store and self.store[key][0] == token:
            del self.store[key]
            return 1
        return 0


class TaskLockTests(SimpleTestCase):
    def test_lock_uses_set_nx_with_ttl_and_service_prefix(self):
        fake = FakeRedis()
        with task_lock('job', ttl=120, client=fake) as acquired:
            self.assertTrue(acquired)
        self.assertEqual(
            fake.set_calls,
            [{'key': 'storage-service:scheduler:lock:job', 'nx': True, 'ex': 120}],
        )
        self.assertEqual(lock_key('job'), f'{settings.SCHEDULER_LOCK_PREFIX}:lock:job')

    def test_second_holder_is_refused_while_the_first_runs(self):
        fake = FakeRedis()
        with task_lock('job', ttl=60, client=fake) as first:
            with task_lock('job', ttl=60, client=fake) as second:
                self.assertTrue(first)
                self.assertFalse(second)
            # The refused run must not release the lock it never held.
            self.assertIn(lock_key('job'), fake.store)
        self.assertNotIn(lock_key('job'), fake.store)

    def test_released_after_an_exception(self):
        fake = FakeRedis()
        with self.assertRaises(RuntimeError):
            with task_lock('job', ttl=60, client=fake):
                raise RuntimeError('boom')
        with task_lock('job', ttl=60, client=fake) as acquired:
            self.assertTrue(acquired)

    def test_release_keeps_a_lock_taken_by_someone_else(self):
        fake = FakeRedis()
        with task_lock('job', ttl=60, client=fake):
            # Our TTL ran out and another run took the lock.
            fake.store[lock_key('job')] = ('other-token', time.monotonic() + 60)
        self.assertEqual(fake.store[lock_key('job')][0], 'other-token')

    def test_release_error_is_logged_not_raised(self):
        fake = FakeRedis()
        fake.eval = mock.Mock(side_effect=redis.ConnectionError('down'))
        with self.assertLogs('config.task_lock', level='WARNING'):
            with task_lock('job', ttl=60, client=fake) as acquired:
                self.assertTrue(acquired)

    def test_redis_down_on_acquire_fails_the_task(self):
        client = mock.Mock()
        client.set.side_effect = redis.ConnectionError('down')
        with self.assertRaises(redis.ConnectionError):
            with task_lock('job', ttl=60, client=client):
                self.fail('must not run without the lock')


class ScheduledTaskTests(TestCase):
    def setUp(self):
        self.fake = FakeRedis()
        patcher = mock.patch('config.task_lock.get_lock_client', return_value=self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    @mock.patch('apps.actions.management.commands.retry_webhooks.connection')
    @mock.patch('apps.actions.management.commands.retry_webhooks.retry_pending_webhooks')
    def test_retry_webhooks_runs_the_management_command(self, retry_webhooks, _conn):
        retry_webhooks.return_value = {'processed': 2, 'delivered': 1, 'retried': 1, 'dead': 0}

        with self.assertLogs('apps.actions.tasks', level='INFO') as logs:
            result = tasks.retry_webhooks.apply().get()

        retry_webhooks.assert_called_once_with(
            batch_size=50,
            max_seconds=50.0,
            concurrency=4,
            dry_run=False,
            scheduled_job_run_id=mock.ANY,
        )
        self.assertIsInstance(retry_webhooks.call_args.kwargs['scheduled_job_run_id'], int)
        self.assertTrue(result.startswith('retry_webhooks: processed=2 delivered=1'))
        self.assertIn('retry_webhooks: processed=2', logs.output[0])
        self.assertEqual(self.fake.set_calls[0]['ex'], tasks.RETRY_WEBHOOKS_LOCK_TTL)
        self.assertEqual(self.fake.store, {}, 'lock is released after the run')

    @mock.patch('apps.actions.management.commands.purge_expired_data.connection')
    @mock.patch('apps.actions.management.commands.purge_expired_data.purge_expired_data')
    def test_purge_expired_data_runs_with_max_seconds_300(self, purge, _conn):
        purge.return_value = {
            'events': 3,
            'webhook_deliveries': 0,
            'scheduled_job_runs': 0,
            'complete': True,
        }

        result = tasks.purge_expired_data.apply().get()

        purge.assert_called_once_with(batch_size=2000, max_seconds=300.0, dry_run=False)
        self.assertIn('deleted events=3', result)
        self.assertIn('scheduled_job_runs=0', result)
        self.assertIn('complete=true', result)
        self.assertEqual(self.fake.set_calls[0]['ex'], tasks.PURGE_EXPIRED_DATA_LOCK_TTL)
        self.assertGreater(tasks.PURGE_EXPIRED_DATA_LOCK_TTL, tasks.PURGE_EXPIRED_DATA_MAX_SECONDS)

    @mock.patch('apps.actions.tasks.call_command')
    def test_task_skips_while_another_run_holds_the_lock(self, call_command):
        for task, name in (
            (tasks.retry_webhooks, 'retry_webhooks'),
            (tasks.purge_expired_data, 'purge_expired_data'),
        ):
            with self.subTest(name=name):
                self.fake.set(lock_key(name), 'held-by-other-worker', ex=60)
                with self.assertLogs('apps.actions.tasks', level='INFO') as logs:
                    self.assertEqual(task.apply().get(), 'skipped')
                self.assertIn('skipped', logs.output[0])
        call_command.assert_not_called()

    def test_tasks_are_registered_under_the_beat_names(self):
        self.assertIn('actions.retry_webhooks', celery_app.tasks)
        self.assertIn('actions.purge_expired_data', celery_app.tasks)


class BeatScheduleTests(SimpleTestCase):
    def test_schedule_contents(self):
        schedule = settings.CELERY_BEAT_SCHEDULE
        self.assertEqual(set(schedule), {'retry-webhooks', 'purge-expired-data'})

        retry = schedule['retry-webhooks']
        self.assertEqual(retry['task'], 'actions.retry_webhooks')
        self.assertEqual(retry['schedule'], timedelta(seconds=60))
        self.assertLess(retry['options']['expires'], 60)

        purge = schedule['purge-expired-data']
        self.assertEqual(purge['task'], 'actions.purge_expired_data')
        self.assertIsInstance(purge['schedule'], crontab)
        self.assertEqual(purge['schedule'], crontab(minute=17))
        self.assertLess(purge['options']['expires'], 3600)

    def test_celery_app_reads_django_settings(self):
        conf = celery_app.conf
        self.assertEqual(conf.beat_schedule, settings.CELERY_BEAT_SCHEDULE)
        self.assertEqual(conf.task_default_queue, 'storage-service')
        self.assertEqual(conf.timezone, 'UTC')
        self.assertTrue(conf.task_ignore_result)
        self.assertFalse(conf.worker_hijack_root_logger)
        self.assertEqual(conf.accept_content, ['json'])

    @override_settings(CELERY_BROKER_URL='redis://broker:6379/2')
    def test_lock_client_uses_the_broker_url(self):
        with mock.patch('config.task_lock._client', None), mock.patch(
            'config.task_lock.redis.Redis.from_url'
        ) as from_url:
            from config.task_lock import get_lock_client

            get_lock_client()
        self.assertEqual(from_url.call_args.args[0], 'redis://broker:6379/2')
