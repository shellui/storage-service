import os
import subprocess
import sys

from django.conf import settings
from django.test import SimpleTestCase

from config.settings import _celery_broker_url


class CeleryBrokerUrlTests(SimpleTestCase):
    def test_defaults_to_redis_url(self):
        self.assertEqual(_celery_broker_url('redis://redis:6379/0', ''), 'redis://redis:6379/0')

    def test_celery_broker_url_overrides(self):
        self.assertEqual(
            _celery_broker_url('redis://redis:6379/0', ' redis://broker:6379/3 '),
            'redis://broker:6379/3',
        )

    def test_empty_without_redis(self):
        self.assertEqual(_celery_broker_url('', ''), '')

    def test_scheduler_enabled_by_default(self):
        if os.environ.get('SCHEDULER_ENABLED', '').strip():
            self.skipTest('SCHEDULER_ENABLED is set in this environment')
        self.assertTrue(settings.SCHEDULER_ENABLED)


class CeleryLoggingTests(SimpleTestCase):
    def test_celery_logs_go_to_stdout_handler(self):
        loggers = settings.LOGGING['loggers']
        for name in ('celery', 'celery.app.trace', 'celery.worker.strategy'):
            with self.subTest(logger=name):
                self.assertEqual(loggers[name]['handlers'], ['console'])
        self.assertNotEqual(loggers['celery']['level'], 'DEBUG')


class SentryCeleryIntegrationTests(SimpleTestCase):
    def test_celery_integration_enabled_with_sentry_dsn(self):
        # Settings run sentry_sdk.init at import, so check in a fresh interpreter.
        code = (
            'import django, sentry_sdk; django.setup(); '
            'print(sorted(sentry_sdk.get_client().integrations))'
        )
        env = dict(os.environ)
        env.update(
            {
                'DJANGO_SETTINGS_MODULE': 'config.settings',
                'SENTRY_DSN': 'https://public@sentry.invalid/1',
                'SECRET_KEY': settings.SECRET_KEY,
                'DEBUG': 'true',
                'STORAGE_BACKEND': 'filesystem',
                'IDENTITY_JWKS_URL': 'http://localhost:8000/.well-known/jwks.json',
            }
        )
        result = subprocess.run(
            [sys.executable, '-c', code],
            cwd=settings.BASE_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("'celery'", result.stdout)
        self.assertIn("'django'", result.stdout)
