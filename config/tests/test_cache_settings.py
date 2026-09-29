from django.conf import settings
from django.test import SimpleTestCase, override_settings

from apps.authapi.checks import shared_cache_recommended_for_multi_worker
from config.settings import _caches_config


class CachesConfigTests(SimpleTestCase):
    def test_locmem_when_redis_url_empty(self):
        caches = _caches_config('')
        self.assertEqual(
            caches['default']['BACKEND'],
            'django.core.cache.backends.locmem.LocMemCache',
        )
        self.assertEqual(caches['default']['LOCATION'], 'identity-service-auth')

    def test_redis_when_redis_url_set(self):
        url = 'redis://127.0.0.1:6379/1'
        caches = _caches_config(url)
        self.assertEqual(
            caches['default']['BACKEND'],
            'django.core.cache.backends.redis.RedisCache',
        )
        self.assertEqual(caches['default']['LOCATION'], url)

    def test_loaded_settings_default_to_locmem_without_redis_url(self):
        backend = settings.CACHES['default']['BACKEND']
        self.assertIn('LocMem', backend)


class SharedCacheDeployCheckTests(SimpleTestCase):
    @override_settings(DEBUG=False, CACHES=_caches_config(''))
    def test_warns_locmem_with_multiple_gunicorn_workers(self):
        import os

        prev = os.environ.get('GUNICORN_WORKERS')
        os.environ['GUNICORN_WORKERS'] = '2'
        try:
            warnings = shared_cache_recommended_for_multi_worker(None)
        finally:
            if prev is None:
                os.environ.pop('GUNICORN_WORKERS', None)
            else:
                os.environ['GUNICORN_WORKERS'] = prev
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].id, 'authapi.W001')

    @override_settings(DEBUG=False, CACHES=_caches_config('redis://redis:6379/0'))
    def test_silent_when_redis_configured(self):
        warnings = shared_cache_recommended_for_multi_worker(None)
        self.assertEqual(warnings, [])

    @override_settings(DEBUG=False, CACHES=_caches_config(''))
    def test_silent_for_single_worker_production(self):
        import os

        prev = os.environ.get('GUNICORN_WORKERS')
        os.environ['GUNICORN_WORKERS'] = '1'
        try:
            warnings = shared_cache_recommended_for_multi_worker(None)
        finally:
            if prev is None:
                os.environ.pop('GUNICORN_WORKERS', None)
            else:
                os.environ['GUNICORN_WORKERS'] = prev
        self.assertEqual(warnings, [])
