"""Django system checks for authapi."""

from django.conf import settings
from django.core.checks import Warning, register

from config.settings import _env_int


@register(deploy=True, tags='security')
def shared_cache_recommended_for_multi_worker(app_configs, **kwargs):
    if settings.DEBUG:
        return []
    backend = settings.CACHES.get('default', {}).get('BACKEND', '')
    if 'locmem' not in backend.lower():
        return []
    workers = _env_int('GUNICORN_WORKERS', 2)
    if workers <= 1:
        return []
    return [
        Warning(
            'LocMemCache is not shared across Gunicorn workers — cache-backed rate limits '
            'and throttles would be per-worker.',
            hint=(
                'Add a Redis service and set REDIS_URL (e.g. redis://redis:6379/0) on the '
                'storage-service container. LocMem is fine for single-worker or local dev.'
            ),
            id='authapi.W001',
        )
    ]
