"""Django system checks for authapi."""

from django.conf import settings
from django.core.checks import Error, Warning, register
from django.core.exceptions import ImproperlyConfigured

from config.settings import _env_int

REDIS_URL_REQUIRED_MESSAGE = 'REDIS_URL is required when DEBUG is false (example: redis://redis:6379/0).'

SECRET_KEY_MIN_LENGTH = 50
# Published example values. A longer copy that still starts with one of these is the same placeholder.
_PLACEHOLDER_SECRET_PREFIXES = (
    'django-insecure-',
    'change-me-generate-a-strong-secret-key',
)
_PLACEHOLDER_SECRET_KEYS = frozenset(
    {
        'changeme',
        'change-me',
        'secret',
        'password',
    }
)
_SECRET_KEY_MESSAGES = {
    'empty': 'SECRET_KEY is empty.',
    'placeholder': (
        'SECRET_KEY is a published placeholder '
        '(a django-insecure- prefix or change-me-generate-a-strong-secret-key).'
    ),
    'short': f'SECRET_KEY is shorter than {SECRET_KEY_MIN_LENGTH} characters.',
}
_SECRET_KEY_HINT = (
    'Generate a key with django.core.management.utils.get_random_secret_key and set SECRET_KEY. '
    '.env.example leaves SECRET_KEY empty.'
)


def secret_key_problem(secret_key: str | None) -> str | None:
    """Return empty, placeholder, or short when the key must not sign sessions."""
    key = '' if secret_key is None else str(secret_key).strip()
    if not key:
        return 'empty'
    folded = key.casefold()
    if folded.startswith(_PLACEHOLDER_SECRET_PREFIXES) or folded in _PLACEHOLDER_SECRET_KEYS:
        return 'placeholder'
    if len(key) < SECRET_KEY_MIN_LENGTH:
        return 'short'
    return None


@register(deploy=True, tags='caches')
def redis_required_in_production(app_configs, **kwargs):
    """
    Production needs Redis: the shared cache and the scheduled jobs broker. LocMem is
    per process, so a cache is not shared across Gunicorn workers, and the in-container
    scheduler has no broker.

    A deploy check, so `check --deploy` (run by the Docker entrypoint, and in CI) fails,
    while tests and other management commands still run. The entrypoint also exits
    early with the same message before migrations. See tools/docker-entrypoint.sh.
    """
    if settings.DEBUG:
        return []
    if (getattr(settings, 'REDIS_URL', '') or '').strip():
        return []
    return [
        Error(
            REDIS_URL_REQUIRED_MESSAGE,
            hint=(
                'Add a Redis service and set REDIS_URL on every storage-service container '
                '(web and worker), also with SCHEDULER_ENABLED=false: Redis backs the shared '
                'cache and the scheduled jobs. Use DEBUG=true only for local development '
                'without Redis.'
            ),
            id='authapi.E004',
        )
    ]


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


@register(tags='security')
def secret_key_strength_when_debug_disabled(app_configs, **kwargs):
    """
    Refuse a placeholder, empty, or short SECRET_KEY when DEBUG is false.

    Django's security.W009 is only a deploy warning. This is an error on
    `manage.py check`, which `check --deploy` (the container entrypoint) includes.
    An empty key also fails at import, before checks run.

    The test runner forces DEBUG false and then runs `check`. It substitutes a
    long key for that one call so a local dev key does not fail the suite.
    """
    if settings.DEBUG:
        return []
    try:
        secret_key = settings.SECRET_KEY
    except ImproperlyConfigured:
        secret_key = ''
    problem = secret_key_problem(secret_key)
    if problem is None:
        return []
    return [
        Error(
            _SECRET_KEY_MESSAGES[problem],
            hint=_SECRET_KEY_HINT,
            id='authapi.E005',
        )
    ]
