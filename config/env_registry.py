"""Single source of truth for storage-service environment variables.

Pure Python: no Django settings, database, Redis or env needed. Used by
``manage.py generate_env``, to render ``.env.example``, and by the tests that
keep both in sync with ``config/settings.py``, the Docker entrypoint and
``docs/configuration.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

PLACEHOLDER = 'change-me'


@dataclass(frozen=True)
class Var:
    name: str
    default: str = ''
    group: str = ''


@dataclass(frozen=True)
class Required:
    """Required in production (DEBUG=false)."""

    name: str
    comment: str


REQUIRED = (
    Required('SECRET_KEY', 'Signs sessions and CSRF tokens. At least 50 characters. Generated.'),
    Required('DEBUG', 'Production mode.'),
    Required('ALLOWED_HOSTS', 'Public host names, comma-separated, no scheme.'),
    Required('CSRF_TRUSTED_ORIGINS', 'Full HTTPS origin, for Django admin form posts.'),
    Required('IDENTITY_SERVICE_URL', 'identity-service origin. JWKS is read from {url}/.well-known/jwks.json.'),
    Required('IDENTITY_ISSUER', 'Must match identity-service JWT_ISSUER.'),
    Required('IDENTITY_AUDIENCE', 'Must match identity-service JWT_AUDIENCE.'),
    Required('REDIS_URL', 'Shared cache and job broker.'),
    Required('POSTGRES_DATABASE_URL', 'PostgreSQL DSN. Leave empty to use SQLite.'),
)

OPTIONAL = (
    Var('LOG_LEVEL', 'INFO', 'Runtime'),
    Var('SETUP_TOKEN', ''),
    Var('DJANGO_ADMIN_ENABLED', 'true'),
    Var('STORAGE_SERVICE_PORT', '8001'),
    Var('POSTGRES_DATABASE_URL', '', 'Database: SQLite unless POSTGRES_DATABASE_URL is set'),
    Var('SQLITE_PATH', 'db.sqlite3'),
    Var('POSTGRES_SSL_REQUIRE', 'true'),
    Var('IDENTITY_JWKS_FILE', '', 'Identity and JWT. Pin the JWKS with a file or JSON in production.'),
    Var('IDENTITY_JWKS', ''),
    Var('IDENTITY_JWKS_URL', ''),
    Var('JWKS_CACHE_TTL', '900'),
    Var('JWKS_TIMEOUT', '15'),
    Var('JWKS_RETRIES', '2'),
    Var('JWT_ALGORITHMS', 'RS256'),
    Var('JWT_HS256_FALLBACK_SECRET', ''),
    Var('ALLOW_JWT_HS256_FALLBACK', 'false'),
    Var('STORAGE_BACKEND', 'filesystem', 'Object storage: filesystem or s3'),
    Var('MEDIA_ROOT', 'data/media'),
    Var('STORAGE_KEY_PREFIX', 'shellui'),
    Var('AWS_ACCESS_KEY_ID', ''),
    Var('AWS_SECRET_ACCESS_KEY', ''),
    Var('AWS_STORAGE_BUCKET_NAME', ''),
    Var('AWS_S3_REGION_NAME', 'us-east-1'),
    Var('AWS_S3_ENDPOINT_URL', ''),
    Var('AWS_S3_CUSTOM_DOMAIN', ''),
    Var('AWS_S3_SIGNATURE_VERSION', 's3v4'),
    Var('AWS_S3_ADDRESSING_STYLE', ''),
    Var('SIGNED_URL_EXPIRES', '3600'),
    Var('DEFAULT_COMPANY_QUOTA_BYTES', '10G', 'Quotas and uploads (K, M, G, T suffixes)'),
    Var('DEFAULT_USER_QUOTA_BYTES', '0'),
    Var('MAX_UPLOAD_BYTES', '5G'),
    Var('DATA_UPLOAD_MAX_MEMORY_SIZE', '12M'),
    Var('WEBDAV_ENABLED', 'true', 'WebDAV'),
    Var('WEBDAV_PATH_PREFIX', '/dav'),
    Var('SCHEDULER_ENABLED', 'true', 'Scheduled jobs'),
    Var('CELERY_BROKER_URL', ''),
    Var('CELERY_WORKER_CONCURRENCY', '2'),
    Var('CELERY_BEAT_SCHEDULE_FILE', '/tmp/celerybeat-schedule'),
    Var('CORS_ALLOW_ALL_ORIGINS', 'true', 'CORS and HTTPS'),
    Var('CORS_ALLOW_CREDENTIALS', 'false'),
    Var('CORS_ALLOWED_ORIGINS', ''),
    Var('CORS_ALLOW_PRIVATE_NETWORK', 'true'),
    Var('SECURE_SSL_REDIRECT', 'true'),
    Var('SECURE_HSTS_SECONDS', '31536000'),
    Var('SECURE_HSTS_INCLUDE_SUBDOMAINS', 'true'),
    Var('SECURE_HSTS_PRELOAD', 'false'),
    Var('SESSION_COOKIE_SECURE', 'true'),
    Var('CSRF_COOKIE_SECURE', 'true'),
    Var('ACTIONS_WEBHOOK_TIMEOUT_SECONDS', '5', 'Shellui Actions (outbound webhooks)'),
    Var('ACTIONS_OUTBOX_MAX_ATTEMPTS', '8'),
    Var('ACTIONS_WEBHOOK_ALLOW_PRIVATE', 'false'),
    Var('ACTIONS_WEBHOOK_RETRY_LEASE_SECONDS', '120'),
    Var('ACTIONS_WEBHOOK_DISPATCH_WORKERS', '4'),
    Var('ACTIONS_WEBHOOK_SYNC_DELIVERY', 'false'),
    Var('EVENT_LOG_RETENTION_DAYS', '7'),
    Var('EMAIL_SERVICE_API_KEY', '', 'Email notifications: nothing is forwarded while EMAIL_SERVICE_API_KEY is empty'),
    Var('EMAIL_SERVICE_URL', 'https://email.shellui.com'),
    Var('EMAIL_SERVICE_ALLOW_PRIVATE', 'false'),
    Var('SENTRY_DSN', '', 'Sentry'),
    Var('SENTRY_ENVIRONMENT', 'production'),
    Var('SENTRY_RELEASE', ''),
    Var('SENTRY_TRACES_SAMPLE_RATE', '0'),
    Var('GUNICORN_WORKERS', '2', 'Gunicorn (Docker entrypoint)'),
    Var('GUNICORN_THREADS', '2'),
    Var('GUNICORN_TIMEOUT', '120'),
    Var('GUNICORN_GRACEFUL_TIMEOUT', '30'),
    Var('GUNICORN_KEEP_ALIVE', '75'),
    Var('GUNICORN_MAX_REQUESTS', '1000'),
    Var('GUNICORN_MAX_REQUESTS_JITTER', '200'),
)

# Read by Docker Compose only, not by the app.
COMPOSE_ONLY = frozenset({'STORAGE_SERVICE_PORT'})


def all_names() -> set[str]:
    return {v.name for v in REQUIRED} | {v.name for v in OPTIONAL}


def optional_lines(skip: frozenset[str] = frozenset()) -> list[str]:
    """Commented-out optional vars with their default, grouped by topic."""
    lines: list[str] = []
    for var in OPTIONAL:
        if var.group:
            lines.extend(['', f'# {var.group}'])
        if var.name in skip:
            continue
        lines.append(f'# {var.name}={var.default}')
    return lines


_EXAMPLE_HEADER = """\
# storage-service settings. Full reference: docs/configuration.md
# Generated from config/env_registry.py: python manage.py generate_env --example > .env.example
# Production: python manage.py generate_env --host storage.example.com
# Copy to .env for local runs. Commented-out lines show the default the code uses.

# Required
# Signs sessions and CSRF tokens. At least 50 characters when DEBUG=false.
SECRET_KEY=
# Local development only. Unset means false (production).
DEBUG=true
# Public host names, comma-separated, no scheme.
ALLOWED_HOSTS=localhost,127.0.0.1
# Local identity-service. JWKS is read from {url}/.well-known/jwks.json.
IDENTITY_SERVICE_URL=http://localhost:8000

# Required when DEBUG=false (production)
IDENTITY_ISSUER=
IDENTITY_AUDIENCE=
REDIS_URL=
CSRF_TRUSTED_ORIGINS=

# Optional (defaults shown)"""


def render_example() -> str:
    """The content of ``.env.example`` (local development, no secrets)."""
    return '\n'.join([_EXAMPLE_HEADER, *optional_lines()]) + '\n'
