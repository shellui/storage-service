"""
Django settings for ShellUI storage-service.
"""

from __future__ import annotations

import logging
import os
import re
import tomllib
from datetime import timedelta
from pathlib import Path

import dj_database_url
from dotenv import load_dotenv
from django.core.exceptions import ImproperlyConfigured

from config.s3utils import (
    infer_addressing_style,
    infer_s3_region,
    normalize_custom_domain,
    normalize_s3_endpoint,
)

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / '.env')


def _env_csv(name, default):
    raw = os.getenv(name, '').strip()
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(',') if item.strip()]


_DURATION_RE = re.compile(r'^(\d+(?:\.\d+)?)(s|m|h|d)?$', re.IGNORECASE)
_DURATION_UNITS = {
    's': 1,
    'm': 60,
    'h': 3600,
    'd': 86400,
}


def _env_duration(name, default):
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    match = _DURATION_RE.fullmatch(raw)
    if not match:
        raise ImproperlyConfigured(
            f'{name} must be a duration like 30s, 5m, 2h, or 7d (bare integer = seconds). '
            f'Got: {raw!r}'
        )
    amount = float(match.group(1))
    unit = (match.group(2) or 's').lower()
    if amount <= 0:
        raise ImproperlyConfigured(f'{name} must be greater than zero. Got: {raw!r}')
    return timedelta(seconds=amount * _DURATION_UNITS[unit])


def _env_float(name, default):
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ImproperlyConfigured(f'{name} must be a number. Got: {raw!r}') from exc


def _env_int(name, default):
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ImproperlyConfigured(f'{name} must be an integer. Got: {raw!r}') from exc


def _env_bytes(name, default):
    """Parse byte sizes: bare int, or suffixes K/M/G/T (binary, 1024-based)."""
    raw = os.getenv(name, '').strip()
    if not raw:
        return default
    match = re.fullmatch(r'(\d+)([KkMmGgTt])?', raw)
    if not match:
        raise ImproperlyConfigured(
            f'{name} must be an integer byte count or size like 10G, 500M. Got: {raw!r}'
        )
    amount = int(match.group(1))
    unit = (match.group(2) or '').upper()
    multipliers = {'': 1, 'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4}
    return amount * multipliers[unit]


_secret_key = os.getenv('SECRET_KEY', '').strip()
if not _secret_key:
    raise ImproperlyConfigured(
        '\n'
        'SECRET_KEY is not set — storage-service cannot start.\n'
        '\n'
        'How to fix:\n'
        '  1. Copy the example env file:\n'
        '       cp .env.example .env\n'
        '  2. Set SECRET_KEY in .env.\n'
        '  3. Generate a strong key:\n'
        '       python -c "from django.core.management.utils import '
        'get_random_secret_key; print(get_random_secret_key())"\n'
    )
SECRET_KEY = _secret_key

DEBUG = os.getenv('DEBUG', 'false').strip().lower() in {'1', 'true', 'yes', 'on'}

ALLOWED_HOSTS = _env_csv('ALLOWED_HOSTS', ('localhost', '127.0.0.1'))
CSRF_TRUSTED_ORIGINS = _env_csv(
    'CSRF_TRUSTED_ORIGINS',
    (
        'http://localhost:8001',
        'http://127.0.0.1:8001',
        'http://localhost:4000',
        'http://127.0.0.1:4000',
        'http://localhost:5174',
        'http://127.0.0.1:5174',
        'http://localhost:5175',
        'http://127.0.0.1:5175',
        'https://admin.shellui.com',
    ),
)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')


def _project_version():
    pyproject = BASE_DIR / 'pyproject.toml'
    with pyproject.open('rb') as fh:
        data = tomllib.load(fh)
    version = str(data.get('project', {}).get('version', '')).strip()
    if not version:
        raise ImproperlyConfigured(f'project.version is missing in {pyproject}')
    return version


VERSION = _project_version()

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'corsheaders',
    'rest_framework',
    'drf_spectacular',
    'storages',
    'apps.authapi',
    'apps.storage',
    'apps.webdav',
]

REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'apps.authapi.authentication.IdentityJWKSAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'apps.authapi.permissions.IsAuthenticatedPrincipal',
    ],
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'ShellUI Storage API',
    'DESCRIPTION': (
        'Supabase-compatible object storage API for ShellUI. '
        'Authenticate with a Bearer JWT issued by identity-service. '
        'Use **Authorize** and enter `Bearer <token>` or paste the raw JWT.'
    ),
    'VERSION': VERSION,
    'SERVE_INCLUDE_SCHEMA': False,
    'SWAGGER_UI_SETTINGS': {
        'persistAuthorization': True,
    },
    'TAGS': [
        {'name': 'buckets', 'description': 'Create and manage storage buckets.'},
        {'name': 'objects', 'description': 'Upload, download, list, move, copy, and delete objects.'},
        {'name': 'access', 'description': 'Path-level access grants (invite / restrict / block).'},
        {'name': 'share', 'description': 'Capability share links for anonymous downloads.'},
        {'name': 'quotas', 'description': 'Company and per-user storage quotas.'},
        {'name': 'platform-metrics', 'description': 'Prometheus metrics endpoints.'},
        {'name': 'health', 'description': 'Service health checks.'},
    ],
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

POSTGRES_DATABASE_URL = os.getenv('POSTGRES_DATABASE_URL', '').strip()

if POSTGRES_DATABASE_URL:
    DATABASES = {
        'default': dj_database_url.parse(
            POSTGRES_DATABASE_URL,
            conn_max_age=600,
            ssl_require=False,
        )
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': os.getenv('SQLITE_PATH', str(BASE_DIR / 'db.sqlite3')),
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

MEDIA_URL = '/media/'
_media_root = os.getenv('MEDIA_ROOT', '').strip()
MEDIA_ROOT = Path(_media_root) if _media_root else (BASE_DIR / 'data' / 'media')

# ---------------------------------------------------------------------------
# Object storage backend: s3 (default for production) or filesystem
# ---------------------------------------------------------------------------
STORAGE_BACKEND = os.getenv('STORAGE_BACKEND', 'filesystem').strip().lower()
if STORAGE_BACKEND not in {'s3', 'filesystem'}:
    raise ImproperlyConfigured(
        f'STORAGE_BACKEND must be "s3" or "filesystem". Got: {STORAGE_BACKEND!r}'
    )

AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID', '').strip()
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY', '').strip()
AWS_STORAGE_BUCKET_NAME = os.getenv('AWS_STORAGE_BUCKET_NAME', '').strip()
_raw_s3_endpoint = os.getenv('AWS_S3_ENDPOINT_URL', '').strip() or None
AWS_S3_ENDPOINT_URL = normalize_s3_endpoint(_raw_s3_endpoint, AWS_STORAGE_BUCKET_NAME)
AWS_S3_REGION_NAME = infer_s3_region(
    AWS_S3_ENDPOINT_URL,
    os.getenv('AWS_S3_REGION_NAME', 'us-east-1'),
)
AWS_S3_CUSTOM_DOMAIN = normalize_custom_domain(
    os.getenv('AWS_S3_CUSTOM_DOMAIN', '').strip() or None,
    AWS_S3_ENDPOINT_URL,
)
AWS_DEFAULT_ACL = None
AWS_QUERYSTRING_AUTH = True
AWS_S3_FILE_OVERWRITE = True
AWS_S3_OBJECT_PARAMETERS = {'CacheControl': 'max-age=3600'}
AWS_S3_SIGNATURE_VERSION = os.getenv('AWS_S3_SIGNATURE_VERSION', 's3v4').strip() or 's3v4'
# path = /bucket/key (MinIO and custom endpoints); virtual = bucket.s3.region.amazonaws.com/key
AWS_S3_ADDRESSING_STYLE = infer_addressing_style(
    AWS_S3_ENDPOINT_URL,
    os.getenv('AWS_S3_ADDRESSING_STYLE', ''),
)
if AWS_S3_ADDRESSING_STYLE not in {'path', 'virtual', 'auto'}:
    raise ImproperlyConfigured(
        f'AWS_S3_ADDRESSING_STYLE must be path, virtual, or auto. Got: {AWS_S3_ADDRESSING_STYLE!r}'
    )
# Prefix inside the bucket for all ShellUI objects (keeps multi-tenant keys tidy).
STORAGE_KEY_PREFIX = os.getenv('STORAGE_KEY_PREFIX', 'shellui').strip().strip('/')

if STORAGE_BACKEND == 's3':
    if not AWS_STORAGE_BUCKET_NAME:
        raise ImproperlyConfigured(
            'STORAGE_BACKEND=s3 requires AWS_STORAGE_BUCKET_NAME '
            '(and usually AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY).'
        )
    _default_storage = {
        'BACKEND': 'storages.backends.s3.S3Storage',
        'OPTIONS': {
            'bucket_name': AWS_STORAGE_BUCKET_NAME,
            'region_name': AWS_S3_REGION_NAME,
            'access_key': AWS_ACCESS_KEY_ID or None,
            'secret_key': AWS_SECRET_ACCESS_KEY or None,
            'endpoint_url': AWS_S3_ENDPOINT_URL,
            'custom_domain': AWS_S3_CUSTOM_DOMAIN,
            'addressing_style': AWS_S3_ADDRESSING_STYLE,
            'default_acl': None,
            'querystring_auth': True,
            'file_overwrite': True,
            'signature_version': AWS_S3_SIGNATURE_VERSION,
        },
    }
else:
    _default_storage = {
        'BACKEND': 'django.core.files.storage.FileSystemStorage',
        'OPTIONS': {
            'location': str(MEDIA_ROOT / 'objects'),
            'base_url': f'{MEDIA_URL}objects/',
        },
    }

STORAGES = {
    'default': _default_storage,
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedStaticFilesStorage',
    },
}

# ---------------------------------------------------------------------------
# Download strategy
#   auto     — S3 → signed redirect; filesystem + nginx → xaccel; else stream
#   redirect — HTTP 302 to a signed URL (best for S3, works without nginx)
#   xaccel   — NGINX X-Accel-Redirect (great for local disk or nginx→S3 proxy)
#   stream   — stream bytes through Django (always works, uses app bandwidth)
# ---------------------------------------------------------------------------
DOWNLOAD_MODE = os.getenv('DOWNLOAD_MODE', 'auto').strip().lower()
if DOWNLOAD_MODE not in {'auto', 'redirect', 'xaccel', 'stream'}:
    raise ImproperlyConfigured(
        f'DOWNLOAD_MODE must be auto|redirect|xaccel|stream. Got: {DOWNLOAD_MODE!r}'
    )
X_ACCEL_REDIRECT_ENABLED = os.getenv('X_ACCEL_REDIRECT_ENABLED', 'false').strip().lower() in {
    '1',
    'true',
    'yes',
    'on',
}
# Internal nginx location prefix, e.g. /protected/ → alias to MEDIA_ROOT/objects/
X_ACCEL_REDIRECT_PREFIX = os.getenv('X_ACCEL_REDIRECT_PREFIX', '/protected/').strip() or '/protected/'
SIGNED_URL_EXPIRES = _env_int('SIGNED_URL_EXPIRES', 3600)

# ---------------------------------------------------------------------------
# Identity / JWKS authentication
#
# Customize via env (pick one):
#   IDENTITY_JWKS_URL=https://id.shellui.com/.well-known/jwks.json
#   IDENTITY_JWKS_URL=http://localhost:8000/.well-known/jwks.json
# or set the identity base URL and the JWKS path is derived:
#   IDENTITY_SERVICE_URL=https://id.shellui.com
# ---------------------------------------------------------------------------
def _resolve_identity_jwks_url() -> str:
    explicit = os.getenv('IDENTITY_JWKS_URL', '').strip()
    if explicit:
        return explicit.rstrip('/')
    base = os.getenv('IDENTITY_SERVICE_URL', '').strip().rstrip('/')
    if base:
        return f'{base}/.well-known/jwks.json'
    return 'http://localhost:8000/.well-known/jwks.json'


IDENTITY_JWKS_URL = _resolve_identity_jwks_url()
IDENTITY_SERVICE_URL = os.getenv('IDENTITY_SERVICE_URL', '').strip().rstrip('/') or None
if not IDENTITY_JWKS_URL.startswith(('http://', 'https://')):
    raise ImproperlyConfigured(
        f'IDENTITY_JWKS_URL must be an absolute http(s) URL. Got: {IDENTITY_JWKS_URL!r}\n'
        'Examples:\n'
        '  IDENTITY_JWKS_URL=http://localhost:8000/.well-known/jwks.json\n'
        '  IDENTITY_JWKS_URL=https://id.shellui.com/.well-known/jwks.json\n'
        'Or set IDENTITY_SERVICE_URL=https://id.shellui.com'
    )
IDENTITY_ISSUER = os.getenv('IDENTITY_ISSUER', '').strip() or None
IDENTITY_AUDIENCE = os.getenv('IDENTITY_AUDIENCE', '').strip() or None
JWKS_CACHE_TTL = _env_int('JWKS_CACHE_TTL', 900)
# Dev-only: verify HS256 tokens signed with identity-service SECRET_KEY when JWKS is empty.
# Refused in production unless ALLOW_JWT_HS256_FALLBACK is explicitly enabled.
JWT_HS256_FALLBACK_SECRET = os.getenv('JWT_HS256_FALLBACK_SECRET', '').strip() or None
ALLOW_JWT_HS256_FALLBACK = os.getenv('ALLOW_JWT_HS256_FALLBACK', '').strip().lower() in {
    '1',
    'true',
    'yes',
    'on',
}
if JWT_HS256_FALLBACK_SECRET and not DEBUG and not ALLOW_JWT_HS256_FALLBACK:
    raise ImproperlyConfigured(
        'JWT_HS256_FALLBACK_SECRET is set but DEBUG is false. '
        'HS256 fallback must not be enabled in production (forged tokens risk). '
        'Unset JWT_HS256_FALLBACK_SECRET, or set DEBUG=true for local use, '
        'or set ALLOW_JWT_HS256_FALLBACK=true only if you fully understand the risk.'
    )
JWT_ALGORITHMS = _env_csv('JWT_ALGORITHMS', ('RS256',))

# ---------------------------------------------------------------------------
# Quotas & upload limits
# ---------------------------------------------------------------------------
DEFAULT_COMPANY_QUOTA_BYTES = _env_bytes('DEFAULT_COMPANY_QUOTA_BYTES', 10 * 1024**3)  # 10 GiB
DEFAULT_USER_QUOTA_BYTES = _env_bytes('DEFAULT_USER_QUOTA_BYTES', 0)  # 0 = no per-user default
MAX_UPLOAD_BYTES = _env_bytes('MAX_UPLOAD_BYTES', 5 * 1024**3)  # 5 GiB hard cap per file
DATA_UPLOAD_MAX_MEMORY_SIZE = _env_bytes('DATA_UPLOAD_MAX_MEMORY_SIZE', 12 * 1024**2)
FILE_UPLOAD_MAX_MEMORY_SIZE = DATA_UPLOAD_MAX_MEMORY_SIZE

# WebDAV (third-party file clients)
WEBDAV_ENABLED = os.getenv('WEBDAV_ENABLED', 'true').strip().lower() in {'1', 'true', 'yes', 'on'}
WEBDAV_PATH_PREFIX = os.getenv('WEBDAV_PATH_PREFIX', '/dav').strip() or '/dav'

CORS_ALLOWED_ORIGINS = [
    'http://localhost:4000',
    'http://127.0.0.1:4000',
    'http://localhost:5174',
    'http://127.0.0.1:5174',
    'http://localhost:5175',
    'http://127.0.0.1:5175',
    'https://admin.shellui.com',
]
for _origin in os.getenv('CORS_ALLOWED_ORIGINS', '').split(','):
    _origin = _origin.strip()
    if _origin and _origin not in CORS_ALLOWED_ORIGINS:
        CORS_ALLOWED_ORIGINS.append(_origin)

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = list(
    {
        'accept',
        'accept-encoding',
        'authorization',
        'content-type',
        'dnt',
        'origin',
        'user-agent',
        'x-csrftoken',
        'x-requested-with',
        'x-upsert',
        'x-metadata',
        'cache-control',
        'apikey',
        'x-client-info',
    }
)

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SENTRY_DSN = os.getenv('SENTRY_DSN', '').strip()
SENTRY_ENVIRONMENT = os.getenv('SENTRY_ENVIRONMENT', '').strip() or (
    'development' if DEBUG else 'production'
)
SENTRY_RELEASE = os.getenv('SENTRY_RELEASE', '').strip() or VERSION
SENTRY_TRACES_SAMPLE_RATE = _env_float('SENTRY_TRACES_SAMPLE_RATE', 0.0)

if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(),
            LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
        ],
        environment=SENTRY_ENVIRONMENT,
        release=SENTRY_RELEASE,
        traces_sample_rate=SENTRY_TRACES_SAMPLE_RATE,
        send_default_pii=False,
        attach_stacktrace=True,
    )
