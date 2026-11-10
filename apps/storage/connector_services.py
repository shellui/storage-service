"""Connector bucket lifecycle: allowlisted settings, safe issue codes, local configuration checks."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from django.conf import settings as dj_settings
from django.db import transaction
from django.utils import timezone

from .access import COMPANY_BUCKET_NAME
from .crypto_helpers import decrypt_connector_secret, encrypt_connector_secret
from .models import Bucket, BucketKind


_SLUG_RE = re.compile(r'^[a-z][a-z0-9_-]{0,62}[a-z0-9]$|^[a-z]$')
# Order is the OpenAPI enum order agents see.
CONNECTOR_PROVIDER_CHOICES: tuple[tuple[str, str], ...] = (
    ('sharepoint', 'SharePoint'),
    ('dropbox', 'Dropbox'),
    ('google_drive', 'Google Drive'),
    ('box', 'Box'),
    ('s3', 'S3'),
    ('generic', 'Generic'),
)
_CONNECTOR_PROVIDERS = frozenset(choice[0] for choice in CONNECTOR_PROVIDER_CHOICES)

# Public, non-secret connector metadata (stored JSON is scrubbed to these keys only).
ALLOWED_CONNECTOR_SETTING_KEYS = frozenset(
    {
        'display_name',
        'external_root_path',
        'tenant_id',
        'site_id',
        'drive_id',
        'resource_id',
    }
)

_SECRET_KEY_SUBSTRINGS = (
    'secret',
    'password',
    'passwd',
    'token',
    'credential',
    'authorization',
    'auth',
    'connection_string',
    'connectionstring',
    'access_key',
    'accesskey',
    'private_key',
    'privatekey',
    'client_secret',
    'refresh_token',
    'access_token',
    'api_key',
    'apikey',
    'bearer',
    'signed_url',
    'presigned',
)

# Simulation is for DEBUG or automated tests only (never relied on in production).
_DEV_SIMULATION_KEY = '_dev_simulation'


class ConnectorError(Exception):
    """Invalid connector operation (status and code match StorageError REST shape)."""

    def __init__(self, message: str, *, status: int = 400, code: str = 'connector_error'):
        super().__init__(message)
        self.status = status
        self.code = code


def allow_connector_dev_simulation() -> bool:
    return bool(getattr(dj_settings, 'DEBUG', False) or getattr(dj_settings, 'TEST_MODE', False))


def validate_connector_slug(name: str) -> str:
    s = (name or '').strip().lower()
    if not s or s == COMPANY_BUCKET_NAME:
        raise ConnectorError('Invalid connector bucket name.', status=400, code='invalid_connector_name')
    if not _SLUG_RE.match(s):
        raise ConnectorError(
            'Connector name must be a slug: lowercase letters, digits, hyphen, underscore, 1-64 characters.',
            status=400,
            code='invalid_connector_name',
        )
    return s


def _is_secret_like_key(name: str) -> bool:
    n = (name or '').strip().lower()
    if not n:
        return False
    if n == _DEV_SIMULATION_KEY:
        return False
    if n.startswith('_'):
        return True
    return any(sub in n for sub in _SECRET_KEY_SUBSTRINGS)


def _walk_reject_secrets(obj: Any, *, path: str) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k)
            if _is_secret_like_key(key_str):
                raise ConnectorError(
                    f'connector_settings may not use reserved or secret-like key "{key_str}".',
                    status=400,
                    code='settings_secret_key_forbidden',
                )
            _walk_reject_secrets(v, path=f'{path}.{key_str}' if path else key_str)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk_reject_secrets(v, path=f'{path}[{i}]')


def _sanitize_allowed_settings(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ALLOWED_CONNECTOR_SETTING_KEYS:
        if key not in raw:
            continue
        val = raw[key]
        if val in (None, ''):
            continue
        if key in {'display_name', 'external_root_path'}:
            if not isinstance(val, str):
                raise ConnectorError(
                    f'connector_settings.{key} must be a string.',
                    status=400,
                    code='invalid_settings',
                )
            out[key] = val[:512]
        elif key in {'tenant_id', 'site_id', 'drive_id', 'resource_id'}:
            if not isinstance(val, str):
                raise ConnectorError(
                    f'connector_settings.{key} must be a string.',
                    status=400,
                    code='invalid_settings',
                )
            s = val.strip()
            if len(s) > 128 or not s.replace('-', '').replace('_', '').isalnum():
                raise ConnectorError(
                    f'connector_settings.{key} must be alphanumeric (hyphen or underscore allowed), max 128 chars.',
                    status=400,
                    code='invalid_settings',
                )
            out[key] = s
    return out


def parse_connector_settings_body(
    raw: dict | None,
    *,
    allow_dev_simulation: bool,
) -> dict[str, Any]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ConnectorError('connector_settings must be a JSON object.', status=400, code='invalid_settings')

    _walk_reject_secrets(raw, path='')

    extra = set(raw.keys()) - ALLOWED_CONNECTOR_SETTING_KEYS
    if _DEV_SIMULATION_KEY in raw:
        extra.discard(_DEV_SIMULATION_KEY)
    if extra:
        raise ConnectorError(
            f'Unknown or disallowed connector_settings keys: {", ".join(sorted(extra))}.',
            status=400,
            code='settings_unknown_keys',
        )

    sim = raw.get(_DEV_SIMULATION_KEY)
    if sim is not None:
        if not allow_dev_simulation:
            raise ConnectorError(
                'Development simulation is not allowed in this environment.',
                status=400,
                code='simulation_not_allowed',
            )
        if not isinstance(sim, dict):
            raise ConnectorError(
                f'{_DEV_SIMULATION_KEY} must be an object.',
                status=400,
                code='invalid_simulation',
            )
        mode = str(sim.get('mode') or '').lower()
        if mode not in {'ok', 'error', 'unavailable'}:
            raise ConnectorError(
                '_dev_simulation.mode must be ok, error, or unavailable.',
                status=400,
                code='invalid_simulation',
            )

    return dict(raw)


def merge_connector_settings(
    existing: dict[str, Any] | None,
    new_body: dict[str, Any] | None,
    *,
    merge: bool,
    allow_dev_simulation: bool,
) -> dict[str, Any]:
    parsed = parse_connector_settings_body(new_body, allow_dev_simulation=allow_dev_simulation)
    sim_block = parsed.pop(_DEV_SIMULATION_KEY, None)
    sanitized = _sanitize_allowed_settings(parsed)
    if sim_block is not None:
        sanitized[_DEV_SIMULATION_KEY] = sim_block
    if not merge:
        base: dict[str, Any] = {}
    else:
        base = dict(existing or {})
        for k in list(base.keys()):
            if k not in ALLOWED_CONNECTOR_SETTING_KEYS and k != _DEV_SIMULATION_KEY:
                del base[k]
    base.update(sanitized)
    if not allow_dev_simulation and _DEV_SIMULATION_KEY in base:
        del base[_DEV_SIMULATION_KEY]
    return base


def stored_settings_for_api(stored: dict[str, Any] | None) -> dict[str, Any]:
    raw = dict(stored or {})
    raw.pop(_DEV_SIMULATION_KEY, None)
    return _sanitize_allowed_settings(raw)


def run_configuration_check(
    *,
    provider: str,
    settings_obj: dict[str, Any] | None,
    credential_plaintext: str | None,
    allow_dev_simulation: bool,
) -> tuple[str, str]:
    """
    Local configuration and credential validation only (no live provider or remote sync).

    Returns (configuration_status, issue_code). issue_code is empty when status is ``configured``.
    """
    prov = (provider or '').strip().lower() or 'generic'
    if prov not in _CONNECTOR_PROVIDERS:
        return 'unsupported', 'unsupported_provider'

    settings_obj = dict(settings_obj or {})
    sim = settings_obj.get(_DEV_SIMULATION_KEY) if allow_dev_simulation else None
    if isinstance(sim, dict):
        mode = str(sim.get('mode') or '').lower()
        if mode == 'ok':
            return 'configured', ''
        if mode == 'error':
            return 'disconnected', 'dev_simulation_error'
        if mode == 'unavailable':
            return 'adapter_unavailable', 'dev_simulation_unavailable'

    has_cred = bool((credential_plaintext or '').strip())

    if not has_cred:
        return 'disconnected', 'no_credential'

    # No live adapter in this service: credential present but remote sync is not implemented.
    return 'adapter_unavailable', 'adapter_not_implemented'


def connector_configuration_status(bucket: Bucket) -> str:
    code = (bucket.connector_last_issue_code or '').strip()
    cred = bool((bucket.connector_credential_encrypted or '').strip())
    if not code:
        return 'configured'
    if code in {'no_credential'} or (not cred and code == 'credential_decrypt_failed'):
        return 'disconnected'
    if code == 'unsupported_provider':
        return 'unsupported'
    if code == 'dev_simulation_error':
        return 'disconnected'
    if code == 'dev_simulation_unavailable':
        return 'adapter_unavailable'
    if code == 'adapter_not_implemented':
        return 'adapter_unavailable'
    return 'configuration_invalid'


def serialize_connector_bucket_api(
    bucket: Bucket,
    *,
    include_secret_hint: bool = False,
    include_provider_details: bool = False,
    include_issue_code: bool = False,
) -> dict[str, Any]:
    code = (bucket.connector_last_issue_code or '').strip()
    stored = stored_settings_for_api(bucket.connector_settings)
    status = connector_configuration_status(bucket)
    payload: dict[str, Any] = {
        'id': bucket.name,
        'name': bucket.name,
        'company_id': bucket.company_id,
        'kind': bucket.kind,
        'connector_provider': bucket.connector_provider or None,
        'connector_settings': stored if include_provider_details else {},
        'credential_configured': bool((bucket.connector_credential_encrypted or '').strip()),
        'connector_last_refresh_at': (
            bucket.connector_last_refresh_at.isoformat().replace('+00:00', 'Z')
            if bucket.connector_last_refresh_at
            else None
        ),
        'connector_last_test_at': (
            bucket.connector_last_test_at.isoformat().replace('+00:00', 'Z')
            if bucket.connector_last_test_at
            else None
        ),
        'connector_retry_after': (
            bucket.connector_retry_after.isoformat().replace('+00:00', 'Z')
            if bucket.connector_retry_after
            else None
        ),
        'connector_credential_updated_at': (
            bucket.connector_credential_updated_at.isoformat().replace('+00:00', 'Z')
            if bucket.connector_credential_updated_at
            else None
        ),
        'connector_configuration_status': status,
        'has_connector_issue': bool(code),
    }
    if include_issue_code and code:
        payload['connector_last_issue_code'] = code[:64]
    if include_secret_hint:
        enc = (bucket.connector_credential_encrypted or '').strip()
        payload['credential_hint'] = 'configured' if enc else 'not_configured'
    return payload


def _check_and_persist(
    bucket: Bucket,
    *,
    credential_plaintext: str | None,
    allow_dev_simulation: bool,
) -> None:
    status, issue = run_configuration_check(
        provider=bucket.connector_provider or '',
        settings_obj=bucket.connector_settings or {},
        credential_plaintext=credential_plaintext,
        allow_dev_simulation=allow_dev_simulation,
    )
    now = timezone.now()
    bucket.connector_last_refresh_at = now
    bucket.connector_last_test_at = now
    bucket.connector_last_issue_code = (issue or '')[:64]
    if status == 'configured':
        bucket.connector_retry_after = None
    else:
        bucket.connector_retry_after = now + timedelta(minutes=5)
    bucket.save(
        update_fields=[
            'connector_last_refresh_at',
            'connector_last_test_at',
            'connector_last_issue_code',
            'connector_retry_after',
            'updated_at',
        ]
    )


@transaction.atomic
def create_connector_bucket(
    *,
    company_id: int,
    name: str,
    connector_provider: str,
    connector_settings: dict | None,
    credential: str | None,
    owner_id: int | None,
    allow_dev_simulation: bool,
) -> Bucket:
    slug = validate_connector_slug(name)
    prov = (connector_provider or '').strip().lower()
    if not prov:
        raise ConnectorError('connector_provider is required.', status=400, code='provider_required')
    if prov not in _CONNECTOR_PROVIDERS:
        raise ConnectorError(
            f'Unsupported connector_provider. Allowed: {", ".join(sorted(_CONNECTOR_PROVIDERS))}.',
            status=400,
            code='unsupported_provider',
        )

    if Bucket.objects.filter(company_id=company_id, name=slug).exists():
        raise ConnectorError('A bucket with this name already exists.', status=409, code='bucket_exists')

    settings_obj = merge_connector_settings(
        {},
        connector_settings,
        merge=False,
        allow_dev_simulation=allow_dev_simulation,
    )

    enc = encrypt_connector_secret(credential) if credential else ''
    bucket = Bucket.objects.create(
        name=slug,
        company_id=company_id,
        kind=BucketKind.CONNECTOR,
        public=False,
        connector_provider=prov,
        connector_settings=settings_obj,
        connector_credential_encrypted=enc,
        owner_id=owner_id,
        connector_credential_updated_at=timezone.now() if enc else None,
    )
    _check_and_persist(bucket, credential_plaintext=credential or '', allow_dev_simulation=allow_dev_simulation)
    return bucket


@transaction.atomic
def update_connector_bucket(
    bucket: Bucket,
    *,
    connector_provider: str | None = None,
    connector_settings: dict | None = None,
    credential: str | None = None,
    merge_settings: bool = True,
    allow_dev_simulation: bool = False,
) -> Bucket:
    if bucket.kind != BucketKind.CONNECTOR:
        raise ConnectorError('Not a connector bucket.', status=400, code='not_connector')
    fields: list[str] = ['updated_at']
    should_recheck = False
    if connector_provider is not None:
        prov = connector_provider.strip().lower()
        if prov not in _CONNECTOR_PROVIDERS:
            raise ConnectorError('Unsupported connector_provider.', status=400, code='unsupported_provider')
        bucket.connector_provider = prov
        fields.append('connector_provider')
        should_recheck = True
    if connector_settings is not None:
        bucket.connector_settings = merge_connector_settings(
            bucket.connector_settings or {},
            connector_settings,
            merge=merge_settings,
            allow_dev_simulation=allow_dev_simulation,
        )
        fields.append('connector_settings')
        should_recheck = True
    if credential is not None:
        if credential == '':
            bucket.connector_credential_encrypted = ''
            bucket.connector_credential_updated_at = None
        else:
            bucket.connector_credential_encrypted = encrypt_connector_secret(credential)
            bucket.connector_credential_updated_at = timezone.now()
        fields.extend(['connector_credential_encrypted', 'connector_credential_updated_at'])
        should_recheck = True
    bucket.save(update_fields=fields)
    if should_recheck:
        plain: str | None = None
        if (bucket.connector_credential_encrypted or '').strip():
            try:
                plain = decrypt_connector_secret(bucket.connector_credential_encrypted)
            except Exception:
                bucket.connector_last_issue_code = 'credential_decrypt_failed'
                bucket.connector_last_refresh_at = timezone.now()
                bucket.connector_last_test_at = timezone.now()
                bucket.connector_retry_after = timezone.now() + timedelta(minutes=5)
                bucket.save(
                    update_fields=[
                        'connector_last_issue_code',
                        'connector_last_refresh_at',
                        'connector_last_test_at',
                        'connector_retry_after',
                        'updated_at',
                    ]
                )
                return bucket
        _check_and_persist(bucket, credential_plaintext=plain, allow_dev_simulation=allow_dev_simulation)
    return bucket


@transaction.atomic
def delete_connector_bucket(bucket: Bucket) -> None:
    if bucket.kind != BucketKind.CONNECTOR:
        raise ConnectorError('Not a connector bucket.', status=400, code='not_connector')
    bucket.delete()


@transaction.atomic
def check_connector_configuration(
    bucket: Bucket,
    *,
    allow_dev_simulation: bool,
) -> Bucket:
    """Re-run local configuration validation (not a live provider or remote connectivity test)."""
    if bucket.kind != BucketKind.CONNECTOR:
        raise ConnectorError('Not a connector bucket.', status=400, code='not_connector')
    plain = ''
    if (bucket.connector_credential_encrypted or '').strip():
        try:
            plain = decrypt_connector_secret(bucket.connector_credential_encrypted)
        except Exception:
            bucket.connector_last_issue_code = 'credential_decrypt_failed'
            bucket.connector_last_refresh_at = timezone.now()
            bucket.connector_last_test_at = timezone.now()
            bucket.connector_retry_after = timezone.now() + timedelta(minutes=5)
            bucket.save(
                update_fields=[
                    'connector_last_issue_code',
                    'connector_last_refresh_at',
                    'connector_last_test_at',
                    'connector_retry_after',
                    'updated_at',
                ]
            )
            return bucket
    _check_and_persist(bucket, credential_plaintext=plain or None, allow_dev_simulation=allow_dev_simulation)
    return bucket
