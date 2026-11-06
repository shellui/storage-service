"""Connector bucket lifecycle: validation, provider adapters, and safe serialization."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.utils import timezone

from .access import COMPANY_BUCKET_NAME
from .crypto_helpers import decrypt_connector_secret, encrypt_connector_secret
from .models import Bucket, BucketKind


_SLUG_RE = re.compile(r'^[a-z][a-z0-9_-]{0,62}[a-z0-9]$|^[a-z]$')
_CONNECTOR_PROVIDERS = frozenset(
    {
        'sharepoint',
        'dropbox',
        'google_drive',
        'box',
        's3',
        'generic',
    }
)


class ConnectorError(Exception):
    """Invalid connector operation (status and code match StorageError REST shape)."""

    def __init__(self, message: str, *, status: int = 400, code: str = 'connector_error'):
        super().__init__(message)
        self.status = status
        self.code = code


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


def _parse_settings(raw: dict | None) -> dict[str, Any]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ConnectorError('connector_settings must be a JSON object.', status=400, code='invalid_settings')
    return dict(raw)


def run_provider_check(
    provider: str,
    settings_obj: dict[str, Any],
    credential_plaintext: str | None,
) -> tuple[bool, str | None]:
    """
    Deterministic connectivity check without live network by default.

    Returns (ok, error_message). Unknown provider or unset simulation flag fails closed
    unless ``SHELLUI_CONNECTOR_PROVIDER_AVAILABLE`` is true in settings (tests only).
    """
    from django.conf import settings as dj_settings

    provider_norm = (provider or '').strip().lower() or 'generic'
    sim = (settings_obj or {}).get('simulation') or {}
    if not isinstance(sim, dict):
        sim = {}

    if getattr(dj_settings, 'SHELLUI_CONNECTOR_PROVIDER_AVAILABLE', False):
        return True, None

    mode = str(sim.get('mode') or '').lower()
    if mode == 'unavailable':
        return False, 'Provider is not configured for this environment.'
    if mode == 'error':
        return False, str(sim.get('message') or 'Simulated provider error.')
    if mode == 'ok':
        return True, None

    return False, (
        f'No connectivity check is configured for provider {provider_norm!r}. '
        'Set connector_settings.simulation.mode to "ok" for tests or configure the provider.'
    )


def serialize_connector_bucket_api(
    bucket: Bucket,
    *,
    include_secret_hint: bool = False,
    include_provider_details: bool = False,
    include_last_error: bool = False,
) -> dict[str, Any]:
    """API shape for connector buckets (shared REST; never includes raw credentials)."""
    settings_obj = bucket.connector_settings or {}
    last_err = (bucket.connector_last_error or '').strip()
    payload: dict[str, Any] = {
        'id': bucket.name,
        'name': bucket.name,
        'company_id': bucket.company_id,
        'kind': bucket.kind,
        'connector_provider': bucket.connector_provider or None,
        'connector_settings': settings_obj if include_provider_details else {},
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
        'has_credential_error': bool(last_err),
    }
    if include_last_error and last_err:
        payload['connector_last_error'] = last_err[:512]
    if include_secret_hint:
        enc = (bucket.connector_credential_encrypted or '').strip()
        payload['credential_hint'] = 'configured' if enc else 'not_configured'
    return payload


@transaction.atomic
def create_connector_bucket(
    *,
    company_id: int,
    name: str,
    connector_provider: str,
    connector_settings: dict | None,
    credential: str | None,
    owner_id: int | None,
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
    settings_obj = _parse_settings(connector_settings)

    if Bucket.objects.filter(company_id=company_id, name=slug).exists():
        raise ConnectorError('A bucket with this name already exists.', status=409, code='bucket_exists')

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
    ok, err = run_provider_check(prov, settings_obj, credential)
    bucket.connector_last_test_at = timezone.now()
    if not ok:
        bucket.connector_last_error = (err or 'Connectivity check failed.')[:512]
        bucket.connector_retry_after = timezone.now() + timedelta(minutes=5)
    else:
        bucket.connector_last_error = ''
        bucket.connector_retry_after = None
    bucket.save(
        update_fields=[
            'connector_last_test_at',
            'connector_last_error',
            'connector_retry_after',
            'updated_at',
        ]
    )
    return bucket


@transaction.atomic
def update_connector_bucket(
    bucket: Bucket,
    *,
    connector_provider: str | None = None,
    connector_settings: dict | None = None,
    credential: str | None = None,
    merge_settings: bool = True,
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
        new_settings = _parse_settings(connector_settings)
        if merge_settings:
            merged = dict(bucket.connector_settings or {})
            merged.update(new_settings)
            bucket.connector_settings = merged
        else:
            bucket.connector_settings = new_settings
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
        plain = ''
        if (bucket.connector_credential_encrypted or '').strip():
            try:
                plain = decrypt_connector_secret(bucket.connector_credential_encrypted)
            except Exception:
                raise ConnectorError(
                    'Stored credential could not be decrypted.',
                    status=500,
                    code='credential_decrypt_failed',
                ) from None
        ok, err = run_provider_check(
            bucket.connector_provider or '',
            bucket.connector_settings or {},
            plain or None,
        )
        bucket.connector_last_test_at = timezone.now()
        if not ok:
            bucket.connector_last_error = (err or 'Connectivity check failed.')[:512]
            bucket.connector_retry_after = timezone.now() + timedelta(minutes=5)
        else:
            bucket.connector_last_error = ''
            bucket.connector_retry_after = None
        bucket.save(
            update_fields=[
                'connector_last_test_at',
                'connector_last_error',
                'connector_retry_after',
                'updated_at',
            ]
        )
    return bucket


@transaction.atomic
def delete_connector_bucket(bucket: Bucket) -> None:
    if bucket.kind != BucketKind.CONNECTOR:
        raise ConnectorError('Not a connector bucket.', status=400, code='not_connector')
    bucket.delete()


@transaction.atomic
def refresh_connector_bucket(bucket: Bucket) -> Bucket:
    if bucket.kind != BucketKind.CONNECTOR:
        raise ConnectorError('Not a connector bucket.', status=400, code='not_connector')
    plain = ''
    if (bucket.connector_credential_encrypted or '').strip():
        try:
            plain = decrypt_connector_secret(bucket.connector_credential_encrypted)
        except Exception:
            raise ConnectorError(
                'Stored credential could not be decrypted.',
                status=500,
                code='credential_decrypt_failed',
            ) from None
    ok, err = run_provider_check(
        bucket.connector_provider or '',
        bucket.connector_settings or {},
        plain or None,
    )
    bucket.connector_last_refresh_at = timezone.now()
    bucket.connector_last_test_at = timezone.now()
    if not ok:
        bucket.connector_last_error = (err or 'Refresh failed.')[:512]
        bucket.connector_retry_after = timezone.now() + timedelta(minutes=5)
    else:
        bucket.connector_last_error = ''
        bucket.connector_retry_after = None
    bucket.save(
        update_fields=[
            'connector_last_refresh_at',
            'connector_last_test_at',
            'connector_last_error',
            'connector_retry_after',
            'updated_at',
        ]
    )
    return bucket


@transaction.atomic
def test_connector_bucket(bucket: Bucket) -> Bucket:
    return refresh_connector_bucket(bucket)


@transaction.atomic
def retry_connector_bucket(bucket: Bucket) -> Bucket:
    """Clear retry backoff after a successful check, or set error on failure."""
    return refresh_connector_bucket(bucket)
