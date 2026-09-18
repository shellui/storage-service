"""Startup validation for production security settings."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

from django.test import Client, TestCase, override_settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANAGE_PY = PROJECT_ROOT / 'manage.py'

_ADMIN_URL_CHECK = """
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()
from django.urls import get_resolver

patterns = [getattr(p, 'pattern', '') for p in get_resolver().url_patterns]
has_admin = any('admin/' in str(p) for p in patterns)
print('has_admin=' + str(has_admin))
"""


def _settings_check(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.update(env)
    merged.setdefault('SECRET_KEY', 'test-secret-key-for-settings-check-only')
    return subprocess.run(
        [sys.executable, str(MANAGE_PY), 'check'],
        cwd=PROJECT_ROOT,
        env=merged,
        capture_output=True,
        text=True,
        check=False,
    )


class ProductionSettingsValidationTests(unittest.TestCase):
    def test_cors_allow_all_with_credentials_fails_startup(self):
        result = _settings_check(
            {
                'DEBUG': 'true',
                'CORS_ALLOW_ALL_ORIGINS': 'true',
                'CORS_ALLOW_CREDENTIALS': 'true',
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CORS_ALLOW_ALL_ORIGINS=true with CORS_ALLOW_CREDENTIALS=true', result.stderr)

    def test_production_requires_identity_issuer_and_audience(self):
        result = _settings_check({'DEBUG': 'false'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('IDENTITY_ISSUER is required when DEBUG=false', result.stderr)
        self.assertIn('IDENTITY_AUDIENCE is required when DEBUG=false', result.stderr)

    def test_production_starts_with_matching_iss_aud(self):
        result = _settings_check(
            {
                'DEBUG': 'false',
                'IDENTITY_ISSUER': 'https://id.shellui.com',
                'IDENTITY_AUDIENCE': 'shellui',
                'IDENTITY_JWKS': '{"keys":[{"kty":"RSA","kid":"test","n":"x","e":"AQAB"}]}',
            }
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)


@override_settings(CORS_ALLOW_ALL_ORIGINS=True, CORS_ALLOW_CREDENTIALS=False)
class CorsProductionPatternTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_allow_all_without_credentials_uses_wildcard(self):
        origin = 'https://tenant-preview.shellui.app'
        response = self.client.options(
            '/storage/v1/health',
            HTTP_ORIGIN=origin,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD='GET',
            HTTP_ACCESS_CONTROL_REQUEST_HEADERS='authorization',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Access-Control-Allow-Origin'], '*')


class DjangoAdminDisabledTests(unittest.TestCase):
    def test_admin_urls_not_mounted_when_disabled(self):
        env = os.environ.copy()
        env.update(
            {
                'SECRET_KEY': 'test-secret-key-for-settings-check-only',
                'DEBUG': 'true',
                'DJANGO_ADMIN_ENABLED': 'false',
            }
        )
        result = subprocess.run(
            [sys.executable, '-c', _ADMIN_URL_CHECK],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn('has_admin=False', result.stdout)
