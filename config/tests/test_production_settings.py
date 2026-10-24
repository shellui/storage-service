"""Startup validation for production security settings."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
import unittest
from pathlib import Path

from django.test import Client, SimpleTestCase, TestCase, override_settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANAGE_PY = PROJECT_ROOT / 'manage.py'
LONG_SECRET_KEY = 'test-secret-key-for-settings-check-only-0123456789abcd'

_COOKIE_SETTINGS_SCRIPT = """
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()
from django.conf import settings

fields = {
    'session_name': settings.SESSION_COOKIE_NAME,
    'csrf_name': settings.CSRF_COOKIE_NAME,
    'csrf_httponly': settings.CSRF_COOKIE_HTTPONLY,
    'session_domain': settings.SESSION_COOKIE_DOMAIN,
    'csrf_domain': settings.CSRF_COOKIE_DOMAIN,
    'session_path': settings.SESSION_COOKIE_PATH,
    'csrf_path': settings.CSRF_COOKIE_PATH,
    'session_secure': settings.SESSION_COOKIE_SECURE,
    'csrf_secure': settings.CSRF_COOKIE_SECURE,
}
for key, value in fields.items():
    print(f'{key}={value!r}')
"""

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


def _merged_env(env: dict[str, str]) -> dict[str, str]:
    merged = os.environ.copy()
    merged.update(env)
    merged.setdefault('SECRET_KEY', LONG_SECRET_KEY)
    return merged


def _settings_check(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(MANAGE_PY), *(args or ('check',))],
        cwd=PROJECT_ROOT,
        env=_merged_env(env),
        capture_output=True,
        text=True,
        check=False,
    )


def _output(result: subprocess.CompletedProcess[str]) -> str:
    return f'{result.stdout}\n{result.stderr}'


def _cookie_settings(env: dict[str, str]) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, '-c', _COOKIE_SETTINGS_SCRIPT],
        cwd=PROJECT_ROOT,
        env=_merged_env(env),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    values: dict[str, object] = {}
    for line in result.stdout.splitlines():
        key, raw = line.split('=', 1)
        values[key] = ast.literal_eval(raw)
    return values


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

    def test_email_service_key_must_use_esk_prefix(self):
        result = _settings_check(
            {
                'DEBUG': 'true',
                'EMAIL_SERVICE_API_KEY': 'not-a-service-key',
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('esk_', result.stderr)
        self.assertNotIn('not-a-service-key', result.stderr)

    def test_email_service_url_must_be_an_origin_when_key_is_set(self):
        result = _settings_check(
            {
                'DEBUG': 'true',
                'EMAIL_SERVICE_API_KEY': 'esk_test_prefix_only',  # gitleaks:allow
                'EMAIL_SERVICE_URL': 'email.shellui.com',
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('EMAIL_SERVICE_URL', result.stderr)
        self.assertNotIn('esk_test_prefix_only', result.stderr)

    def test_unset_email_service_key_still_starts(self):
        result = _settings_check(
            {
                'DEBUG': 'true',
                'EMAIL_SERVICE_API_KEY': '',
                'EMAIL_SERVICE_URL': '',
            }
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_production_starts_with_matching_iss_aud(self):
        result = _settings_check(
            {
                'DEBUG': 'false',
                'SECRET_KEY': LONG_SECRET_KEY,
                'IDENTITY_ISSUER': 'https://id.shellui.com',
                'IDENTITY_AUDIENCE': 'shellui',
                'IDENTITY_JWKS': '{"keys":[{"kty":"RSA","kid":"test","n":"x","e":"AQAB"}]}',
            }
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_production_rejects_short_secret_key(self):
        result = _settings_check(
            {
                'DEBUG': 'false',
                'SECRET_KEY': 'test-secret-key-for-settings-check-only',
                'IDENTITY_ISSUER': 'https://id.shellui.com',
                'IDENTITY_AUDIENCE': 'shellui',
            }
        )
        self.assertNotEqual(result.returncode, 0)
        output = _output(result)
        self.assertIn('authapi.E005', output)
        self.assertIn('shorter than 50 characters', output)

    def test_production_rejects_placeholder_secret_key(self):
        result = _settings_check(
            {
                'DEBUG': 'false',
                'SECRET_KEY': 'django-insecure-' + ('abcdefghij' * 5),
                'IDENTITY_ISSUER': 'https://id.shellui.com',
                'IDENTITY_AUDIENCE': 'shellui',
            },
            'check',
            '--deploy',
        )
        self.assertNotEqual(result.returncode, 0)
        output = _output(result)
        self.assertIn('authapi.E005', output)
        self.assertIn('published placeholder', output)
        self.assertNotIn('abcdefghij', output)

    def test_production_check_deploy_rejects_published_example_key(self):
        result = _settings_check(
            {
                'DEBUG': 'false',
                'SECRET_KEY': 'change-me-generate-a-strong-secret-key',
                'IDENTITY_ISSUER': 'https://id.shellui.com',
                'IDENTITY_AUDIENCE': 'shellui',
            },
            'check',
            '--deploy',
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('authapi.E005', _output(result))

    def test_empty_secret_key_refuses_to_start(self):
        result = _settings_check({'DEBUG': 'true', 'SECRET_KEY': ''})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SECRET_KEY is not set', result.stderr)

    def test_debug_allows_short_secret_key(self):
        result = _settings_check(
            {
                'DEBUG': 'true',
                'SECRET_KEY': 'change-me-generate-a-strong-secret-key',
            },
            'check',
            '--deploy',
        )
        self.assertEqual(result.returncode, 0, msg=_output(result))
        self.assertNotIn('authapi.E005', _output(result))

    def test_secure_cookies_use_host_prefix_without_domain(self):
        values = _cookie_settings(
            {
                'DEBUG': 'false',
                'IDENTITY_ISSUER': 'https://id.shellui.com',
                'IDENTITY_AUDIENCE': 'shellui',
            }
        )
        self.assertEqual(values['session_name'], '__Host-sessionid')
        self.assertEqual(values['csrf_name'], '__Host-csrftoken')
        self.assertIs(values['csrf_httponly'], True)
        self.assertIsNone(values['session_domain'])
        self.assertIsNone(values['csrf_domain'])
        self.assertEqual(values['session_path'], '/')
        self.assertEqual(values['csrf_path'], '/')
        self.assertIs(values['session_secure'], True)
        self.assertIs(values['csrf_secure'], True)

    def test_insecure_cookies_keep_classic_names_and_httponly_csrf(self):
        values = _cookie_settings(
            {
                'DEBUG': 'true',
                'SESSION_COOKIE_SECURE': 'false',
                'CSRF_COOKIE_SECURE': 'false',
            }
        )
        self.assertEqual(values['session_name'], 'sessionid')
        self.assertEqual(values['csrf_name'], 'csrftoken')
        self.assertIs(values['csrf_httponly'], True)
        self.assertIsNone(values['session_domain'])
        self.assertIsNone(values['csrf_domain'])
        self.assertIs(values['session_secure'], False)
        self.assertIs(values['csrf_secure'], False)

    def test_host_prefix_follows_each_secure_flag(self):
        values = _cookie_settings(
            {
                'DEBUG': 'true',
                'SESSION_COOKIE_SECURE': 'true',
                'CSRF_COOKIE_SECURE': 'false',
            }
        )
        self.assertEqual(values['session_name'], '__Host-sessionid')
        self.assertEqual(values['csrf_name'], 'csrftoken')
        self.assertIs(values['session_secure'], True)
        self.assertIs(values['csrf_secure'], False)


class SecretKeyCheckTests(SimpleTestCase):
    def _problems(self):
        from django.core.checks import run_checks

        return [
            item
            for item in run_checks(include_deployment_checks=True)
            if item.id == 'authapi.E005'
        ]

    def test_debug_skips_the_check(self):
        with override_settings(DEBUG=True, SECRET_KEY='short'):
            self.assertEqual(self._problems(), [])

    def test_empty_and_whitespace_are_errors(self):
        with override_settings(DEBUG=False, SECRET_KEY=''):
            errors = self._problems()
        self.assertEqual(len(errors), 1)
        self.assertIn('empty', errors[0].msg)
        with override_settings(DEBUG=False, SECRET_KEY='   '):
            errors = self._problems()
        self.assertIn('empty', errors[0].msg)

    def test_long_non_placeholder_key_passes(self):
        self.assertGreaterEqual(len(LONG_SECRET_KEY), 50)
        with override_settings(DEBUG=False, SECRET_KEY=LONG_SECRET_KEY):
            self.assertEqual(self._problems(), [])

    def test_padded_published_placeholder_is_an_error(self):
        key = 'change-me-generate-a-strong-secret-key' + ('x' * 20)
        self.assertGreaterEqual(len(key), 50)
        with override_settings(DEBUG=False, SECRET_KEY=key):
            errors = self._problems()
        self.assertEqual(len(errors), 1)
        self.assertIn('placeholder', errors[0].msg)


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
