"""Tests for Prometheus metrics endpoints."""

from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.storage.access import COMPANY_BUCKET_NAME
from apps.storage.tests.test_storage import make_token


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
)
class StorageMetricsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.jwks_patch = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = self.jwks_patch.start()
        mock_client.return_value.get_signing_key.return_value = None
        self.addCleanup(self.jwks_patch.stop)

    def _auth(self, **kwargs):
        return {'HTTP_AUTHORIZATION': f'Bearer {make_token(**kwargs)}'}

    def _upload(self, *, company_id: int, user_id: int, path: str, body: bytes, content_type: str):
        auth = self._auth(user_id=user_id, company_id=company_id, is_company_owner=True)
        response = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/{path}',
            data=body,
            content_type=content_type,
            **auth,
        )
        self.assertEqual(response.status_code, 200, response.content)

    def test_metrics_requires_auth(self):
        response = self.client.get('/storage/v1/metrics')
        self.assertEqual(response.status_code, 401)

    def test_metrics_forbidden_for_regular_member(self):
        self._upload(company_id=10, user_id=1, path='note.md', body=b'# hi', content_type='text/markdown')
        response = self.client.get('/storage/v1/metrics', **self._auth())
        self.assertEqual(response.status_code, 403)

    def test_metrics_company_owner_sees_only_own_company(self):
        self._upload(company_id=10, user_id=1, path='a.md', body=b'# a', content_type='text/markdown')
        self._upload(company_id=11, user_id=2, path='b.png', body=b'\x89PNG', content_type='image/png')

        response = self.client.get(
            '/storage/v1/metrics',
            HTTP_ACCEPT='text/plain',
            **self._auth(is_company_owner=True),
        )
        self.assertEqual(response.status_code, 200)
        text = response.content.decode()
        self.assertIn('shellui_storage_objects_total{company_id="10"}', text)
        self.assertNotIn('company_id="11"', text)
        self.assertIn('shellui_storage_objects_total{company_id="10"} 1.0', text)

    def test_metrics_rejects_company_id_query(self):
        response = self.client.get(
            '/storage/v1/metrics?company_id=10',
            **self._auth(is_company_owner=True),
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('query string', response.content.decode())

    def test_metrics_staff_ok(self):
        self._upload(company_id=10, user_id=1, path='a.md', body=b'# a', content_type='text/markdown')
        response = self.client.get('/storage/v1/metrics', **self._auth(is_staff=True))
        self.assertEqual(response.status_code, 200)
        self.assertIn('shellui_storage_bytes_total{company_id="10"}', response.content.decode())

    def test_metrics_all_staff_includes_every_company(self):
        self._upload(company_id=10, user_id=1, path='a.md', body=b'# a', content_type='text/markdown')
        self._upload(company_id=11, user_id=2, path='b.png', body=b'\x89PNG', content_type='image/png')
        response = self.client.get('/storage/v1/metrics/all', **self._auth(is_staff=True))
        self.assertEqual(response.status_code, 200)
        text = response.content.decode()
        self.assertIn('company_id="10"', text)
        self.assertIn('company_id="11"', text)

    def test_metrics_all_forbidden_for_owner(self):
        response = self.client.get('/storage/v1/metrics/all', **self._auth(is_company_owner=True))
        self.assertEqual(response.status_code, 403)

    def test_metrics_all_pat_agm(self):
        self._upload(company_id=10, user_id=1, path='a.md', body=b'# a', content_type='text/markdown')
        response = self.client.get(
            '/storage/v1/metrics/all',
            **self._auth(is_company_owner=True, access_global_metrics=True),
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('shellui_storage_objects_total', response.content.decode())
