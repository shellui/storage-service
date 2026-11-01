"""Company deletion asked by identity-service: assertion checks, flag, Celery purge."""

from __future__ import annotations

import time
from datetime import timedelta
from unittest import mock

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.actions import company_deletion
from apps.actions.models import ActionRule, CompanyDeletion

URL = '/api/v1/internal/company-deletions'
ISSUER = 'https://id.eu.example'

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _assertion(key=_KEY, **overrides):
    now = int(time.time())
    claims = {
        'iss': ISSUER,
        'aud': 'shellui-company-deletion',
        'scope': 'company.delete',
        'company_id': 7,
        'iat': now,
        'exp': now + 60,
        'jti': 'j',
    }
    claims.update(overrides)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return jwt.encode(claims, pem, algorithm='RS256')


class _Client:
    def get_signing_key(self, _raw):
        return mock.Mock(key=_KEY.public_key())


@override_settings(IDENTITY_ISSUER=ISSUER, JWT_HS256_FALLBACK_SECRET=None)
class CompanyDeletionTests(TestCase):
    def setUp(self):
        patcher = mock.patch('apps.authapi.jwks_client.get_jwks_client', return_value=_Client())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = APIClient()

    def _post(self, token):
        return self.client.post(URL, {}, format='json', HTTP_AUTHORIZATION=f'Bearer {token}')

    def test_flags_company(self):
        response = self._post(_assertion())
        self.assertEqual(response.status_code, 202)
        self.assertTrue(CompanyDeletion.objects.filter(company_id=7).exists())
        self.assertEqual(self._post(_assertion()).status_code, 202)
        self.assertEqual(CompanyDeletion.objects.count(), 1)

    def test_rejects_bad_assertions(self):
        self.assertEqual(self.client.post(URL, {}, format='json').status_code, 401)
        for token in (
            _assertion(key=_OTHER),
            _assertion(aud='shellui'),
            _assertion(scope='openid'),
            _assertion(iss='https://evil.example'),
            _assertion(company_id='7'),
            _assertion(exp=int(time.time()) + 3600),
            _assertion(exp=int(time.time()) - 10),
        ):
            self.assertEqual(self._post(token).status_code, 401)
        self.assertFalse(CompanyDeletion.objects.exists())

    def test_purge_deletes_company_rows_only_and_releases_flag(self):
        model_fields = {f.name for f in ActionRule._meta.get_fields()}
        self.assertIn('company_id', model_fields)
        self.assertIn(ActionRule, company_deletion.company_scoped_models())
        CompanyDeletion.objects.create(company_id=7)
        with mock.patch.object(company_deletion, 'delete_company_rows', wraps=company_deletion.delete_company_rows) as rows:
            stats = company_deletion.purge_deleted_companies()
        rows.assert_called_once_with(7)
        self.assertEqual(stats['purged'], 1)
        self.assertIsNotNone(CompanyDeletion.objects.get(company_id=7).completed_at)
        # Swept again within the window, then released.
        company_deletion.purge_deleted_companies()
        self.assertTrue(CompanyDeletion.objects.exists())
        later = timezone.now() + timedelta(hours=2)
        self.assertEqual(company_deletion.purge_deleted_companies(now=later)['released'], 1)
        self.assertFalse(CompanyDeletion.objects.exists())

    def test_failed_purge_is_retried(self):
        CompanyDeletion.objects.create(company_id=7)
        with mock.patch.object(company_deletion, 'purge_company', side_effect=RuntimeError('s3 down')):
            self.assertEqual(company_deletion.purge_deleted_companies()['failed'], 1)
        self.assertIsNone(CompanyDeletion.objects.get(company_id=7).completed_at)
        self.assertEqual(company_deletion.purge_deleted_companies()['purged'], 1)

    def test_beat_runs_every_minute(self):
        from django.conf import settings

        entry = settings.CELERY_BEAT_SCHEDULE['purge-deleted-companies']
        self.assertEqual(entry['task'], 'actions.purge_deleted_companies')
        self.assertEqual(entry['schedule'], timedelta(seconds=60))
