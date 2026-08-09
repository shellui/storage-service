"""Tests for storage-service."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import patch

import jwt
from django.core.files.storage import default_storage
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.storage.access import (
    COMPANY_BUCKET_NAME,
    ensure_system_buckets,
    user_bucket_name,
)
from apps.storage.mime import guess_mime_type, mime_allowed, safe_object_path
from apps.storage.models import Bucket, BucketKind, CompanyQuota, StorageObject, UserQuota
from apps.storage.quotas import QuotaExceeded, assert_can_store
from apps.storage.services import upload_object


def make_token(
    *,
    user_id: int = 1,
    company_id: int = 10,
    email: str = 'user@example.com',
    is_staff: bool = False,
    is_company_owner: bool = False,
    secret: str = 'test-secret',
) -> str:
    payload = {
        'sub': str(user_id),
        'user_id': user_id,
        'company_id': company_id,
        'email': email,
        'user_metadata': {
            'is_staff': is_staff,
            'is_company_owner': is_company_owner,
        },
        'exp': 2**31 - 1,
    }
    return jwt.encode(payload, secret, algorithm='HS256')


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=1024 * 1024,
    DEFAULT_USER_QUOTA_BYTES=0,
    DOWNLOAD_MODE='stream',
)
class MimeTests(TestCase):
    def test_guess_markdown(self):
        self.assertEqual(guess_mime_type('readme.md'), 'text/markdown')

    def test_mime_allowed_wildcard(self):
        self.assertTrue(mime_allowed('image/png', ['image/*']))
        self.assertFalse(mime_allowed('application/pdf', ['image/*']))

    def test_safe_path_rejects_traversal(self):
        with self.assertRaises(ValueError):
            safe_object_path('../secret')


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=1000,
    DEFAULT_USER_QUOTA_BYTES=0,
    DOWNLOAD_MODE='stream',
)
class QuotaTests(TestCase):
    def test_company_quota_blocks_overflow(self):
        assert_can_store(company_id=1, user_id=1, additional_bytes=500)
        CompanyQuota.objects.filter(company_id=1).update(used_bytes=800)
        with self.assertRaises(QuotaExceeded):
            assert_can_store(company_id=1, user_id=1, additional_bytes=300)

    def test_user_quota_override(self):
        CompanyQuota.objects.create(company_id=2, max_bytes=10_000, max_bytes_per_user=100)
        UserQuota.objects.create(company_id=2, user_id=5, max_bytes=50, used_bytes=40)
        with self.assertRaises(QuotaExceeded):
            assert_can_store(company_id=2, user_id=5, additional_bytes=20)


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
    DOWNLOAD_MODE='stream',
    MEDIA_ROOT='/tmp/shellui-storage-test-media',
)
class StorageAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.token = make_token()
        self.auth = {'HTTP_AUTHORIZATION': f'Bearer {self.token}'}
        self.jwks_patch = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = self.jwks_patch.start()
        mock_client.return_value.get_signing_key.return_value = None
        self.addCleanup(self.jwks_patch.stop)

    def test_health_public(self):
        response = self.client.get('/storage/v1/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'ok')

    def test_list_buckets_provisions_company_and_user(self):
        response = self.client.get('/storage/v1/bucket', **self.auth)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body), 2)
        kinds = {row['kind'] for row in body}
        self.assertEqual(kinds, {'company', 'user'})
        company = next(row for row in body if row['kind'] == 'company')
        personal = next(row for row in body if row['kind'] == 'user')
        self.assertEqual(company['name'], COMPANY_BUCKET_NAME)
        self.assertEqual(company['access']['audience'], 'company')
        self.assertEqual(personal['name'], user_bucket_name(1))
        self.assertEqual(personal['access']['audience'], 'owner')
        self.assertFalse(company['public'])

    def test_create_bucket_disabled(self):
        response = self.client.post(
            '/storage/v1/bucket',
            {'name': 'custom', 'public': False},
            format='json',
            **self.auth,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json().get('error'), 'bucket_create_disabled')

    def test_user_cannot_access_other_users_bucket(self):
        ensure_system_buckets(company_id=10, user_id=1)
        ensure_system_buckets(company_id=10, user_id=2)
        other = user_bucket_name(2)
        response = self.client.post(
            f'/storage/v1/object/{other}/secret.txt',
            data=b'secret',
            content_type='text/plain',
            **self.auth,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json().get('error'), 'bucket_access_denied')

    def test_company_bucket_upload_list_download(self):
        content = b'hello nested world'
        response = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/folder/hello.txt',
            data=content,
            content_type='text/plain',
            **self.auth,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('Key', response.json())

        listing = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': '', 'limit': 100},
            format='json',
            **self.auth,
        )
        self.assertEqual(listing.status_code, 200)
        names = [row['name'] for row in listing.json()]
        self.assertIn('folder', names)
        folder_row = next(row for row in listing.json() if row['name'] == 'folder')
        self.assertEqual(folder_row['access']['audience'], 'company')

        nested = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': 'folder', 'limit': 100},
            format='json',
            **self.auth,
        )
        self.assertIn('hello.txt', [row['name'] for row in nested.json()])
        file_row = next(row for row in nested.json() if row['name'] == 'hello.txt')
        self.assertEqual(file_row['access']['audience'], 'company')

        download = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/folder/hello.txt',
            **self.auth,
        )
        self.assertEqual(download.status_code, 200)
        self.assertEqual(b''.join(download.streaming_content), content)

    def test_personal_bucket_is_private_to_owner(self):
        personal = user_bucket_name(1)
        response = self.client.post(
            f'/storage/v1/object/{personal}/note.txt',
            data=b'private',
            content_type='text/plain',
            **self.auth,
        )
        self.assertEqual(response.status_code, 200)

        other_auth = {'HTTP_AUTHORIZATION': f'Bearer {make_token(user_id=2)}'}
        denied = self.client.get(
            f'/storage/v1/object/{personal}/note.txt',
            **other_auth,
        )
        self.assertEqual(denied.status_code, 403)

        # Other user still sees company bucket + their own personal bucket only.
        listing = self.client.get('/storage/v1/bucket', **other_auth)
        names = {row['name'] for row in listing.json()}
        self.assertIn(COMPANY_BUCKET_NAME, names)
        self.assertIn(user_bucket_name(2), names)
        self.assertNotIn(personal, names)

    def test_public_download_disabled(self):
        ensure_system_buckets(company_id=10, user_id=1)
        bucket = Bucket.objects.get(company_id=10, name=COMPANY_BUCKET_NAME)
        upload_object(
            bucket=bucket,
            path='logo.png',
            fileobj=io.BytesIO(b'png'),
            owner_id=1,
            content_type='image/png',
        )
        response = self.client.get(f'/storage/v1/object/public/{COMPANY_BUCKET_NAME}/logo.png')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json().get('error'), 'public_download_disabled')

    def test_missing_token_rejected(self):
        list_resp = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': '', 'limit': 10},
            format='json',
        )
        self.assertIn(list_resp.status_code, {401, 403})

    def _expired_auth(self):
        expired = jwt.encode(
            {
                'sub': '1',
                'user_id': 1,
                'company_id': 10,
                'email': 'user@example.com',
                'user_metadata': {'is_staff': False, 'is_company_owner': False},
                'exp': 1,
            },
            'test-secret',
            algorithm='HS256',
        )
        return {'HTTP_AUTHORIZATION': f'Bearer {expired}'}

    def test_expired_token_rejected_on_object_list(self):
        """Expired JWT must not list private company objects (data leak)."""
        auth = self._expired_auth()
        list_resp = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': '', 'limit': 10},
            format='json',
            **auth,
        )
        self.assertEqual(list_resp.status_code, 401)
        self.assertIn('expired', list_resp.json().get('detail', '').lower())

    def test_expired_token_rejected_on_bucket_list(self):
        """Expired JWT must not list buckets."""
        response = self.client.get('/storage/v1/bucket', **self._expired_auth())
        self.assertEqual(response.status_code, 401)
        self.assertIn('expired', response.json().get('detail', '').lower())

    def test_expired_token_rejected_on_object_download(self):
        """Expired JWT must not download or preview object bytes."""
        # Seed an object with a valid token first.
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/secret.txt',
            data=b'top-secret',
            content_type='text/plain',
            **self.auth,
        )
        response = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/secret.txt',
            **self._expired_auth(),
        )
        self.assertEqual(response.status_code, 401)
        body = response.json()
        self.assertIn('expired', body.get('detail', '').lower())
        # Response must not contain file bytes
        self.assertNotIn(b'top-secret', response.content)

    def test_expired_token_rejected_on_authenticated_download_alias(self):
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/secret2.txt',
            data=b'top-secret-2',
            content_type='text/plain',
            **self.auth,
        )
        response = self.client.get(
            f'/storage/v1/object/authenticated/{COMPANY_BUCKET_NAME}/secret2.txt',
            **self._expired_auth(),
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn('expired', response.json().get('detail', '').lower())
        self.assertNotIn(b'top-secret-2', response.content)

    def test_stats_endpoint(self):
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/note.md',
            data=b'# hi',
            content_type='text/markdown',
            **self.auth,
        )
        response = self.client.get('/storage/v1/stats', **self.auth)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertGreaterEqual(body['object_count'], 1)

    def test_folder_prefix_stats_and_delete(self):
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/reports/q1.txt',
            data=b'q1',
            content_type='text/plain',
            **self.auth,
        )
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/reports/nested/q2.txt',
            data=b'q2',
            content_type='text/plain',
            **self.auth,
        )
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/keep.txt',
            data=b'keep',
            content_type='text/plain',
            **self.auth,
        )

        stats = self.client.get(
            f'/storage/v1/object/prefix/{COMPANY_BUCKET_NAME}?prefix=reports',
            **self.auth,
        )
        self.assertEqual(stats.status_code, 200)
        self.assertEqual(stats.json()['file_count'], 2)

        deleted = self.client.delete(
            f'/storage/v1/object/prefix/{COMPANY_BUCKET_NAME}',
            {'prefix': 'reports'},
            format='json',
            **self.auth,
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json()['count'], 2)

        listing = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': '', 'limit': 100},
            format='json',
            **self.auth,
        )
        names = [row['name'] for row in listing.json()]
        self.assertIn('keep.txt', names)
        self.assertNotIn('reports', names)

    def test_delete_prunes_empty_filesystem_dirs(self):
        response = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/nested/file.txt',
            data=b'bye',
            content_type='text/plain',
            **self.auth,
        )
        self.assertEqual(response.status_code, 200)
        obj = StorageObject.objects.get(bucket__name=COMPANY_BUCKET_NAME, name='nested/file.txt')
        storage_key = obj.storage_key
        root = Path(default_storage.location)
        object_dir = (root / storage_key).parent
        self.assertTrue(object_dir.is_dir())

        deleted = self.client.delete(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/nested/file.txt',
            **self.auth,
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertFalse((object_dir / 'file.txt').exists())
        self.assertFalse(object_dir.exists())

    def test_quota_endpoint(self):
        response = self.client.get('/storage/v1/quota', **self.auth)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['company_id'], 10)

    def test_markdown_signal_stores_sidecar(self):
        md = b'# Title\n\nHello **world**.\n'
        response = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/readme.md',
            data=md,
            content_type='text/markdown',
            **self.auth,
        )
        self.assertEqual(response.status_code, 200)
        obj = StorageObject.objects.get(name='readme.md')
        self.assertIn('markdown_text', obj.metadata)
        self.assertIn('Title', obj.metadata['markdown_text'])

    def test_webdav_propfind_and_put(self):
        ensure_system_buckets(company_id=10, user_id=1)
        response = self.client.generic('PROPFIND', '/dav/', **self.auth, HTTP_DEPTH='1')
        self.assertEqual(response.status_code, 207)
        self.assertIn(COMPANY_BUCKET_NAME.encode(), response.content)

        response = self.client.put(
            f'/dav/{COMPANY_BUCKET_NAME}/notes/hello.md',
            data=b'# hi\n',
            content_type='text/markdown',
            **self.auth,
        )
        self.assertIn(response.status_code, (201, 204))
        self.assertTrue(
            StorageObject.objects.filter(
                bucket__name=COMPANY_BUCKET_NAME,
                name='notes/hello.md',
            ).exists()
        )

    def test_connector_bucket_hidden(self):
        Bucket.objects.create(
            company_id=10,
            name='sharepoint',
            kind=BucketKind.CONNECTOR,
            connector_provider='sharepoint',
            public=False,
        )
        response = self.client.get('/storage/v1/bucket', **self.auth)
        names = {row['name'] for row in response.json()}
        self.assertNotIn('sharepoint', names)


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
    DOWNLOAD_MODE='xaccel',
    X_ACCEL_REDIRECT_ENABLED=True,
    X_ACCEL_REDIRECT_PREFIX='/protected/',
    MEDIA_ROOT='/tmp/shellui-storage-test-media-xaccel',
)
class XAccelDownloadTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.token = make_token()
        self.auth = {'HTTP_AUTHORIZATION': f'Bearer {self.token}'}
        self.jwks_patch = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = self.jwks_patch.start()
        mock_client.return_value.get_signing_key.return_value = None
        self.addCleanup(self.jwks_patch.stop)

    def test_xaccel_header(self):
        company, _personal = ensure_system_buckets(company_id=10, user_id=1)
        upload_object(
            bucket=company,
            path='a.bin',
            fileobj=io.BytesIO(b'abc'),
            owner_id=1,
            content_type='application/octet-stream',
        )
        response = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/a.bin',
            **self.auth,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.has_header('X-Accel-Redirect'))
