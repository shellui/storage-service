"""Tests for storage-service."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import patch

import jwt
from django.core.files.storage import default_storage
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from datetime import timedelta

from django.utils import timezone

from apps.storage.access import COMPANY_BUCKET_NAME, ensure_company_bucket
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
    access_global_metrics: bool = False,
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
    if access_global_metrics:
        payload['pat_agm'] = True
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

    def test_list_buckets_provisions_company_only(self):
        response = self.client.get('/storage/v1/bucket', **self.auth)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body), 1)
        company = body[0]
        self.assertEqual(company['kind'], 'company')
        self.assertEqual(company['name'], COMPANY_BUCKET_NAME)
        self.assertEqual(company['access']['audience'], 'company')
        self.assertTrue(company['access']['shareable'])
        self.assertTrue(company['access']['grants_enabled'])
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
        # Nested upload without ancestor grants → object is private to creator.
        nested = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': 'folder', 'limit': 100},
            format='json',
            **self.auth,
        )
        self.assertIn('hello.txt', [row['name'] for row in nested.json()])
        file_row = next(row for row in nested.json() if row['name'] == 'hello.txt')
        self.assertEqual(file_row['access']['audience'], 'restricted')
        self.assertIn('1', file_row['access'].get('allowed_user_ids') or [])

        download = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/folder/hello.txt',
            **self.auth,
        )
        self.assertEqual(download.status_code, 200)
        self.assertEqual(b''.join(download.streaming_content), content)

        other_auth = {'HTTP_AUTHORIZATION': f'Bearer {make_token(user_id=2)}'}
        denied = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/folder/hello.txt',
            **other_auth,
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json().get('error'), 'path_access_denied')

    def test_upload_private_by_default(self):
        upload = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/solo.txt',
            data=b'mine',
            content_type='text/plain',
            **self.auth,
        )
        self.assertEqual(upload.status_code, 200)

        listing = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': '', 'limit': 100},
            format='json',
            **self.auth,
        )
        row = next(r for r in listing.json() if r['name'] == 'solo.txt')
        self.assertEqual(row['access']['audience'], 'restricted')

        other_auth = {'HTTP_AUTHORIZATION': f'Bearer {make_token(user_id=2)}'}
        denied = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/solo.txt',
            **other_auth,
        )
        self.assertEqual(denied.status_code, 403)

        other_list = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': '', 'limit': 100},
            format='json',
            **other_auth,
        )
        self.assertEqual(other_list.status_code, 200)
        self.assertNotIn('solo.txt', [r['name'] for r in other_list.json()])

    def test_empty_folder_placeholder_is_private(self):
        upload = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/projects/.emptyFolderPlaceholder',
            data=b'',
            content_type='application/octet-stream',
            **self.auth,
        )
        self.assertEqual(upload.status_code, 200)

        listing = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': '', 'limit': 100},
            format='json',
            **self.auth,
        )
        folder_row = next(r for r in listing.json() if r['name'] == 'projects')
        self.assertEqual(folder_row['access']['audience'], 'restricted')
        self.assertIn('1', folder_row['access'].get('allowed_user_ids') or [])
        self.assertIsNone(folder_row['id'])
        self.assertEqual(folder_row['folder_id'], upload.json()['Id'])

    def test_resolve_folder_id_survives_rename(self):
        created = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/projects/.emptyFolderPlaceholder',
            data=b'',
            content_type='application/octet-stream',
            **self.auth,
        )
        self.assertEqual(created.status_code, 200)
        folder_id = created.json()['Id']

        renamed = self.client.post(
            f'/storage/v1/object/prefix/{COMPANY_BUCKET_NAME}',
            {'from': 'projects', 'to': 'renamed-projects'},
            format='json',
            **self.auth,
        )
        self.assertEqual(renamed.status_code, 200)

        resolved = self.client.get(
            f'/storage/v1/object/id/{folder_id}',
            **self.auth,
        )
        self.assertEqual(resolved.status_code, 200)
        body = resolved.json()
        self.assertEqual(body['id'], folder_id)
        self.assertEqual(body['type'], 'folder')
        self.assertEqual(body['path'], 'renamed-projects')
        self.assertEqual(body['name'], 'renamed-projects')
        self.assertEqual(body['bucket'], COMPANY_BUCKET_NAME)

    def test_nested_inherits_folder_grants(self):
        # Create private folder via placeholder, then upload nested file — inherits.
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/.emptyFolderPlaceholder',
            data=b'',
            content_type='application/octet-stream',
            **self.auth,
        )
        nested = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/secret.txt',
            data=b'secret',
            content_type='text/plain',
            **self.auth,
        )
        self.assertEqual(nested.status_code, 200)

        listing = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': 'vault', 'limit': 100},
            format='json',
            **self.auth,
        )
        file_row = next(r for r in listing.json() if r['name'] == 'secret.txt')
        self.assertEqual(file_row['access']['audience'], 'restricted')

        # No object-level grants — inheritance from folder only.
        from apps.storage.models import StorageAccessGrant

        object_grants = StorageAccessGrant.objects.filter(
            resource_type='object',
            resource_id='vault/secret.txt',
        )
        self.assertEqual(object_grants.count(), 0)
        folder_grants = StorageAccessGrant.objects.filter(
            resource_type='folder',
            resource_id='vault',
        )
        self.assertEqual(folder_grants.count(), 2)

        other_auth = {'HTTP_AUTHORIZATION': f'Bearer {make_token(user_id=2)}'}
        denied = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/secret.txt',
            **other_auth,
        )
        self.assertEqual(denied.status_code, 403)

        # Manual grant lets another user in.
        allow = self.client.post(
            '/storage/v1/access/grant',
            {
                'bucket': COMPANY_BUCKET_NAME,
                'subject_type': 'user',
                'subject_id': '2',
                'resource_type': 'folder',
                'resource_id': 'vault',
                'permission': 'read',
                'effect': 'allow',
            },
            format='json',
            **self.auth,
        )
        self.assertEqual(allow.status_code, 201)
        allowed = self.client.get(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/secret.txt',
            **other_auth,
        )
        self.assertEqual(allowed.status_code, 200)

    def test_nested_folder_copies_parent_grants(self):
        """Nested folder materializes parent ACL (not company-open with empty grants)."""
        from apps.storage.models import StorageAccessGrant

        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/.emptyFolderPlaceholder',
            data=b'',
            content_type='application/octet-stream',
            **self.auth,
        )
        # Share parent with user 2 before creating nested folder.
        self.client.post(
            '/storage/v1/access/grant',
            {
                'bucket': COMPANY_BUCKET_NAME,
                'subject_type': 'user',
                'subject_id': '2',
                'resource_type': 'folder',
                'resource_id': 'vault',
                'permission': 'read',
                'effect': 'allow',
            },
            format='json',
            **self.auth,
        )

        nested = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/team/.emptyFolderPlaceholder',
            data=b'',
            content_type='application/octet-stream',
            **self.auth,
        )
        self.assertEqual(nested.status_code, 200)

        team_grants = list(
            StorageAccessGrant.objects.filter(resource_type='folder', resource_id='vault/team')
        )
        # deny company + allow user 1 + allow user 2 (copied from parent)
        self.assertEqual(len(team_grants), 3)
        subjects = {(g.effect, g.subject_type, g.subject_id) for g in team_grants}
        self.assertIn(('deny', 'company', '10'), subjects)
        self.assertIn(('allow', 'user', '1'), subjects)
        self.assertIn(('allow', 'user', '2'), subjects)

        listing = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': 'vault', 'limit': 100},
            format='json',
            **self.auth,
        )
        team_row = next(r for r in listing.json() if r['name'] == 'team')
        self.assertEqual(team_row['access']['audience'], 'restricted')
        self.assertEqual(set(team_row['access'].get('allowed_user_ids') or []), {'1', '2'})

        other_auth = {'HTTP_AUTHORIZATION': f'Bearer {make_token(user_id=2)}'}
        # User 2 can list/see under vault/team (read via copied grant).
        other_list = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': 'vault/team', 'limit': 100},
            format='json',
            **other_auth,
        )
        self.assertEqual(other_list.status_code, 200)

        stranger = {'HTTP_AUTHORIZATION': f'Bearer {make_token(user_id=3)}'}
        stranger_list = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': 'vault', 'limit': 100},
            format='json',
            **stranger,
        )
        self.assertNotIn('team', [r['name'] for r in stranger_list.json()])

    def test_cannot_make_nested_folder_public_while_parent_private(self):
        """Removing company deny under a private parent must fail with a clear error."""
        from apps.storage.models import StorageAccessGrant

        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/.emptyFolderPlaceholder',
            data=b'',
            content_type='application/octet-stream',
            **self.auth,
        )
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/team/.emptyFolderPlaceholder',
            data=b'',
            content_type='application/octet-stream',
            **self.auth,
        )

        deny = StorageAccessGrant.objects.get(
            resource_type='folder',
            resource_id='vault/team',
            effect='deny',
            subject_type='company',
        )
        resp = self.client.delete(
            f'/storage/v1/access/grant/{deny.id}',
            **self.auth,
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.json()
        self.assertEqual(body.get('error'), 'parent_folder_private')
        self.assertIn('vault', body.get('message', ''))
        self.assertIn('private', body.get('message', '').lower())

        # Company allow on nested path is also blocked (would pierce parent).
        allow_company = self.client.post(
            '/storage/v1/access/grant',
            {
                'bucket': COMPANY_BUCKET_NAME,
                'subject_type': 'company',
                'subject_id': '10',
                'resource_type': 'folder',
                'resource_id': 'vault/team',
                'permission': 'read',
                'effect': 'allow',
            },
            format='json',
            **self.auth,
        )
        self.assertEqual(allow_company.status_code, 400)
        self.assertEqual(allow_company.json().get('error'), 'parent_folder_private')

        # Opening the parent first, then the nested folder, works.
        for g in StorageAccessGrant.objects.filter(resource_type='folder', resource_id='vault'):
            self.client.delete(f'/storage/v1/access/grant/{g.id}', **self.auth)
        # Parent no longer private — nested make-public should succeed.
        resp2 = self.client.delete(
            f'/storage/v1/access/grant/{deny.id}',
            **self.auth,
        )
        self.assertEqual(resp2.status_code, 204)

    def test_cannot_make_nested_file_public_while_parent_private(self):
        """Same rule for files: cannot remove object company-deny under a private folder."""
        from apps.storage.models import StorageAccessGrant

        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/.emptyFolderPlaceholder',
            data=b'',
            content_type='application/octet-stream',
            **self.auth,
        )
        # File with its own private grants (e.g. made private locally).
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/note.txt',
            data=b'note',
            content_type='text/plain',
            **self.auth,
        )
        # Nested upload inherits — add object-level private grants explicitly
        # (allow first so the creator is not locked out by the company deny).
        allow_self = self.client.post(
            '/storage/v1/access/grant',
            {
                'bucket': COMPANY_BUCKET_NAME,
                'subject_type': 'user',
                'subject_id': '1',
                'resource_type': 'object',
                'resource_id': 'vault/note.txt',
                'permission': 'admin',
                'effect': 'allow',
            },
            format='json',
            **self.auth,
        )
        self.assertEqual(allow_self.status_code, 201)
        deny = self.client.post(
            '/storage/v1/access/grant',
            {
                'bucket': COMPANY_BUCKET_NAME,
                'subject_type': 'company',
                'subject_id': '10',
                'resource_type': 'object',
                'resource_id': 'vault/note.txt',
                'permission': 'read',
                'effect': 'deny',
            },
            format='json',
            **self.auth,
        )
        self.assertEqual(deny.status_code, 201)

        effective = self.client.get(
            '/storage/v1/access/grant',
            {
                'bucket': COMPANY_BUCKET_NAME,
                'resource_type': 'object',
                'resource_id': 'vault/note.txt',
                'include_effective': '1',
            },
            **self.auth,
        )
        self.assertEqual(effective.status_code, 200)
        body = effective.json()
        self.assertEqual(body.get('private_ancestor'), 'vault')
        self.assertTrue(any(g['effect'] == 'deny' for g in body.get('grants') or []))

        grant_id = deny.json()['id']
        resp = self.client.delete(
            f'/storage/v1/access/grant/{grant_id}',
            **self.auth,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.json().get('error'), 'parent_folder_private')
        self.assertIn('vault', resp.json().get('message', ''))

        # Company allow on the file is also blocked.
        allow = self.client.post(
            '/storage/v1/access/grant',
            {
                'bucket': COMPANY_BUCKET_NAME,
                'subject_type': 'company',
                'subject_id': '10',
                'resource_type': 'object',
                'resource_id': 'vault/note.txt',
                'permission': 'read',
                'effect': 'allow',
            },
            format='json',
            **self.auth,
        )
        self.assertEqual(allow.status_code, 400)
        self.assertEqual(allow.json().get('error'), 'parent_folder_private')

    def test_public_download_disabled(self):
        ensure_company_bucket(company_id=10)
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

    def test_folder_rename_moves_objects_and_grants(self):
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
        owner_auth = {
            'HTTP_AUTHORIZATION': f'Bearer {make_token(user_id=1, is_company_owner=True)}'
        }
        deny = self.client.post(
            '/storage/v1/access/grant',
            {
                'bucket': COMPANY_BUCKET_NAME,
                'subject_type': 'company',
                'subject_id': '10',
                'resource_type': 'folder',
                'resource_id': 'reports',
                'permission': 'read',
                'effect': 'deny',
            },
            format='json',
            **owner_auth,
        )
        self.assertEqual(deny.status_code, 201)
        deny_id = deny.json()['id']
        allow = self.client.post(
            '/storage/v1/access/grant',
            {
                'bucket': COMPANY_BUCKET_NAME,
                'subject_type': 'user',
                'subject_id': '1',
                'resource_type': 'folder',
                'resource_id': 'reports',
                'permission': 'write',
                'effect': 'allow',
            },
            format='json',
            **owner_auth,
        )
        self.assertEqual(allow.status_code, 201)
        allow_id = allow.json()['id']

        renamed = self.client.post(
            f'/storage/v1/object/prefix/{COMPANY_BUCKET_NAME}',
            {'from': 'reports', 'to': 'archives'},
            format='json',
            **self.auth,
        )
        self.assertEqual(renamed.status_code, 200)
        body = renamed.json()
        self.assertEqual(body['from'], 'reports')
        self.assertEqual(body['to'], 'archives')
        self.assertEqual(body['moved'], 2)
        # Includes auto-private grants on the folder tree, plus our deny/allow.
        self.assertGreaterEqual(body['grants_updated'], 2)

        listing = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': '', 'limit': 100},
            format='json',
            **self.auth,
        )
        names = [row['name'] for row in listing.json()]
        self.assertIn('archives', names)
        self.assertNotIn('reports', names)

        nested = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': 'archives', 'limit': 100},
            format='json',
            **self.auth,
        )
        nested_names = [row['name'] for row in nested.json()]
        self.assertIn('q1.txt', nested_names)
        self.assertIn('nested', nested_names)

        grants = self.client.get(
            '/storage/v1/access/grant',
            {'resource_type': 'folder', 'resource_id': 'archives', 'bucket': COMPANY_BUCKET_NAME},
            **owner_auth,
        )
        self.assertEqual(grants.status_code, 200)
        by_id = {g['id']: g for g in grants.json()}
        self.assertEqual(by_id[deny_id]['resource_id'], 'archives')
        self.assertEqual(by_id[allow_id]['resource_id'], 'archives')

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
        ensure_company_bucket(company_id=10)
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

    def test_webdav_href_encodes_spaces(self):
        """PROPFIND hrefs must percent-encode spaces so clients keep the entry."""
        ensure_company_bucket(company_id=10)
        # Make company-open so grants don't obscure the encoding check.
        from apps.storage.models import StorageAccessGrant

        upload = self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/My Report.pdf',
            data=b'%PDF',
            content_type='application/pdf',
            **self.auth,
        )
        self.assertEqual(upload.status_code, 200)
        StorageAccessGrant.objects.filter(
            resource_id='My Report.pdf',
            subject_type='company',
            effect='deny',
        ).delete()

        dav = self.client.generic(
            'PROPFIND',
            f'/dav/{COMPANY_BUCKET_NAME}/',
            **self.auth,
            HTTP_DEPTH='1',
        )
        self.assertEqual(dav.status_code, 207)
        body = dav.content.decode()
        self.assertIn('/dav/company/My%20Report.pdf', body)
        self.assertNotIn('/dav/company/My%20Report.pdf/', body)
        self.assertIn('My Report.pdf', body)  # displayname stays human-readable
        self.assertIn('getcontentlength', body)

        # GET via encoded URL works.
        got = self.client.get(
            f'/dav/{COMPANY_BUCKET_NAME}/My%20Report.pdf',
            **self.auth,
        )
        self.assertEqual(got.status_code, 200)

        # PROPFIND on the file must not synthesize an empty folder.
        file_prop = self.client.generic(
            'PROPFIND',
            f'/dav/{COMPANY_BUCKET_NAME}/My%20Report.pdf',
            **self.auth,
            HTTP_DEPTH='0',
        )
        self.assertEqual(file_prop.status_code, 207)
        self.assertNotIn(b'collection', file_prop.content)
        self.assertIn(b'getcontentlength', file_prop.content)

        missing = self.client.generic(
            'PROPFIND',
            f'/dav/{COMPANY_BUCKET_NAME}/does-not-exist',
            **self.auth,
            HTTP_DEPTH='1',
        )
        self.assertEqual(missing.status_code, 404)

    def test_webdav_respects_path_grants(self):
        """WebDAV listings must match REST ACL: hide private paths, show company-open files."""
        from apps.storage.models import StorageAccessGrant

        ensure_company_bucket(company_id=10)

        # Private folder + nested file (private to user 1).
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/.emptyFolderPlaceholder',
            data=b'',
            content_type='application/octet-stream',
            **self.auth,
        )
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/vault/secret.txt',
            data=b'secret',
            content_type='text/plain',
            **self.auth,
        )

        # Company-open file (upload private, then remove auto company deny).
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/open.txt',
            data=b'hello',
            content_type='text/plain',
            **self.auth,
        )
        StorageAccessGrant.objects.filter(
            resource_type='object',
            resource_id='open.txt',
            subject_type='company',
            effect='deny',
        ).delete()

        other_auth = {'HTTP_AUTHORIZATION': f'Bearer {make_token(user_id=2)}'}

        rest = self.client.post(
            f'/storage/v1/object/list/{COMPANY_BUCKET_NAME}',
            {'prefix': '', 'limit': 100},
            format='json',
            **other_auth,
        )
        self.assertEqual(rest.status_code, 200)
        rest_names = [r['name'] for r in rest.json()]
        self.assertIn('open.txt', rest_names)
        self.assertNotIn('vault', rest_names)

        dav = self.client.generic(
            'PROPFIND',
            f'/dav/{COMPANY_BUCKET_NAME}/',
            **other_auth,
            HTTP_DEPTH='1',
        )
        self.assertEqual(dav.status_code, 207)
        body = dav.content.decode()
        self.assertIn('open.txt', body)
        self.assertNotIn('vault', body)
        self.assertNotIn('secret.txt', body)

        # Direct PROPFIND on private folder must be forbidden (not an empty collection).
        denied_folder = self.client.generic(
            'PROPFIND',
            f'/dav/{COMPANY_BUCKET_NAME}/vault',
            **other_auth,
            HTTP_DEPTH='1',
        )
        self.assertEqual(denied_folder.status_code, 403)

        denied_file = self.client.generic(
            'PROPFIND',
            f'/dav/{COMPANY_BUCKET_NAME}/vault/secret.txt',
            **other_auth,
            HTTP_DEPTH='0',
        )
        self.assertEqual(denied_file.status_code, 403)

        # Owner still sees private folder via WebDAV.
        owner = self.client.generic(
            'PROPFIND',
            f'/dav/{COMPANY_BUCKET_NAME}/',
            **self.auth,
            HTTP_DEPTH='1',
        )
        self.assertEqual(owner.status_code, 207)
        self.assertIn(b'vault', owner.content)
        self.assertIn(b'open.txt', owner.content)

    def test_webdav_mkcol_lists_for_creator_only(self):
        ensure_company_bucket(company_id=10)
        created = self.client.generic(
            'MKCOL',
            f'/dav/{COMPANY_BUCKET_NAME}/emptydir',
            **self.auth,
        )
        self.assertEqual(created.status_code, 201)

        owner = self.client.generic(
            'PROPFIND',
            f'/dav/{COMPANY_BUCKET_NAME}/',
            **self.auth,
            HTTP_DEPTH='1',
        )
        self.assertEqual(owner.status_code, 207)
        self.assertIn(b'emptydir', owner.content)

        other_auth = {'HTTP_AUTHORIZATION': f'Bearer {make_token(user_id=2)}'}
        other = self.client.generic(
            'PROPFIND',
            f'/dav/{COMPANY_BUCKET_NAME}/',
            **other_auth,
            HTTP_DEPTH='1',
        )
        self.assertEqual(other.status_code, 207)
        self.assertNotIn(b'emptydir', other.content)

    def test_connector_bucket_read_only(self):
        Bucket.objects.create(
            company_id=10,
            name='sharepoint',
            kind=BucketKind.CONNECTOR,
            connector_provider='sharepoint',
            public=False,
        )
        response = self.client.get('/storage/v1/bucket', **self.auth)
        rows = {row['name']: row for row in response.json()}
        self.assertIn('sharepoint', rows)
        self.assertFalse(rows['sharepoint']['access']['can_write'])
        self.assertEqual(rows['sharepoint']['access']['writers'], 'none')

        denied_write = self.client.post(
            '/storage/v1/object/sharepoint/file.txt',
            data=b'x',
            content_type='text/plain',
            **self.auth,
        )
        self.assertEqual(denied_write.status_code, 403)

    def test_share_link_expiry_and_max_downloads(self):
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/deck.pdf',
            data=b'%PDF-1.4',
            content_type='application/pdf',
            **self.auth,
        )
        created = self.client.post(
            f'/storage/v1/share/{COMPANY_BUCKET_NAME}/deck.pdf',
            {
                'max_downloads': 1,
                'expires_at': (timezone.now() + timedelta(hours=1)).isoformat(),
            },
            format='json',
            **self.auth,
        )
        self.assertEqual(created.status_code, 201)
        token = created.json()['token']
        self.assertTrue(token)

        # Anonymous redeem (no auth).
        first = self.client.get(f'/storage/v1/share/link/{token}')
        self.assertEqual(first.status_code, 200)
        self.assertEqual(b''.join(first.streaming_content), b'%PDF-1.4')

        second = self.client.get(f'/storage/v1/share/link/{token}')
        self.assertEqual(second.status_code, 410)
        self.assertEqual(second.json().get('error'), 'share_inactive')

        # No public directory of share tokens.
        listing = self.client.get(
            f'/storage/v1/share/{COMPANY_BUCKET_NAME}/deck.pdf',
            **self.auth,
        )
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(len(listing.json()), 1)

    def test_share_link_requires_limit(self):
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/a.txt',
            data=b'a',
            content_type='text/plain',
            **self.auth,
        )
        response = self.client.post(
            f'/storage/v1/share/{COMPANY_BUCKET_NAME}/a.txt',
            {},
            format='json',
            **self.auth,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json().get('error'), 'share_limit_required')

    def test_share_link_revoke(self):
        self.client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/b.txt',
            data=b'b',
            content_type='text/plain',
            **self.auth,
        )
        created = self.client.post(
            f'/storage/v1/share/{COMPANY_BUCKET_NAME}/b.txt',
            {'max_downloads': 10},
            format='json',
            **self.auth,
        )
        token = created.json()['token']
        revoked = self.client.delete(f'/storage/v1/share/link/{token}', **self.auth)
        self.assertEqual(revoked.status_code, 200)
        self.assertIsNotNone(revoked.json().get('revoked_at'))
        response = self.client.get(f'/storage/v1/share/link/{token}')
        self.assertEqual(response.status_code, 410)


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
        company = ensure_company_bucket(company_id=10)
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
