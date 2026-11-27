"""Who an agent acts as: its creator, or nobody. Plus sharing limits and upload safety."""

from __future__ import annotations

import hashlib
import io
import uuid
from io import StringIO
from unittest.mock import patch

import jwt
from django.core.files.storage import default_storage
from django.core.management import call_command
from django.db import connection
from django.test import TestCase, TransactionTestCase, override_settings
from rest_framework.test import APIClient

from apps.authapi.agent_tokens import authenticate_agent_bearer, principal_from_agent_claims
from apps.authapi.principal import StoragePrincipal
from apps.storage.access import (
    COMPANY_BUCKET_NAME,
    can_access_path,
    ensure_company_bucket,
)
from apps.storage.grants import create_grant, delete_grant
from apps.storage.models import CompanyQuota, StorageAccessGrant, StorageObject
from apps.storage.services import StorageError, upload_object
from apps.storage.shares import create_share_link
from apps.storage.tests.test_storage import make_token

COMPANY = 10


def _agent_principal(user_id: int, *, owner: bool = False) -> StoragePrincipal:
    claims = {
        'sub': f'agent:{uuid.uuid4()}',
        'agent_id': str(uuid.uuid4()),
        'company_id': COMPANY,
        'token_type': 'access',
        'scope': 'storage',
    }
    if user_id:
        claims['owner_user_id'] = user_id
        claims['owner_is_company_owner'] = owner
    return principal_from_agent_claims(claims)


def _human(user_id: int, *, owner: bool = False) -> StoragePrincipal:
    return StoragePrincipal(user_id=user_id, company_id=COMPANY, is_company_owner=owner)


class _Base(TestCase):
    def setUp(self):
        self.bucket = ensure_company_bucket(company_id=COMPANY)

    def upload(self, name: str, owner_id: int | None, data: bytes = b'data'):
        return upload_object(
            bucket=self.bucket,
            path=name,
            fileobj=io.BytesIO(data),
            owner_id=owner_id,
            content_type='text/plain',
        )


class AgentActsAsCreatorTests(_Base):
    def test_personal_agent_gets_its_creators_files_and_not_anyone_elses(self):
        mine = self.upload('mine.txt', 7)
        theirs = self.upload('theirs.txt', 8)
        agent = _agent_principal(7)
        self.assertEqual(agent.user_id, 7)
        for write, admin in ((False, False), (True, False), (False, True)):
            self.assertTrue(can_access_path(agent, self.bucket, mine.name, write=write, admin=admin))
            self.assertFalse(can_access_path(agent, self.bucket, theirs.name, write=write, admin=admin))

    def test_agent_has_the_same_file_access_as_its_creator(self):
        mine = self.upload('mine.txt', 7)
        agent, human = _agent_principal(7), _human(7)
        for write, admin in ((False, False), (True, False), (False, True)):
            self.assertEqual(
                can_access_path(agent, self.bucket, mine.name, write=write, admin=admin),
                can_access_path(human, self.bucket, mine.name, write=write, admin=admin),
            )

    def test_creator_role_comes_from_the_signed_claim_only(self):
        self.assertTrue(_agent_principal(7, owner=True).is_company_owner)
        self.assertFalse(_agent_principal(7, owner=False).is_company_owner)
        claims = {
            'sub': 'agent:x',
            'agent_id': 'x',
            'company_id': COMPANY,
            'owner_user_id': 7,
            'owner_is_company_owner': 'true',
            'user_metadata': {'is_company_owner': True, 'is_staff': True},
            'is_company_owner': True,
        }
        principal = principal_from_agent_claims(claims)
        self.assertFalse(principal.is_company_owner)
        self.assertFalse(principal.is_staff)
        no_owner = principal_from_agent_claims(
            {'sub': 'agent:x', 'agent_id': 'x', 'company_id': COMPANY, 'owner_is_company_owner': True}
        )
        self.assertEqual(no_owner.user_id, 0)
        self.assertFalse(no_owner.is_company_owner)

    def test_missing_role_claim_is_a_plain_member(self):
        # A token minted before identity sent the claim, or by an older identity, has an owner
        # id and no owner_is_company_owner. The creator is treated as a member, never an owner.
        claims = {
            'sub': 'agent:x',
            'agent_id': 'x',
            'company_id': COMPANY,
            'token_type': 'access',
            'owner_user_id': 7,
        }
        self.assertNotIn('owner_is_company_owner', claims)
        principal = principal_from_agent_claims(claims)
        self.assertEqual(principal.user_id, 7)
        self.assertFalse(principal.is_company_owner)
        self.assertFalse(principal.is_staff)
        for bad in (None, 1, 0, 'true', 'True', [True], {'v': True}):
            with self.subTest(claim=bad):
                self.assertFalse(
                    principal_from_agent_claims({**claims, 'owner_is_company_owner': bad}).is_company_owner
                )

    def test_owner_agent_is_not_staff_and_cannot_read_others_private_files(self):
        theirs = self.upload('theirs.txt', 8)
        agent = _agent_principal(7, owner=True)
        self.assertFalse(agent.is_staff)
        self.assertFalse(can_access_path(agent, self.bucket, theirs.name))


class OwnerlessAgentTests(_Base):
    def test_user_zero_never_matches_a_private_file(self):
        private = self.upload('private.txt', 7)
        agent = _agent_principal(0)
        self.assertEqual(agent.user_id, 0)
        for write, admin in ((False, False), (True, False), (False, True)):
            self.assertFalse(can_access_path(agent, self.bucket, private.name, write=write, admin=admin))

    def test_user_zero_grant_never_gives_an_ownerless_agent_access(self):
        obj = self.upload('legacy.txt', 7)
        StorageAccessGrant.objects.filter(object=obj).delete()
        for subject_type, subject_id, effect, permission in (
            ('company', str(COMPANY), 'deny', 'read'),
            ('user', '0', 'allow', 'admin'),
        ):
            StorageAccessGrant.objects.create(
                company_id=COMPANY,
                bucket=self.bucket,
                object=obj,
                resource_type='object',
                subject_type=subject_type,
                subject_id=subject_id,
                effect=effect,
                permission=permission,
            )
        agent = _agent_principal(0)
        self.assertFalse(can_access_path(agent, self.bucket, obj.name))
        self.assertFalse(can_access_path(agent, self.bucket, obj.name, write=True))
        self.assertFalse(can_access_path(agent, self.bucket, obj.name, admin=True))

    def test_company_visible_files_stay_available_at_the_agents_role(self):
        shared = self.upload('shared.txt', None)
        agent = _agent_principal(0)
        self.assertTrue(can_access_path(agent, self.bucket, shared.name))
        self.assertTrue(can_access_path(agent, self.bucket, shared.name, write=True))
        self.assertFalse(can_access_path(agent, self.bucket, shared.name, admin=True))

    def test_ownerless_agent_cannot_upload_a_private_file(self):
        with self.assertRaises(StorageError) as caught:
            self.upload('new.txt', 0)
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(caught.exception.code, 'agent_has_no_owner')
        self.assertIn('no creating user', str(caught.exception))
        self.assertFalse(StorageObject.objects.filter(name='new.txt').exists())
        self.assertFalse(StorageAccessGrant.objects.filter(subject_type='user', subject_id='0').exists())

    def test_ownerless_refusal_leaves_no_blob_and_no_quota_change(self):
        before = set(default_storage.listdir('')[1]) if default_storage.exists('') else set()
        with self.assertRaises(StorageError):
            self.upload('new.txt', 0, b'x' * 100)
        quota = CompanyQuota.objects.filter(company_id=COMPANY).first()
        self.assertTrue(quota is None or quota.used_bytes == 0)
        after = set(default_storage.listdir('')[1]) if default_storage.exists('') else set()
        self.assertEqual(before, after)


class LegacyUserZeroFilesTests(_Base):
    def _legacy_file(self):
        obj = self.upload('legacy.txt', 7)
        StorageObject.objects.filter(pk=obj.pk).update(owner_id=0)
        StorageAccessGrant.objects.filter(object=obj, subject_type='user').update(subject_id='0')
        return obj

    def test_company_owner_reaches_and_manages_legacy_files(self):
        obj = self._legacy_file()
        owner = _human(1, owner=True)
        for write, admin in ((False, False), (True, False), (False, True)):
            self.assertTrue(can_access_path(owner, self.bucket, obj.name, write=write, admin=admin))

    def test_staff_reaches_legacy_files(self):
        obj = self._legacy_file()
        staff = StoragePrincipal(user_id=2, company_id=COMPANY, is_staff=True)
        self.assertTrue(can_access_path(staff, self.bucket, obj.name, admin=True))

    def test_members_and_personal_agents_do_not(self):
        obj = self._legacy_file()
        for principal in (_human(3), _agent_principal(3), _agent_principal(7), _agent_principal(0)):
            self.assertFalse(can_access_path(principal, self.bucket, obj.name), principal)

    def test_data_migration_labels_user_zero_grants_and_keeps_them(self):
        from importlib import import_module

        from django.apps import apps as django_apps

        obj = self._legacy_file()
        migration = import_module('apps.storage.migrations.0008_unowned_agent_files')
        migration.label_unowned_grants(django_apps, None)
        grants = StorageAccessGrant.objects.filter(object=obj, subject_type='user', subject_id='0')
        self.assertTrue(grants.exists())
        self.assertTrue(all('company owners' in g.notes for g in grants))
        self.assertTrue(StorageObject.objects.filter(pk=obj.pk).exists())

    def test_reassign_command_moves_files_grants_and_usage_to_a_user(self):
        obj = self._legacy_file()
        CompanyQuota.objects.update_or_create(
            company_id=COMPANY, defaults={'max_bytes': 10**9, 'used_bytes': obj.size}
        )
        out = StringIO()
        call_command('reassign_unowned_files', company=COMPANY, user=9, dry_run=True, stdout=out)
        self.assertIn('Would reassign 1 object', out.getvalue())
        self.assertEqual(StorageObject.objects.get(pk=obj.pk).owner_id, 0)

        call_command('reassign_unowned_files', company=COMPANY, user=9, stdout=StringIO())
        self.assertEqual(StorageObject.objects.get(pk=obj.pk).owner_id, 9)
        self.assertTrue(
            StorageAccessGrant.objects.filter(object=obj, subject_type='user', subject_id='9').exists()
        )
        self.assertFalse(
            StorageAccessGrant.objects.filter(object=obj, subject_type='user', subject_id='0').exists()
        )
        self.assertTrue(can_access_path(_agent_principal(9), self.bucket, obj.name, admin=True))
        self.assertEqual(CompanyQuota.objects.get(company_id=COMPANY).used_bytes, obj.size)


class AgentSharingTests(_Base):
    def test_agent_cannot_create_a_grant_widen_or_delete_one(self):
        obj = self.upload('mine.txt', 7)
        agent = _agent_principal(7, owner=True)
        for data in (
            {'subject_type': 'company', 'subject_id': str(COMPANY), 'resource_type': 'object',
             'resource_id': obj.name, 'permission': 'read'},
            {'subject_type': 'user', 'subject_id': '99', 'resource_type': 'object',
             'resource_id': obj.name, 'permission': 'admin'},
        ):
            with self.assertRaises(StorageError) as caught:
                create_grant(principal=agent, data=data)
            self.assertEqual(caught.exception.code, 'agent_cannot_share')
        deny = StorageAccessGrant.objects.filter(object=obj, effect='deny').first()
        with self.assertRaises(StorageError) as caught:
            delete_grant(principal=agent, grant_id=str(deny.id))
        self.assertEqual(caught.exception.code, 'agent_cannot_share')
        self.assertTrue(StorageAccessGrant.objects.filter(pk=deny.pk).exists())

    def test_agent_cannot_create_a_share_link(self):
        obj = self.upload('mine.txt', 7)
        with self.assertRaises(StorageError) as caught:
            create_share_link(
                principal=_agent_principal(7, owner=True),
                bucket_name=COMPANY_BUCKET_NAME,
                path=obj.name,
                max_downloads=1,
            )
        self.assertEqual(caught.exception.code, 'agent_cannot_share')

    def test_a_person_can_still_share(self):
        obj = self.upload('mine.txt', 7)
        grant = create_grant(
            principal=_human(7),
            data={'subject_type': 'user', 'subject_id': '8', 'resource_type': 'object',
                  'resource_id': obj.name, 'permission': 'read'},
        )
        self.assertEqual(grant.subject_id, '8')


def _agent_http_token(*, owner_user_id: int | None, token_type: str = 'access') -> str:
    payload = {
        'sub': 'agent:abc',
        'token_type': token_type,
        'agent_id': 'abc',
        'company_id': COMPANY,
        'scope': 'storage',
        'exp': 2**31 - 1,
    }
    if owner_user_id:
        payload['owner_user_id'] = owner_user_id
    return jwt.encode(payload, 'test-secret', algorithm='HS256')


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    IDENTITY_AUDIENCE='',
    IDENTITY_ISSUER='',
    DEBUG=True,
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
)
class AgentTokensOffMcpTests(TestCase):
    def setUp(self):
        self.bucket = ensure_company_bucket(company_id=COMPANY)
        self.obj = upload_object(
            bucket=self.bucket, path='a.txt', fileobj=io.BytesIO(b'hi'), owner_id=7, content_type='text/plain'
        )
        jwks = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = jwks.start()
        mock_client.return_value.get_signing_key.return_value = None
        mock_client.return_value.key_count.return_value = 0
        mock_client.return_value.key_ids.return_value = []
        self.addCleanup(jwks.stop)
        self.client = APIClient()
        self.auth = {'HTTP_AUTHORIZATION': f'Bearer {_agent_http_token(owner_user_id=7)}'}

    def test_agent_token_is_401_on_every_object_route(self):
        base = f'/storage/v1/object/{COMPANY_BUCKET_NAME}'
        calls = [
            ('get', f'{base}/a.txt', None),
            ('post', f'{base}/b.txt', b'x'),
            ('get', f'/storage/v1/object/authenticated/{COMPANY_BUCKET_NAME}/a.txt', None),
            ('post', f'/storage/v1/object/sign/{COMPANY_BUCKET_NAME}/a.txt', {}),
            ('post', f'/storage/v1/object/sign/{COMPANY_BUCKET_NAME}', {'paths': ['a.txt']}),
            ('get', '/storage/v1/bucket', None),
            ('get', '/api/v1/scheduled-jobs', None),
        ]
        for method, path, data in calls:
            kwargs = {'content_type': 'application/octet-stream'} if isinstance(data, bytes) else {'format': 'json'}
            response = getattr(self.client, method)(path, data=data, **kwargs, **self.auth) if method == 'post' else getattr(self.client, method)(path, **self.auth)
            self.assertEqual(response.status_code, 401, (method, path))
        self.assertFalse(StorageObject.objects.filter(name='b.txt').exists())

    def test_agent_token_is_401_on_webdav_bearer_and_basic(self):
        import base64

        response = self.client.generic('PROPFIND', '/dav/', **self.auth)
        self.assertEqual(response.status_code, 401)
        raw = _agent_http_token(owner_user_id=7)
        basic = base64.b64encode(f'agent:{raw}'.encode()).decode()
        response = self.client.generic('PROPFIND', '/dav/', HTTP_AUTHORIZATION=f'Basic {basic}')
        self.assertEqual(response.status_code, 401)
        response = self.client.generic(
            'PUT', '/dav/company/dav.txt', data=b'x', content_type='text/plain', **self.auth
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(StorageObject.objects.filter(name='dav.txt').exists())

    def test_only_access_tokens_are_bearers(self):
        for token_type in ('refresh', 'setup', 'id', ''):
            payload = {
                'sub': '1', 'token_type': token_type, 'user_id': 1, 'company_id': COMPANY,
                'user_metadata': {'is_staff': False, 'is_company_owner': True}, 'exp': 2**31 - 1,
            }
            if token_type == '':
                payload.pop('token_type')
            token = jwt.encode(payload, 'test-secret', algorithm='HS256')
            response = self.client.get('/storage/v1/bucket', HTTP_AUTHORIZATION=f'Bearer {token}')
            self.assertEqual(response.status_code, 401, repr(token_type))
        ok = self.client.get('/storage/v1/bucket', HTTP_AUTHORIZATION=f'Bearer {make_token(is_company_owner=True)}')
        self.assertEqual(ok.status_code, 200)

    def test_agent_bearer_requires_an_access_token(self):
        for token_type in ('refresh', 'setup', ''):
            claims = {'sub': 'agent:abc', 'agent_id': 'abc', 'company_id': COMPANY, 'scope': 'storage',
                      'aud': 'http://127.0.0.1/mcp', 'exp': 2**31 - 1}
            if token_type:
                claims['token_type'] = token_type
            raw = jwt.encode(claims, 'test-secret', algorithm='HS256')
            with patch('apps.authapi.agent_tokens._decode_agent_claims', return_value=claims):
                self.assertIsNone(
                    authenticate_agent_bearer(raw, expected_resource='http://127.0.0.1/mcp'), repr(token_type)
                )


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
)
class UploadSafetyTests(TestCase):
    def setUp(self):
        self.bucket = ensure_company_bucket(company_id=COMPANY)
        self.bucket.file_size_limit = 1024
        self.bucket.save(update_fields=['file_size_limit'])
        jwks = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = jwks.start()
        mock_client.return_value.get_signing_key.return_value = None
        mock_client.return_value.key_count.return_value = 0
        mock_client.return_value.key_ids.return_value = []
        self.addCleanup(jwks.stop)

    def _blobs(self) -> set[str]:
        found: set[str] = set()

        def walk(prefix: str):
            dirs, files = default_storage.listdir(prefix)
            for name in files:
                found.add(f'{prefix}/{name}'.lstrip('/'))
            for sub in dirs:
                walk(f'{prefix}/{sub}'.lstrip('/'))

        try:
            walk('')
        except FileNotFoundError:
            pass
        return found

    def _used(self) -> int:
        quota = CompanyQuota.objects.filter(company_id=COMPANY).first()
        return quota.used_bytes if quota else 0

    def test_oversized_body_with_no_declared_length_is_413_and_leaves_nothing(self):
        class _Chunked:
            """A non-seekable body with no length, like a chunked request."""

            def __init__(self, total: int):
                self.left = total

            def read(self, n: int = -1) -> bytes:
                n = self.left if n is None or n < 0 else min(n, self.left)
                self.left -= n
                return b'z' * n

        before_blobs, before_used = self._blobs(), self._used()
        with self.assertRaises(StorageError) as caught:
            upload_object(bucket=self.bucket, path='big.bin', fileobj=_Chunked(4096), owner_id=1)
        self.assertEqual(caught.exception.status, 413)
        self.assertEqual(caught.exception.code, 'payload_too_large')
        self.assertFalse(StorageObject.objects.filter(name='big.bin').exists())
        self.assertEqual(self._blobs(), before_blobs)
        self.assertEqual(self._used(), before_used)

    def test_oversized_replace_with_no_declared_length_keeps_the_old_file(self):
        class _Chunked:
            def __init__(self, total: int):
                self.left = total

            def read(self, n: int = -1) -> bytes:
                n = self.left if n is None or n < 0 else min(n, self.left)
                self.left -= n
                return b'z' * n

        first = upload_object(bucket=self.bucket, path='r.bin', fileobj=io.BytesIO(b'old'), owner_id=1)
        before_blobs, before_used = self._blobs(), self._used()
        with self.assertRaises(StorageError) as caught:
            upload_object(
                bucket=self.bucket, path='r.bin', fileobj=_Chunked(4096), owner_id=1, upsert=True
            )
        self.assertEqual(caught.exception.status, 413)
        row = StorageObject.objects.get(name='r.bin')
        self.assertEqual((row.storage_key, row.size), (first.storage_key, 3))
        self.assertEqual(self._blobs(), before_blobs)
        self.assertEqual(self._used(), before_used)

    def test_webdav_put_over_the_cap_is_413_and_leaves_nothing(self):
        client = APIClient()
        token = make_token()
        before_blobs, before_used = self._blobs(), self._used()
        response = client.generic(
            'PUT',
            '/dav/company/big.bin',
            data=b'z' * 4096,
            content_type='application/octet-stream',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 413, response.content)
        self.assertFalse(StorageObject.objects.filter(name='big.bin').exists())
        self.assertEqual(self._blobs(), before_blobs)
        self.assertEqual(self._used(), before_used)

    def test_etag_is_the_md5_of_the_bytes_that_were_saved(self):
        data = b'checksum-me'
        obj = upload_object(bucket=self.bucket, path='c.txt', fileobj=io.BytesIO(data), owner_id=1)
        self.assertEqual(obj.etag, hashlib.md5(data).hexdigest())
        with default_storage.open(obj.storage_key, 'rb') as handle:
            self.assertEqual(hashlib.md5(handle.read()).hexdigest(), obj.etag)

    def test_etag_matches_when_the_source_does_not_start_at_zero(self):
        buffer = io.BytesIO(b'JUNKPREFIX' + b'payload-bytes')
        buffer.seek(len(b'JUNKPREFIX'))
        obj = upload_object(bucket=self.bucket, path='offset.txt', fileobj=buffer, owner_id=1)
        with default_storage.open(obj.storage_key, 'rb') as handle:
            self.assertEqual(handle.read(), b'payload-bytes')
        self.assertEqual(obj.etag, hashlib.md5(b'payload-bytes').hexdigest())

    def test_a_failed_database_write_removes_the_new_blob(self):
        before = self._blobs()
        with patch('apps.storage.services.apply_usage_delta', side_effect=RuntimeError('db down')):
            with self.assertRaises(RuntimeError):
                upload_object(bucket=self.bucket, path='orphan.txt', fileobj=io.BytesIO(b'abc'), owner_id=1)
        self.assertEqual(self._blobs(), before)
        self.assertFalse(StorageObject.objects.filter(name='orphan.txt').exists())

    def test_replace_keeps_the_old_bytes_if_the_new_save_fails(self):
        first = upload_object(bucket=self.bucket, path='r.txt', fileobj=io.BytesIO(b'old'), owner_id=1)
        old_key = first.storage_key
        with patch('apps.storage.services.default_storage.save', side_effect=OSError('disk full')):
            with self.assertRaises(StorageError):
                upload_object(
                    bucket=self.bucket, path='r.txt', fileobj=io.BytesIO(b'new'), owner_id=1, upsert=True
                )
        row = StorageObject.objects.get(name='r.txt')
        self.assertEqual(row.storage_key, old_key)
        with default_storage.open(old_key, 'rb') as handle:
            self.assertEqual(handle.read(), b'old')

    def test_replace_keeps_the_old_bytes_if_the_database_write_fails(self):
        first = upload_object(bucket=self.bucket, path='r.txt', fileobj=io.BytesIO(b'old'), owner_id=1)
        old_key = first.storage_key
        before = self._blobs()
        with patch('apps.storage.services.apply_usage_delta', side_effect=RuntimeError('db down')):
            with self.assertRaises(RuntimeError):
                upload_object(
                    bucket=self.bucket, path='r.txt', fileobj=io.BytesIO(b'new'), owner_id=1, upsert=True
                )
        self.assertEqual(self._blobs(), before)
        with default_storage.open(old_key, 'rb') as handle:
            self.assertEqual(handle.read(), b'old')

    def test_replace_writes_the_new_blob_first_and_removes_the_old_after_commit(self):
        first = upload_object(bucket=self.bucket, path='r.txt', fileobj=io.BytesIO(b'old'), owner_id=1)
        old_key = first.storage_key
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            second = upload_object(
                bucket=self.bucket, path='r.txt', fileobj=io.BytesIO(b'newer'), owner_id=1, upsert=True
            )
        self.assertNotEqual(second.storage_key, old_key)
        self.assertTrue(default_storage.exists(old_key), 'old bytes stay until the commit')
        for callback in callbacks:
            callback()
        self.assertFalse(default_storage.exists(old_key))
        with default_storage.open(second.storage_key, 'rb') as handle:
            self.assertEqual(handle.read(), b'newer')

    def test_an_agent_with_no_creator_does_not_take_over_a_replaced_file(self):
        first = upload_object(bucket=self.bucket, path='r.txt', fileobj=io.BytesIO(b'old'), owner_id=7)
        upload_object(bucket=self.bucket, path='r.txt', fileobj=io.BytesIO(b'new'), owner_id=0, upsert=True)
        self.assertEqual(StorageObject.objects.get(pk=first.pk).owner_id, 7)
