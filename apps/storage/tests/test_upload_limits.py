"""Uploads are capped before the body is read and are not buffered as one bytes object."""

from __future__ import annotations

import hashlib
import io
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from apps.authapi.principal import StoragePrincipal
from apps.storage.access import COMPANY_BUCKET_NAME, ensure_company_bucket
from apps.storage.models import StorageObject
from apps.storage.services import StorageError, upload_object
from apps.storage.tests.test_storage import make_token
from apps.storage.views import ObjectResourceView

_CHUNK = 1024 * 1024


class _Recording(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.reads: list[int] = []

    def read(self, n: int = -1) -> bytes:
        self.reads.append(-1 if n is None else n)
        return super().read(n)


class _Unread:
    def read(self, n: int = -1) -> bytes:
        raise AssertionError(f'body was read ({n})')


@override_settings(
    STORAGE_BACKEND='filesystem',
    JWT_HS256_FALLBACK_SECRET='test-secret',
    ALLOW_JWT_HS256_FALLBACK=True,
    IDENTITY_JWKS_URL='http://jwks.test/.well-known/jwks.json',
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
)
class UploadLimitTests(TestCase):
    def setUp(self):
        self.bucket = ensure_company_bucket(company_id=10)
        self.bucket.file_size_limit = 8 * _CHUNK
        self.bucket.save(update_fields=['file_size_limit'])
        jwks = patch('apps.authapi.authentication.get_jwks_client')
        mock_client = jwks.start()
        mock_client.return_value.get_signing_key.return_value = None
        mock_client.return_value.key_count.return_value = 0
        mock_client.return_value.key_ids.return_value = []
        self.addCleanup(jwks.stop)

    def test_reads_are_chunked(self):
        payload = b'hello-stream'
        src = _Recording(payload)
        obj = upload_object(
            bucket=self.bucket,
            path='notes/stream.txt',
            fileobj=src,
            owner_id=1,
            content_type='text/plain',
        )
        self.assertTrue(src.reads)
        self.assertTrue(all(0 < size <= _CHUNK for size in src.reads))
        self.assertEqual(obj.etag, hashlib.md5(payload).hexdigest())
        self.assertEqual(obj.size, len(payload))

    def test_content_length_rejects_before_read(self):
        request = APIRequestFactory().post(
            '/storage/v1/object/company/big.bin',
            data=b'',
            content_type='application/octet-stream',
        )
        request.META['CONTENT_LENGTH'] = '50000000'
        with self.assertRaises(StorageError) as caught:
            upload_object(
                bucket=self.bucket,
                path='big.bin',
                fileobj=_Unread(),
                owner_id=1,
                content_type='application/octet-stream',
                request=request,
            )
        self.assertEqual(caught.exception.status, 413)
        self.assertEqual(caught.exception.code, 'payload_too_large')
        self.assertFalse(StorageObject.objects.filter(name='big.bin').exists())

    def test_view_rejects_declared_length_before_saving(self):
        request = APIRequestFactory().post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/early.bin',
            data=b'hello',
            content_type='application/octet-stream',
        )
        request.META['CONTENT_LENGTH'] = '999999999999'
        user = StoragePrincipal(user_id=1, company_id=10)
        force_authenticate(request, user=user)
        response = ObjectResourceView.as_view()(
            request,
            bucket_id=COMPANY_BUCKET_NAME,
            object_path='early.bin',
        )
        self.assertEqual(response.status_code, 413)
        self.assertFalse(StorageObject.objects.filter(name='early.bin').exists())

    def test_multipart_upload_still_stores_the_file(self):
        client = APIClient()
        token = make_token()
        uploaded = SimpleUploadedFile('note.txt', b'hello-multipart', content_type='text/plain')
        response = client.post(
            f'/storage/v1/object/{COMPANY_BUCKET_NAME}/note.txt',
            data={'file': uploaded},
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(response.status_code, 200, response.content)
        obj = StorageObject.objects.get(name='note.txt')
        from django.core.files.storage import default_storage

        with default_storage.open(obj.storage_key, 'rb') as handle:
            self.assertEqual(handle.read(), b'hello-multipart')
        self.assertEqual(obj.etag, hashlib.md5(b'hello-multipart').hexdigest())
