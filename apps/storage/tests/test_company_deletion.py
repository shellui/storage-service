"""A deleted company's files and rows are removed; other companies are untouched."""

import io

from django.core.files.storage import default_storage
from django.test import TestCase, override_settings

from apps.actions.company_deletion import purge_company
from apps.storage.models import Bucket, CompanyQuota, StorageObject
from apps.storage.services import upload_object


@override_settings(STORAGE_BACKEND='filesystem', DEFAULT_COMPANY_QUOTA_BYTES=1024 * 1024)
class StorageCompanyDeletionTests(TestCase):
    def _file(self, company_id, name):
        bucket, _ = Bucket.objects.get_or_create(company_id=company_id, name='docs')
        return upload_object(bucket=bucket, path=name, fileobj=io.BytesIO(b'hello'), owner_id=1)

    def test_purge_removes_files_and_rows(self):
        gone = self._file(7, 'a.txt')
        kept = self._file(8, 'b.txt')
        self.assertTrue(default_storage.exists(gone.storage_key))
        purge_company(7)
        self.assertFalse(default_storage.exists(gone.storage_key))
        self.assertFalse(StorageObject.objects.filter(company_id=7).exists())
        self.assertFalse(Bucket.objects.filter(company_id=7).exists())
        self.assertFalse(CompanyQuota.objects.filter(company_id=7).exists())
        self.assertTrue(default_storage.exists(kept.storage_key))
        self.assertTrue(StorageObject.objects.filter(company_id=8).exists())
        purge_company(7)  # idempotent
        default_storage.delete(kept.storage_key)
