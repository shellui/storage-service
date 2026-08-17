"""Tests for admin storage statistics."""

from __future__ import annotations

import io

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.storage.access import COMPANY_BUCKET_NAME, ensure_company_bucket
from apps.storage.services import upload_object
from apps.storage.stats import build_storage_stats, human_bytes


@override_settings(
    STORAGE_BACKEND='filesystem',
    MEDIA_ROOT='/tmp/shellui-storage-admin-stats',
    DEFAULT_COMPANY_QUOTA_BYTES=10 * 1024 * 1024,
)
class StorageStatsTests(TestCase):
    def setUp(self):
        company = ensure_company_bucket(company_id=10)
        self.assertEqual(company.name, COMPANY_BUCKET_NAME)
        upload_object(
            bucket=company,
            path='reports/q1.md',
            fileobj=io.BytesIO(b'# Report\n'),
            owner_id=1,
            content_type='text/markdown',
        )
        upload_object(
            bucket=company,
            path='logo.png',
            fileobj=io.BytesIO(b'\x89PNG\r\n'),
            owner_id=1,
            content_type='image/png',
        )

    def test_human_bytes(self):
        self.assertEqual(human_bytes(512), '512 B')
        self.assertEqual(human_bytes(2048), '2.0 KiB')

    def test_build_storage_stats(self):
        stats = build_storage_stats()
        self.assertEqual(stats['object_count'], 2)
        self.assertEqual(stats['document_count'], 1)
        self.assertGreaterEqual(stats['bucket_count'], 1)
        self.assertTrue(any(row['family'] == 'Images' for row in stats['by_family']))
        self.assertTrue(any(row['basename'] == 'q1.md' for row in stats['recent']))

    def test_admin_index_and_statistics_pages(self):
        user = get_user_model().objects.create_superuser('admin', 'a@example.com', 'admin-pass-12345')
        self.client.force_login(user)
        index = self.client.get(reverse('admin:index'))
        self.assertEqual(index.status_code, 200)
        self.assertContains(index, 'Storage overview')
        self.assertContains(index, 'Full statistics')

        stats_page = self.client.get(reverse('admin:storage_statistics'))
        self.assertEqual(stats_page.status_code, 200)
        self.assertContains(stats_page, 'Upload statistics')
        self.assertContains(stats_page, 'q1.md')
