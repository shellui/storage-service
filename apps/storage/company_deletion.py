"""Blob cleanup for a deleted company (called by ``actions.purge_deleted_companies``)."""

from __future__ import annotations

from apps.storage.models import StorageObject
from apps.storage.backends import delete_storage_key

BATCH = 500


def delete_company_files(company_id: int) -> int:
    """Delete each file from storage (S3 or disk), then its row, so a retry resumes where it stopped."""
    deleted = 0
    while True:
        batch = list(
            StorageObject._base_manager.filter(company_id=company_id).values_list('pk', 'storage_key')[:BATCH]
        )
        if not batch:
            return deleted
        for _pk, key in batch:
            delete_storage_key(key)
        StorageObject._base_manager.filter(pk__in=[pk for pk, _key in batch]).delete()
        deleted += len(batch)
