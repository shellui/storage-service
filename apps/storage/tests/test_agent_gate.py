"""Calls an agent can make only with a person's approval, in every access mode."""

from __future__ import annotations

import io

from django.test import TestCase

from apps.authapi.principal import StoragePrincipal
from apps.storage.access import COMPANY_BUCKET_NAME, ensure_company_bucket
from apps.storage.agent_gate import (
    ALWAYS_APPROVE_OPERATIONS,
    approval_reason_for_agent_call,
    copy_or_move_widens_visibility,
)
from apps.storage.models import FOLDER_PLACEHOLDER_NAME, Bucket, StorageAccessGrant, StorageObject
from apps.storage.services import upload_object

COMPANY = 10
COPY = 'storage_v1_object_copy_create'
MOVE = 'storage_v1_object_move_create'


def _args(source: str, dest: str) -> dict:
    return {'body': {'sourceKey': f'{COMPANY_BUCKET_NAME}/{source}', 'destinationKey': f'{COMPANY_BUCKET_NAME}/{dest}'}}


class AlwaysApprovedOperationTests(TestCase):
    def test_listed_operations_always_need_approval(self):
        for op in (
            'api_v1_actions_rules_create',
            'api_v1_actions_rules_partial_update',
            'storage_v1_quota_company_update',
            'storage_v1_quota_company_user_update',
            'storage_v1_connector_create',
        ):
            with self.subTest(op=op):
                self.assertIn(op, ALWAYS_APPROVE_OPERATIONS)
                self.assertTrue(approval_reason_for_agent_call(op, {}, None))

    def test_other_operations_do_not(self):
        self.assertIsNone(approval_reason_for_agent_call('storage_v1_object_create', {}, None))
        self.assertIsNone(approval_reason_for_agent_call('storage_v1_bucket_list', {}, None))


class VisibilityTests(TestCase):
    def setUp(self):
        self.bucket = ensure_company_bucket(company_id=COMPANY)
        self.agent = StoragePrincipal(user_id=7, company_id=COMPANY)

    def upload(self, name: str, owner_id: int | None):
        return upload_object(
            bucket=self.bucket,
            path=name,
            fileobj=io.BytesIO(b'x'),
            owner_id=owner_id,
            content_type='text/plain',
        )

    def folder(self, path: str, *, company_read: bool = False, user: int | None = None):
        marker = StorageObject.objects.create(
            bucket=self.bucket,
            company_id=COMPANY,
            name=f'{path}/{FOLDER_PLACEHOLDER_NAME}',
            size=0,
            mime_type='application/x-directory',
            storage_key=f'k/{path}',
        )
        grants = []
        base = dict(
            company_id=COMPANY,
            bucket=self.bucket,
            object=marker,
            resource_type=StorageAccessGrant.ResourceType.FOLDER,
        )
        if company_read:
            grants.append(
                StorageAccessGrant.objects.create(
                    **base,
                    subject_type=StorageAccessGrant.SubjectType.COMPANY,
                    subject_id=str(COMPANY),
                    permission=StorageAccessGrant.Permission.READ,
                    effect=StorageAccessGrant.Effect.ALLOW,
                )
            )
        else:
            grants.append(
                StorageAccessGrant.objects.create(
                    **base,
                    subject_type=StorageAccessGrant.SubjectType.COMPANY,
                    subject_id=str(COMPANY),
                    permission=StorageAccessGrant.Permission.READ,
                    effect=StorageAccessGrant.Effect.DENY,
                )
            )
        if user is not None:
            grants.append(
                StorageAccessGrant.objects.create(
                    **base,
                    subject_type=StorageAccessGrant.SubjectType.USER,
                    subject_id=str(user),
                    permission=StorageAccessGrant.Permission.WRITE,
                    effect=StorageAccessGrant.Effect.ALLOW,
                )
            )
        return marker

    def test_copy_of_a_private_file_into_the_agents_own_private_space_does_not_widen(self):
        self.upload('mine.txt', 7)
        self.assertFalse(copy_or_move_widens_visibility(COPY, _args('mine.txt', 'mine-copy.txt'), self.agent))

    def test_copy_of_a_private_file_into_a_company_folder_widens(self):
        self.upload('mine.txt', 7)
        self.folder('team', company_read=True)
        self.assertTrue(copy_or_move_widens_visibility(COPY, _args('mine.txt', 'team/mine.txt'), self.agent))

    def test_copy_into_a_folder_shared_with_another_person_widens(self):
        self.upload('mine.txt', 7)
        self.folder('with-bob', user=9)
        self.assertTrue(copy_or_move_widens_visibility(COPY, _args('mine.txt', 'with-bob/mine.txt'), self.agent))

    def test_copy_into_a_folder_that_is_private_to_the_same_person_does_not_widen(self):
        self.upload('mine.txt', 7)
        self.folder('mine-only', user=7)
        self.assertFalse(copy_or_move_widens_visibility(COPY, _args('mine.txt', 'mine-only/a.txt'), self.agent))

    def test_copy_of_a_company_visible_file_never_widens(self):
        # A file with no grants at all is already visible to every member.
        StorageObject.objects.create(
            bucket=self.bucket, company_id=COMPANY, name='open.txt', size=1, mime_type='text/plain', storage_key='k/open'
        )
        self.folder('team', company_read=True)
        self.assertFalse(copy_or_move_widens_visibility(COPY, _args('open.txt', 'team/open.txt'), self.agent))

    def test_agent_with_no_creator_copying_a_private_file_widens(self):
        self.upload('mine.txt', 7)
        nobody = StoragePrincipal(user_id=0, company_id=COMPANY)
        self.assertTrue(copy_or_move_widens_visibility(COPY, _args('mine.txt', 'copy.txt'), nobody))

    def test_move_into_a_company_folder_widens_a_file_that_inherits_its_access(self):
        self.folder('private-dir', user=7)
        StorageObject.objects.create(
            bucket=self.bucket,
            company_id=COMPANY,
            name='private-dir/a.txt',
            size=1,
            mime_type='text/plain',
            storage_key='k/a',
        )
        self.folder('team', company_read=True)
        self.assertTrue(copy_or_move_widens_visibility(MOVE, _args('private-dir/a.txt', 'team/a.txt'), self.agent))

    def test_move_keeps_a_files_own_grants_so_it_does_not_widen(self):
        self.upload('mine.txt', 7)
        self.folder('team', company_read=True)
        self.assertFalse(copy_or_move_widens_visibility(MOVE, _args('mine.txt', 'team/mine.txt'), self.agent))

    def test_move_within_the_same_folder_does_not_widen(self):
        self.folder('private-dir', user=7)
        StorageObject.objects.create(
            bucket=self.bucket,
            company_id=COMPANY,
            name='private-dir/a.txt',
            size=1,
            mime_type='text/plain',
            storage_key='k/a',
        )
        self.assertFalse(
            copy_or_move_widens_visibility(MOVE, _args('private-dir/a.txt', 'private-dir/b.txt'), self.agent)
        )

    def test_unknown_files_and_buckets_do_not_need_approval(self):
        self.assertFalse(copy_or_move_widens_visibility(COPY, _args('missing.txt', 'x.txt'), self.agent))
        self.assertFalse(
            copy_or_move_widens_visibility(
                COPY, {'body': {'sourceKey': 'nope/a', 'destinationKey': 'nope/b'}}, self.agent
            )
        )
        self.assertFalse(copy_or_move_widens_visibility(COPY, {}, self.agent))
        self.assertEqual(Bucket.objects.filter(company_id=COMPANY).count(), 1)
