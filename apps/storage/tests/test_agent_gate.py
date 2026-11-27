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
from apps.storage.access import can_access_path
from apps.storage.models import FOLDER_PLACEHOLDER_NAME, Bucket, StorageAccessGrant, StorageObject
from apps.storage.services import upload_object

COMPANY = 10
COPY = 'storage_v1_object_copy_create'
MOVE = 'storage_v1_object_move_create'
RENAME = 'storage_v1_object_prefix_create'


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


def _rename(src: str, dst: str) -> dict:
    return {'path_params': {'bucket_id': COMPANY_BUCKET_NAME}, 'body': {'from': src, 'to': dst}}


class VisibilityTests(TestCase):
    """Who can read before and after, by the real access check, for every move, copy and rename."""

    def setUp(self):
        self.bucket = ensure_company_bucket(company_id=COMPANY)
        self.agent = StoragePrincipal(user_id=7, company_id=COMPANY)
        self.member = StoragePrincipal(user_id=99, company_id=COMPANY)

    def upload(self, name: str, owner_id: int | None = 7):
        return upload_object(
            bucket=self.bucket, path=name, fileobj=io.BytesIO(b'x'), owner_id=owner_id, content_type='text/plain'
        )

    def grant(self, obj, *, subject: str, subject_id, effect='allow', permission='read', kind='object'):
        return StorageAccessGrant.objects.create(
            company_id=COMPANY,
            bucket=self.bucket,
            object=obj,
            resource_type=kind,
            subject_type=subject,
            subject_id=str(subject_id),
            permission=permission,
            effect=effect,
        )

    def folder(self, path: str, *, owner: int | None = 7, company_deny: bool = True):
        """A folder marker. Private to ``owner`` by default, like a folder an agent or person made."""
        marker = StorageObject.objects.create(
            bucket=self.bucket,
            company_id=COMPANY,
            name=f'{path}/{FOLDER_PLACEHOLDER_NAME}',
            size=0,
            mime_type='application/x-directory',
            storage_key=f'k/{path}',
        )
        U, C = StorageAccessGrant.SubjectType.USER, StorageAccessGrant.SubjectType.COMPANY
        if company_deny:
            self.grant(marker, subject=C, subject_id=COMPANY, effect='deny', kind='folder')
        if owner is not None:
            self.grant(marker, subject=U, subject_id=owner, permission='admin', kind='folder')
        return marker

    def widens(self, op, args) -> bool:
        return copy_or_move_widens_visibility(op, args, self.agent)

    def can_read(self, name: str) -> bool:
        return can_access_path(self.member, self.bucket, name)

    # Basic behaviour

    def test_copy_into_the_agents_own_private_space_does_not_widen(self):
        self.upload('mine.txt')
        self.assertFalse(self.widens(COPY, _args('mine.txt', 'mine-copy.txt')))

    def test_copy_of_a_private_file_into_a_company_visible_folder_widens(self):
        self.upload('mine.txt')
        self.folder('team', company_deny=False, owner=None)
        self.grant(
            StorageObject.objects.get(name=f'team/{FOLDER_PLACEHOLDER_NAME}'),
            subject=StorageAccessGrant.SubjectType.COMPANY,
            subject_id=COMPANY,
            kind='folder',
        )
        self.assertTrue(self.widens(COPY, _args('mine.txt', 'team/mine.txt')))

    def test_copy_of_a_company_visible_file_never_widens(self):
        StorageObject.objects.create(
            bucket=self.bucket, company_id=COMPANY, name='open.txt', size=1, mime_type='text/plain', storage_key='k/o'
        )
        self.assertFalse(self.widens(COPY, _args('open.txt', 'open-copy.txt')))

    def test_copy_into_a_folder_shared_with_another_person_widens(self):
        self.upload('mine.txt')
        marker = self.folder('with-bob')
        self.grant(marker, subject=StorageAccessGrant.SubjectType.USER, subject_id=9, kind='folder')
        self.assertTrue(self.widens(COPY, _args('mine.txt', 'with-bob/mine.txt')))

    def test_copy_by_an_agent_with_no_creator_asks(self):
        self.upload('mine.txt')
        nobody = StoragePrincipal(user_id=0, company_id=COMPANY)
        self.assertTrue(copy_or_move_widens_visibility(COPY, _args('mine.txt', 'copy.txt'), nobody))

    def test_move_within_the_same_private_folder_does_not_widen(self):
        self.folder('priv')
        self.upload('priv/a.txt')
        self.assertFalse(self.widens(MOVE, _args('priv/a.txt', 'priv/b.txt')))

    def test_move_of_a_file_that_keeps_its_own_company_deny_does_not_widen(self):
        self.upload('mine.txt')
        self.folder('team', company_deny=False, owner=None)
        self.assertFalse(self.widens(MOVE, _args('mine.txt', 'team/mine.txt')))

    # The four bypasses

    def test_1_unnormalized_keys_are_normalized_before_the_lookup(self):
        self.folder('priv')
        self.upload('priv/b.txt')
        self.assertTrue(self.widens(MOVE, _args('priv//b.txt', 'pub-d.txt')))
        self.assertTrue(self.widens(MOVE, _args('./priv/./b.txt', 'pub-d.txt')))
        self.assertTrue(self.widens(MOVE, _args('/priv/b.txt/', 'pub-d.txt')))
        self.assertFalse(self.widens(COPY, _args('priv//b.txt', 'pub-c.txt')))  # found, and the copy stays private to its creator
        self.assertTrue(self.widens(MOVE, _args('priv/b.txt', 'pub-n.txt')))

    def test_1b_a_source_that_is_not_found_asks(self):
        self.assertTrue(self.widens(MOVE, _args('missing.txt', 'x.txt')))
        self.assertTrue(self.widens(COPY, _args('missing.txt', 'x.txt')))
        self.assertTrue(self.widens(MOVE, _args('a/../b.txt', 'x.txt')))
        self.assertTrue(self.widens(COPY, {}))
        self.assertTrue(self.widens(COPY, {'body': {'sourceKey': 'nope/a', 'destinationKey': 'nope/b'}}))
        self.assertTrue(self.widens(RENAME, _rename('missing', 'other')))

    def test_2_a_file_with_only_an_allow_grant_inside_a_private_folder_asks_before_leaving_it(self):
        self.folder('priv')
        shared = self.upload('priv/s.txt')
        self.grant(shared, subject=StorageAccessGrant.SubjectType.USER, subject_id=9)
        self.assertFalse(self.can_read('priv/s.txt'))
        self.assertTrue(self.widens(MOVE, _args('priv/s.txt', 's.txt')))
        # Staying in the folder is fine.
        self.assertFalse(self.widens(MOVE, _args('priv/s.txt', 'priv/t.txt')))

    def test_3_moving_a_folder_marker_out_asks_because_the_files_left_behind_lose_the_folder(self):
        self.folder('priv')
        self.upload('priv/keep.txt')
        self.folder('mine/sub')
        self.assertFalse(self.can_read('priv/keep.txt'))
        marker = f'priv/{FOLDER_PLACEHOLDER_NAME}'
        self.assertTrue(self.widens(MOVE, _args(marker, f'mine/sub2/{FOLDER_PLACEHOLDER_NAME}')))

    def test_4_a_folder_rename_out_of_a_private_parent_asks(self):
        self.folder('priv')
        self.upload('priv/sub/s.txt')
        self.assertFalse(self.can_read('priv/sub/s.txt'))
        self.assertTrue(self.widens(RENAME, _rename('priv/sub', 'sub2')))

    def test_4b_a_folder_rename_inside_the_same_private_parent_does_not_ask(self):
        self.folder('priv')
        self.upload('priv/sub/s.txt')
        self.assertFalse(self.widens(RENAME, _rename('priv/sub', 'priv/sub2')))

    def test_4c_renaming_a_company_visible_folder_does_not_ask(self):
        StorageObject.objects.create(
            bucket=self.bucket, company_id=COMPANY, name='open/a.txt', size=1, mime_type='text/plain', storage_key='k/a'
        )
        self.assertFalse(self.widens(RENAME, _rename('open', 'open2')))

    def test_a_deeper_company_allow_under_a_company_deny_is_seen_as_readable(self):
        # evaluate_access says the deeper company allow wins. A summary that unions grants would not.
        self.folder('priv')
        self.upload('priv/x/s.txt')
        inner = self.folder('priv/open', company_deny=False, owner=None)
        self.grant(inner, subject=StorageAccessGrant.SubjectType.COMPANY, subject_id=COMPANY, kind='folder')
        self.assertTrue(self.widens(MOVE, _args('priv/x/s.txt', 'priv/open/s.txt')))

    def test_the_simulation_changes_nothing(self):
        self.folder('priv')
        self.upload('priv/sub/s.txt')
        names = sorted(StorageObject.objects.values_list('name', flat=True))
        grants = StorageAccessGrant.objects.count()
        self.widens(RENAME, _rename('priv/sub', 'sub2'))
        self.widens(MOVE, _args('priv/sub/s.txt', 'x.txt'))
        self.widens(COPY, _args('priv/sub/s.txt', 'y.txt'))
        self.assertEqual(names, sorted(StorageObject.objects.values_list('name', flat=True)))
        self.assertEqual(grants, StorageAccessGrant.objects.count())
