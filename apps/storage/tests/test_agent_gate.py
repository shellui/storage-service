"""Calls an agent can make only with a person's approval, in every access mode."""

from __future__ import annotations

import io
from unittest.mock import patch

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from apps.authapi.principal import StoragePrincipal
from apps.storage.access import COMPANY_BUCKET_NAME, ensure_company_bucket
from apps.storage import agent_gate
from apps.storage.access import _resource_matches_grant, active_grants_for_company
from apps.storage.agent_gate import ALWAYS_APPROVE_OPERATIONS, approval_reason_for_agent_call, checked
from apps.storage.access import can_access_path
from apps.storage.models import FOLDER_PLACEHOLDER_NAME, Bucket, StorageAccessGrant, StorageObject
from apps.storage.services import StorageError, copy_object, move_object, rename_folder, upload_object

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
                self.assertTrue(approval_reason_for_agent_call(op, {}))

    def test_other_operations_do_not(self):
        self.assertIsNone(approval_reason_for_agent_call('storage_v1_object_create', {}))
        self.assertIsNone(approval_reason_for_agent_call('storage_v1_bucket_list', {}))


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

    def attempt(self, op, args, principal=None):
        """The real write, through the gate, as the view would do it. ``(ran, reason)``."""
        body = args.get('body') or {}

        def split(key):
            bucket_name, _, name = str(key).partition('/')
            return Bucket.objects.get(company_id=COMPANY, name=bucket_name), name

        who = principal or self.agent

        def write():
            if op == RENAME:
                return rename_folder(bucket=self.bucket, source_path=body['from'], dest_path=body['to'])
            src_bucket, src = split(body['sourceKey'])
            dst_bucket, dst = split(body['destinationKey'])
            if op == MOVE:
                return move_object(bucket=src_bucket, source_path=src, dest_bucket=dst_bucket, dest_path=dst)
            return copy_object(
                bucket=src_bucket, source_path=src, dest_bucket=dst_bucket, dest_path=dst, owner_id=who.user_id
            )

        ran, outcome = checked(op, args, principal or self.agent, write)
        return ran, (None if ran else outcome)

    def widens(self, op, args, principal=None) -> bool:
        ran, _reason = self.attempt(op, args, principal)
        return not ran

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
        StorageAccessGrant.objects.filter(object=self.upload('open.txt')).delete()
        self.assertFalse(self.widens(COPY, _args('open.txt', 'open-copy.txt')))

    def test_copy_into_a_folder_shared_with_another_person_widens(self):
        self.upload('mine.txt')
        marker = self.folder('with-bob')
        self.grant(marker, subject=StorageAccessGrant.SubjectType.USER, subject_id=9, kind='folder')
        self.assertTrue(self.widens(COPY, _args('mine.txt', 'with-bob/mine.txt')))

    def test_copy_by_an_agent_with_no_creator_is_refused_by_the_service_and_writes_nothing(self):
        self.upload('mine.txt')
        nobody = StoragePrincipal(user_id=0, company_id=COMPANY)
        with self.assertRaises(StorageError) as caught:
            self.attempt(COPY, _args('mine.txt', 'copy.txt'), nobody)
        self.assertEqual(caught.exception.code, 'agent_has_no_owner')
        self.assertFalse(StorageObject.objects.filter(name='copy.txt').exists())

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
        StorageAccessGrant.objects.filter(object=self.upload('open/a.txt')).delete()
        self.assertFalse(self.widens(RENAME, _rename('open', 'open2')))

    def test_a_deeper_company_allow_under_a_company_deny_is_seen_as_readable(self):
        # evaluate_access says the deeper company allow wins. A summary that unions grants would not.
        self.folder('priv')
        self.upload('priv/x/s.txt')
        inner = self.folder('priv/open', company_deny=False, owner=None)
        self.grant(inner, subject=StorageAccessGrant.SubjectType.COMPANY, subject_id=COMPANY, kind='folder')
        self.assertTrue(self.widens(MOVE, _args('priv/x/s.txt', 'priv/open/s.txt')))

    def test_a_refused_call_changes_nothing(self):
        self.folder('priv')
        self.upload('priv/sub/s.txt')
        names = sorted(StorageObject.objects.values_list('name', flat=True))
        grants = StorageAccessGrant.objects.count()
        self.widens(RENAME, _rename('priv/sub', 'sub2'))
        self.widens(MOVE, _args('priv/sub/s.txt', 'x.txt'))
        self.assertEqual(names, sorted(StorageObject.objects.values_list('name', flat=True)))
        self.assertEqual(grants, StorageAccessGrant.objects.count())


class VisibilityCostTests(TestCase):
    """The check does bounded work, whatever the company's other grants are."""

    def setUp(self):
        self.bucket = ensure_company_bucket(company_id=COMPANY)
        self.agent = StoragePrincipal(user_id=7, company_id=COMPANY)
        helper = VisibilityTests('folder')
        helper.bucket, helper.agent = self.bucket, self.agent
        self.helper = helper

    def private_folder(self, path='priv'):
        return self.helper.folder(path)

    def objects(self, folder: str, count: int):
        StorageObject.objects.bulk_create(
            [
                StorageObject(
                    bucket=self.bucket,
                    company_id=COMPANY,
                    owner_id=7,
                    name=f'{folder}/f{i}.txt',
                    size=1,
                    mime_type='text/plain',
                    storage_key=f'k/{folder}/{i}',
                )
                for i in range(count)
            ]
        )

    def measure(self, src: str, dst: str):
        """(queries, evaluate_access calls, ran, reason) for one folder rename."""
        calls = 0
        real = agent_gate.evaluate_access

        def counting(*args, **kwargs):
            nonlocal calls
            calls += 1
            return real(*args, **kwargs)

        with patch('apps.storage.agent_gate.evaluate_access', side_effect=counting):
            with CaptureQueriesContext(connection) as queries:
                ran, reason = self.helper.attempt(RENAME, _rename(src, dst))
        return len(queries), calls, ran, reason

    def plain_queries(self, src: str, dst: str) -> int:
        """Queries of the rename itself, with no gate."""
        with CaptureQueriesContext(connection) as queries:
            rename_folder(bucket=self.bucket, source_path=src, dest_path=dst)
        return len(queries)

    def test_work_grows_with_the_objects_and_not_with_the_companys_other_grants(self):
        self.private_folder()
        for name, count in (('small', 20), ('small-ref', 20), ('big', 250), ('big-ref', 250)):
            self.objects(f'priv/{name}', count)
        small_queries, small_calls, ran, _ = self.measure('priv/small', 'priv/small2')
        self.assertTrue(ran)
        big_queries, big_calls, ran, _ = self.measure('priv/big', 'priv/big2')
        self.assertTrue(ran)
        # Three probes (a plain member, a company owner, the creator) for each object, before and after.
        self.assertEqual(small_calls, 20 * 3 * 2)
        self.assertEqual(big_calls, 250 * 3 * 2)
        # What the gate adds to the write's own queries does not depend on the number of objects.
        small_extra = small_queries - self.plain_queries('priv/small-ref', 'priv/small-ref2')
        big_extra = big_queries - self.plain_queries('priv/big-ref', 'priv/big-ref2')
        self.assertEqual(small_extra, big_extra)
        self.assertLess(big_extra, 25)

        # Three hundred grants naming three hundred people, on other folders, change nothing.
        other = self.helper.folder('other', owner=8)
        for uid in range(1000, 1300):
            self.helper.grant(other, subject=StorageAccessGrant.SubjectType.USER, subject_id=uid, kind='folder')
        queries, calls, ran, _ = self.measure('priv/big2', 'priv/big3')
        self.assertTrue(ran)
        self.assertEqual(calls, 250 * 3 * 2)
        self.assertEqual(queries - self.plain_queries('priv/big-ref2', 'priv/big-ref3'), big_extra)

    def test_more_objects_than_the_cap_asks_and_says_why(self):
        self.private_folder()
        self.objects('priv/huge', agent_gate.MAX_OBJECTS + 1)
        _queries, calls, ran, reason = self.measure('priv/huge', 'priv/huge2')
        self.assertFalse(ran)
        self.assertEqual(calls, 0)
        self.assertIn(f'limit is {agent_gate.MAX_OBJECTS}', reason)
        self.assertEqual(StorageObject.objects.filter(name__startswith='priv/huge/').count(), agent_gate.MAX_OBJECTS + 1)

    def test_more_work_than_the_budget_asks_and_says_why(self):
        marker = self.private_folder()
        for uid in (11, 12, 13):
            self.helper.grant(marker, subject=StorageAccessGrant.SubjectType.USER, subject_id=uid, kind='folder')
        self.objects('priv/many', agent_gate.MAX_OBJECTS)
        _queries, calls, ran, reason = self.measure('priv/many', 'priv/many2')
        self.assertFalse(ran)
        self.assertLessEqual(calls, agent_gate.MAX_EVALUATIONS)
        self.assertEqual(reason, agent_gate.BUDGET_REASON)
        self.assertEqual(StorageObject.objects.filter(name__startswith='priv/many/').count(), agent_gate.MAX_OBJECTS)

    def test_a_time_budget_asks_too(self):
        self.private_folder()
        self.objects('priv/slow', 5)
        with patch('apps.storage.agent_gate.MAX_SECONDS', -1):
            _queries, _calls, ran, reason = self.measure('priv/slow', 'priv/slow2')
        self.assertFalse(ran)
        self.assertEqual(reason, agent_gate.BUDGET_REASON)

    def test_the_grant_index_finds_exactly_what_the_access_check_would_match(self):
        helper = self.helper
        helper.folder('priv')
        shared = helper.upload('priv/s.txt')
        helper.grant(shared, subject=StorageAccessGrant.SubjectType.USER, subject_id=9)
        helper.folder('priv/inner', owner=8)
        helper.upload('priv/inner/x.txt')
        helper.upload('open/y.txt')
        helper.grant(
            StorageObject.objects.get(name='open/y.txt'),
            subject=StorageAccessGrant.SubjectType.COMPANY,
            subject_id=COMPANY,
            kind='object',
        )
        StorageAccessGrant.objects.create(
            company_id=COMPANY,
            bucket=self.bucket,
            resource_type='bucket',
            subject_type='company',
            subject_id=str(COMPANY),
            permission='read',
            effect='allow',
        )
        grants = active_grants_for_company(COMPANY)
        index = agent_gate._GrantIndex(grants)
        for obj in StorageObject.objects.select_related('bucket'):
            expected = {
                g.pk for g in grants if _resource_matches_grant(g, bucket=obj.bucket, path=obj.name, object_id=str(obj.pk))
            }
            found = {g.pk for g in index.for_object(obj.bucket_id, obj.name, str(obj.pk))}
            self.assertEqual(found, expected, obj.name)

    def test_company_owners_are_probed_because_legacy_user_zero_folders_grant_them_read(self):
        helper = self.helper
        helper.folder('priv')
        helper.upload('priv/b.txt')
        helper.folder('legacy', owner=0)  # company deny and "allow user 0 admin": owners and staff only
        self.assertTrue(self.helper.widens(MOVE, _args('priv/b.txt', 'legacy/b.txt')))
        self.assertTrue(StorageObject.objects.filter(name='priv/b.txt').exists())

    def test_a_refused_copy_never_touches_the_blob_store(self):
        helper = self.helper
        helper.upload('mine.txt')
        marker = helper.folder('team', company_deny=False, owner=None)
        helper.grant(marker, subject=StorageAccessGrant.SubjectType.COMPANY, subject_id=COMPANY, kind='folder')
        with patch('apps.storage.services._save_blob') as save:
            ran, reason = helper.attempt(COPY, _args('mine.txt', 'team/mine.txt'))
        self.assertFalse(ran)
        self.assertEqual(reason, agent_gate.WIDENS_REASON)
        save.assert_not_called()
        self.assertFalse(StorageObject.objects.filter(name='team/mine.txt').exists())

    def test_moving_a_folder_marker_says_so(self):
        helper = self.helper
        helper.folder('priv')
        helper.upload('priv/keep.txt')
        ran, reason = helper.attempt(MOVE, _args(f'priv/{FOLDER_PLACEHOLDER_NAME}', f'gone/{FOLDER_PLACEHOLDER_NAME}'))
        self.assertFalse(ran)
        self.assertEqual(reason, agent_gate.MARKER_REASON)

    def test_deleting_a_folder_marker_says_so(self):
        reason = agent_gate.destructive_reason(
            'storage_v1_object_destroy', {'path_params': {'object_path': f'priv/{FOLDER_PLACEHOLDER_NAME}'}}
        )
        self.assertEqual(reason, agent_gate.MARKER_REASON)
        self.assertIsNone(
            agent_gate.destructive_reason('storage_v1_object_destroy', {'path_params': {'object_path': 'priv/a.txt'}})
        )
