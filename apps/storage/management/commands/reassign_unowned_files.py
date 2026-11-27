"""Give a company's unowned files (stored by agents as "user 0") to one user."""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Sum

from apps.storage.access import LEGACY_UNOWNED_SUBJECT
from apps.storage.models import StorageAccessGrant, StorageObject
from apps.storage.quotas import apply_usage_delta


class Command(BaseCommand):
    help = (
        'Reassign files stored as user 0 (by agents, before agents acted as their creator) '
        'to one user. Storage has no record of which agent or creator stored a file, so you '
        'choose the user. Run with --dry-run first.'
    )

    def add_arguments(self, parser):
        parser.add_argument('--company', type=int, required=True, help='Company id.')
        parser.add_argument('--user', type=int, required=True, help='User id that becomes the owner.')
        parser.add_argument('--prefix', default='', help='Only objects whose path starts with this prefix.')
        parser.add_argument('--dry-run', action='store_true', help='Count what would change and write nothing.')

    def handle(self, *args, **options):
        company_id = options['company']
        user_id = options['user']
        if user_id < 1:
            raise CommandError('--user must be a positive user id.')
        prefix = (options['prefix'] or '').strip().lstrip('/')

        objects = StorageObject.objects.filter(company_id=company_id, owner_id=0)
        if prefix:
            objects = objects.filter(name__startswith=prefix)
        count = objects.count()
        total = objects.aggregate(total=Sum('size'))['total'] or 0
        grants = StorageAccessGrant.objects.filter(
            company_id=company_id,
            subject_type=StorageAccessGrant.SubjectType.USER,
            subject_id=LEGACY_UNOWNED_SUBJECT,
            object__in=objects,
        )
        grant_count = grants.count()
        if options['dry_run']:
            self.stdout.write(f'Would reassign {count} object(s), {total} bytes, {grant_count} grant(s) to user {user_id}.')
            return

        with transaction.atomic():
            grants.update(subject_id=str(user_id))
            StorageAccessGrant.objects.filter(
                company_id=company_id, created_by_id=0, object__in=objects
            ).update(created_by_id=user_id)
            apply_usage_delta(company_id=company_id, user_id=0, delta=-total)
            apply_usage_delta(company_id=company_id, user_id=user_id, delta=total)
            objects.update(owner_id=user_id)
        self.stdout.write(f'Reassigned {count} object(s), {total} bytes, {grant_count} grant(s) to user {user_id}.')
