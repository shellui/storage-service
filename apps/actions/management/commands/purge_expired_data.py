import argparse

from django.core.management.base import BaseCommand
from django.db import connection

from apps.actions.retention import purge_expired_data
from apps.actions.scheduled_jobs import TRIGGER_COMMAND, TRIGGERS, run_recorded

JOB = 'purge_expired_data'


class Command(BaseCommand):
    help = (
        'Delete event log rows, finished webhook and email deliveries, and old scheduled job runs '
        'past EVENT_LOG_RETENTION_DAYS (hourly when the in-container scheduler is running).'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--batch-size',
            type=int,
            default=2000,
            help='Rows deleted per statement (default: 2000).',
        )
        parser.add_argument(
            '--max-seconds',
            type=float,
            default=0,
            help='Stop after this many seconds; the next run continues (default: 0, no limit).',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Count expired rows without deleting them (not recorded as a run).',
        )
        # Set to "celery" by the Celery task; external runs keep the default.
        parser.add_argument('--trigger', choices=TRIGGERS, default=TRIGGER_COMMAND, help=argparse.SUPPRESS)

    def handle(self, *args, **options):
        dry_run = bool(options['dry_run'])

        def work(_run_id):
            stats = purge_expired_data(
                batch_size=max(1, int(options['batch_size'])),
                max_seconds=max(0.0, float(options['max_seconds'])) or None,
                dry_run=dry_run,
            )
            counts = {k: v for k, v in stats.items() if k != 'complete'}
            counts['complete'] = bool(stats['complete'])
            return stats, counts

        run_id = None
        try:
            if dry_run:
                stats, _counts = work(None)
            else:
                stats, run_id = run_recorded(JOB, options.get('trigger') or TRIGGER_COMMAND, work)
        finally:
            connection.close()
        verb = 'would delete' if dry_run else 'deleted'
        self.stdout.write(
            self.style.SUCCESS(
                f'purge_expired_data: {verb} '
                f"events={stats['events']} "
                f"webhook_deliveries={stats['webhook_deliveries']} "
                f"email_events={stats['email_events']} "
                f"scheduled_job_runs={stats['scheduled_job_runs']} "
                f"complete={str(stats['complete']).lower()}"
                + (f' run_id={run_id}' if run_id else '')
            )
        )
