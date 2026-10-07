import argparse

from django.core.management.base import BaseCommand
from django.db import connection

from apps.actions.delivery import retry_pending_webhooks
from apps.actions.scheduled_jobs import TRIGGER_COMMAND, TRIGGERS, run_recorded

JOB = 'retry_webhooks'


def run_counts(stats: dict) -> dict[str, int]:
    """Run summary stored on ``ScheduledJobRun.counts`` (attempted, succeeded, failed, given up)."""
    return {
        'webhook_deliveries_attempted': stats['processed'],
        'webhook_deliveries_succeeded': stats['delivered'],
        'webhook_deliveries_failed': stats['retried'],
        'webhook_deliveries_given_up': stats['dead'],
    }


class Command(BaseCommand):
    help = 'Retry pending or failed webhook outbox rows (every minute).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--batch-size',
            type=int,
            default=50,
            help='Maximum outbox rows to process in one run (default: 50).',
        )
        parser.add_argument(
            '--max-seconds',
            type=float,
            default=50.0,
            help='Stop after this many seconds (default: 50).',
        )
        parser.add_argument(
            '--concurrency',
            type=int,
            default=4,
            help='Parallel HTTP deliveries (default: 4).',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Claim rows but do not perform HTTP delivery (not recorded as a run).',
        )
        # Set to "celery" by the Celery task; external runs keep the default.
        parser.add_argument('--trigger', choices=TRIGGERS, default=TRIGGER_COMMAND, help=argparse.SUPPRESS)

    def handle(self, *args, **options):
        batch_size = max(1, int(options['batch_size']))
        max_seconds = max(0.1, float(options['max_seconds']))
        concurrency = max(1, int(options['concurrency']))
        dry_run = bool(options['dry_run'])

        def work(run_id):
            stats = retry_pending_webhooks(
                batch_size=batch_size,
                max_seconds=max_seconds,
                concurrency=concurrency,
                dry_run=dry_run,
                scheduled_job_run_id=run_id,
            )
            return stats, run_counts(stats)

        run_id = None
        try:
            if dry_run:
                stats, _counts = work(None)
            else:
                stats, run_id = run_recorded(JOB, options.get('trigger') or TRIGGER_COMMAND, work)
        finally:
            connection.close()
        self.stdout.write(
            self.style.SUCCESS(
                'retry_webhooks: '
                f"processed={stats['processed']} "
                f"delivered={stats['delivered']} "
                f"retried={stats['retried']} "
                f"dead={stats['dead']}"
                + (f' run_id={run_id}' if run_id else '')
            )
        )
