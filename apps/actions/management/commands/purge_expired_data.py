from django.core.management.base import BaseCommand
from django.db import connection

from apps.actions.retention import purge_expired_data


class Command(BaseCommand):
    help = (
        'Delete event log rows and finished webhook deliveries older than EVENT_LOG_RETENTION_DAYS '
        '(for cron, typically every hour).'
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
            help='Count expired rows without deleting them.',
        )

    def handle(self, *args, **options):
        stats = purge_expired_data(
            batch_size=max(1, int(options['batch_size'])),
            max_seconds=max(0.0, float(options['max_seconds'])) or None,
            dry_run=bool(options['dry_run']),
        )
        connection.close()
        verb = 'would delete' if options['dry_run'] else 'deleted'
        self.stdout.write(
            self.style.SUCCESS(
                f'purge_expired_data: {verb} '
                f"events={stats['events']} "
                f"webhook_deliveries={stats['webhook_deliveries']} "
                f"complete={str(stats['complete']).lower()}"
            )
        )
