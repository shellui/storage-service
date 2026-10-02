from django.core.management.base import BaseCommand
from django.db import connection

from apps.actions.delivery import retry_pending_webhooks


class Command(BaseCommand):
    help = (
        'Retry pending or failed webhook and email-service outbox rows '
        '(for cron, typically every minute).'
    )

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
            help='Claim rows but do not perform HTTP delivery.',
        )

    def handle(self, *args, **options):
        batch_size = max(1, int(options['batch_size']))
        max_seconds = max(0.1, float(options['max_seconds']))
        concurrency = max(1, int(options['concurrency']))
        dry_run = bool(options['dry_run'])

        stats = retry_pending_webhooks(
            batch_size=batch_size,
            max_seconds=max_seconds,
            concurrency=concurrency,
            dry_run=dry_run,
        )
        connection.close()
        self.stdout.write(
            self.style.SUCCESS(
                'retry_webhooks: '
                f"processed={stats['processed']} "
                f"delivered={stats['delivered']} "
                f"retried={stats['retried']} "
                f"dead={stats['dead']}"
            )
        )
