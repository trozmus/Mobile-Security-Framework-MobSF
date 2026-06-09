"""Management command to wait for the database to be ready."""
import time

from django.core.management.base import BaseCommand
from django.db import connections
from django.db.utils import OperationalError


class Command(BaseCommand):
    help = 'Wait until the database accepts connections.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--timeout',
            type=int,
            default=60,
            help='Seconds to wait before giving up (default: 60)',
        )
        parser.add_argument(
            '--interval',
            type=float,
            default=2.0,
            help='Seconds between retries (default: 2)',
        )

    def handle(self, *args, **options):
        timeout = options['timeout']
        interval = options['interval']
        deadline = time.monotonic() + timeout
        db_conn = connections['default']

        self.stdout.write('[wait_for_db] Waiting for database...')
        while True:
            try:
                db_conn.ensure_connection()
                self.stdout.write(self.style.SUCCESS('[wait_for_db] Database ready.'))
                return
            except OperationalError as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SystemExit(f'[wait_for_db] Database not ready after {timeout}s: {exc}') from exc
                self.stdout.write(
                    f'[wait_for_db] Not ready yet ({exc}), retrying in {interval}s '
                    f'({remaining:.0f}s remaining)...'
                )
                time.sleep(interval)
