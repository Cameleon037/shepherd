from django.core.management.base import BaseCommand

from jobs.utils import reap_stale_jobs


class Command(BaseCommand):
    help = (
        'Mark running jobs whose recorded process is gone as failed, and reclaim '
        'orphaned Chromium left behind by dead scans. Age is never used: scans may '
        'legitimately run for days.'
    )

    def handle(self, *args, **options):
        reaped = reap_stale_jobs()
        self.stdout.write(self.style.SUCCESS(f'Reaped {reaped} stale job(s).'))
