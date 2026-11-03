from django.core.management.base import BaseCommand

from fixlist.views.utils import _purge_old_trash


class Command(BaseCommand):
    help = (
        'Purge trashed records older than 7 days, all records older than 30 days, '
        'and API request logs older than API_LOG_RETENTION_DAYS.'
    )

    def handle(self, *args, **options):
        _purge_old_trash()
        self.stdout.write('Purge complete.')
