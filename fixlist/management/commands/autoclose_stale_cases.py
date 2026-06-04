from django.core.management.base import BaseCommand

from fixlist.views.utils import _autoclose_stale_cases


class Command(BaseCommand):
    help = 'Close open infection cases with no activity in over 30 days (excludes training cases).'

    def handle(self, *args, **options):
        closed = _autoclose_stale_cases()
        self.stdout.write(f'Closed {closed} stale infection case(s).')
