"""The models and the migrations describe the same schema."""

from io import StringIO

from django.core.management import call_command
from django.test import TestCase


class MigrationsInSyncTests(TestCase):
    def test_no_missing_migrations(self):
        out = StringIO()
        try:
            call_command('makemigrations', 'fixlist', '--check', '--dry-run', stdout=out, stderr=out)
        except SystemExit:
            self.fail(f'The models differ from the migrations:\n{out.getvalue()}')
