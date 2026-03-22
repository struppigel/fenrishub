from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from fixlist.models import UploadedLog


class Command(BaseCommand):
    help = 'Permanently delete trashed uploads older than 30 days.'

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=30)
        deleted_count, _ = UploadedLog.objects.filter(
            deleted_at__isnull=False,
            deleted_at__lt=cutoff,
        ).delete()
        self.stdout.write(f'Purged {deleted_count} trashed upload(s) older than 30 days.')
