import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Creates or updates a superuser from environment variables if enabled.'

    def handle(self, *args, **options):
        enabled = os.getenv('AUTO_CREATE_SUPERUSER', '').strip().lower() in {
            '1',
            'true',
            'yes',
            'on',
        }
        if not enabled:
            self.stdout.write('AUTO_CREATE_SUPERUSER is disabled; skipping superuser bootstrap.')
            return

        username = os.getenv('DJANGO_SUPERUSER_USERNAME', '').strip()
        email = os.getenv('DJANGO_SUPERUSER_EMAIL', '').strip()
        password = os.getenv('DJANGO_SUPERUSER_PASSWORD', '').strip()

        if not username or not password:
            self.stdout.write(
                'Missing DJANGO_SUPERUSER_USERNAME or DJANGO_SUPERUSER_PASSWORD; '
                'skipping superuser bootstrap.'
            )
            return

        User = get_user_model()
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                'email': email,
                'is_staff': True,
                'is_superuser': True,
            },
        )

        if created:
            user.set_password(password)
            user.save(update_fields=['password'])
            self.stdout.write(f'Created superuser: {username}')
            return

        changed = False
        if email and user.email != email:
            user.email = email
            changed = True
        if not user.is_staff:
            user.is_staff = True
            changed = True
        if not user.is_superuser:
            user.is_superuser = True
            changed = True
        if not user.check_password(password):
            user.set_password(password)
            changed = True

        if changed:
            user.save()

        self.stdout.write(f'Superuser already exists: {username}')
