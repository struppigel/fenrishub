from django.contrib.auth.models import User
from django.core.cache import cache


class UploadedLogSharedSetupMixin:
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.other_user = User.objects.create_user(username='bob', password='password123')
        cache.clear()

