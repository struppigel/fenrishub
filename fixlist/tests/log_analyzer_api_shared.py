from django.contrib.auth.models import User
from django.test import TestCase


class LogAnalyzerApiBaseTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="analyzer", password="password123")
        self.other_user = User.objects.create_user(username="other_helper", password="password123")
