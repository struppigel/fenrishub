from django.contrib.auth.models import User
from django.test import TestCase

from ..models import Fixlist


class FixlistModelTests(TestCase):
    def test_share_token_generated_on_create(self):
        user = User.objects.create_user(username="alice", password="password123")

        fixlist = Fixlist.objects.create(
            owner=user,
            title="Initial",
            content="line1",
        )

        self.assertEqual(len(fixlist.share_token), 32)
        self.assertTrue(fixlist.share_token.isalnum())

