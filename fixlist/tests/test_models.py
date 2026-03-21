from django.contrib.auth.models import User
from django.test import TestCase
from unittest.mock import patch

from ..models import Fixlist, UploadedLog


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


class UploadedLogModelTests(TestCase):
    def test_upload_id_defaults_to_two_words(self):
        uploaded = UploadedLog.objects.create(
            reddit_username='test_user',
            original_filename='log.txt',
            content='line-1',
        )

        parts = uploaded.upload_id.split('-')
        self.assertEqual(len(parts), 2)
        self.assertTrue(all(parts))

    def test_upload_id_adds_suffix_on_collision(self):
        UploadedLog.objects.create(
            upload_id='amber-otter',
            reddit_username='first_user',
            original_filename='a.txt',
            content='aaa',
        )

        with patch('fixlist.models.generate_memorable_upload_id', return_value='amber-otter'):
            uploaded = UploadedLog.objects.create(
                reddit_username='second_user',
                original_filename='b.txt',
                content='bbb',
            )

        self.assertRegex(uploaded.upload_id, r'^amber-otter-[a-z0-9]{2}$')

