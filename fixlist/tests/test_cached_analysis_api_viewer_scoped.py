"""Tests that the cached-analysis API picks the row matching the viewer's key."""
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import (
    UploadedLog,
    UploadedLogAnalysis,
    UserProfile,
)


class CachedAnalysisApiViewerScopedTests(TestCase):
    def setUp(self):
        self.shared_user = User.objects.create_user(username='alice', password='pw')
        UserProfile.objects.create(user=self.shared_user, rule_set_mode='shared')
        self.private_user = User.objects.create_user(username='bob', password='pw')
        UserProfile.objects.create(user=self.private_user, rule_set_mode='private')

        self.log = UploadedLog.objects.create(
            forum_username='forum_user',
            original_filename='frst.txt',
            content='Scan result of Farbar Recovery Scan Tool',
            log_type='FRST',
        )
        UploadedLogAnalysis.objects.create(
            upload=self.log,
            rule_set_key='shared',
            payload={'lines': [], 'summary': {'tag': 'shared'}, 'warnings': []},
            source_content_hash=self.log.content_hash,
        )
        UploadedLogAnalysis.objects.create(
            upload=self.log,
            rule_set_key=f'private:{self.private_user.id}',
            payload={'lines': [], 'summary': {'tag': 'private'}, 'warnings': []},
            source_content_hash=self.log.content_hash,
        )

    def _fetch(self, username):
        self.client.login(username=username, password='pw')
        response = self.client.get(
            reverse('uploaded_log_cached_analysis_api', args=[self.log.upload_id]),
        )
        return response.json()

    def test_shared_user_gets_shared_payload(self):
        payload = self._fetch('alice')
        self.assertTrue(payload['has_cache'])
        self.assertEqual(payload['payload']['summary']['tag'], 'shared')

    def test_private_user_gets_their_private_payload(self):
        payload = self._fetch('bob')
        self.assertTrue(payload['has_cache'])
        self.assertEqual(payload['payload']['summary']['tag'], 'private')

    def test_missing_key_for_viewer_returns_has_cache_false(self):
        # Carol exists, is private, but has no cache row for her key yet.
        carol = User.objects.create_user(username='carol', password='pw')
        UserProfile.objects.create(user=carol, rule_set_mode='private')

        payload = self._fetch('carol')
        self.assertFalse(payload['has_cache'])
        self.assertIsNone(payload['payload'])
