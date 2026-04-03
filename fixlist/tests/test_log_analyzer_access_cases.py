import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory

from ..models import ClassificationRule, ParsedFilepathExclusion, UploadedLog
from ..views import log_analyzer_view


class UploadedLogAccessTests(TestCase):
    """Tests for cross-helper log viewing/analyzing permissions.
    
    All logged-in users can view and analyze all logs.
    Only editing operations (delete, assign, unassign) are restricted.
    """

    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="password123")
        self.bob = User.objects.create_user(username="bob", password="password123")
        self.charlie = User.objects.create_user(username="charlie", password="password123")
        
        # Create logs with different assignments
        self.alice_log = UploadedLog.objects.create(
            upload_id='alice-channel-log',
            reddit_username='user_a',
            original_filename='alice.txt',
            content='Alice content',
            recipient_user=self.alice,
        )
        self.bob_log = UploadedLog.objects.create(
            upload_id='bob-channel-log',
            reddit_username='user_b',
            original_filename='bob.txt',
            content='Bob content',
            recipient_user=self.bob,
        )
        self.general_log = UploadedLog.objects.create(
            upload_id='general-channel-log',
            reddit_username='user_c',
            original_filename='general.txt',
            content='General content',
            recipient_user=None,
        )

    def test_log_analyzer_view_shows_only_assigned_logs_in_dropdown(self):
        """The dropdown shows only assigned/general logs to avoid overwhelming users."""
        self.client.login(username='charlie', password='password123')
        response = self.client.get(reverse("log_analyzer"))
        
        self.assertEqual(response.status_code, 200)
        # Only the general log should be in dropdown (charlie not assigned to alice/bob logs)
        self.assertIn(b'general-channel-log', response.content)
        # Alice and Bob's logs should NOT be in dropdown
        self.assertNotIn(b'alice-channel-log', response.content)
        self.assertNotIn(b'bob-channel-log', response.content)

    def test_charlie_can_view_alice_log(self):
        """Charlie can view Alice's assigned log."""
        self.client.login(username='charlie', password='password123')
        
        response = self.client.get(reverse('uploaded_log_content_api', args=[self.alice_log.upload_id]))
        
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['content'], 'Alice content')

    def test_charlie_can_view_bob_log(self):
        """Charlie can view Bob's assigned log."""
        self.client.login(username='charlie', password='password123')
        
        response = self.client.get(reverse('uploaded_log_content_api', args=[self.bob_log.upload_id]))
        
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['content'], 'Bob content')

    def test_charlie_can_view_general_log(self):
        """Charlie can view unassigned general logs."""
        self.client.login(username='charlie', password='password123')
        
        response = self.client.get(reverse('uploaded_log_content_api', args=[self.general_log.upload_id]))
        
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload['content'], 'General content')

    def test_charlie_cannot_see_other_logs_in_dropdown_but_can_analyze(self):
        """Dropdown only shows assigned logs, but analyzing works if upload_id is provided directly."""
        self.client.login(username='charlie', password='password123')
        
        # Dropdown should only show general log
        response = self.client.get(reverse("log_analyzer"))
        self.assertNotIn(b'alice-channel-log', response.content)
        self.assertNotIn(b'bob-channel-log', response.content)
        
        # But analyze API should work if upload_id is specified
        response = self.client.post(
            reverse('analyze_log_api'),
            data=json.dumps({'log': 'test line', 'upload_id': self.alice_log.upload_id}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)

    def test_diff_logs_across_owners(self):
        """Users can view diffs of logs owned by different helpers."""
        self.client.login(username='charlie', password='password123')
        
        response = self.client.get(
            reverse('diff_uploaded_logs', args=[self.alice_log.upload_id, self.bob_log.upload_id])
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Alice content', response.content)
        self.assertIn(b'Bob content', response.content)

    def test_charlie_cannot_delete_alice_log(self):
        """Charlie cannot delete logs assigned to other helpers."""
        self.client.login(username='charlie', password='password123')
        
        response = self.client.post(
            reverse('uploaded_logs'),
            data={'action': 'delete', 'upload_id': self.alice_log.upload_id},
        )
        
        # Should redirect with error
        self.assertIn(response.status_code, [302, 200])
        self.alice_log.refresh_from_db()
        self.assertIsNone(self.alice_log.deleted_at)

    def test_charlie_cannot_assign_alice_log_not_in_scope(self):
        """Charlie can't see Alice's log in the UI, so assignment attempt results in 404."""
        self.client.login(username='charlie', password='password123')
        
        response = self.client.post(
            reverse('uploaded_logs'),
            data={'action': 'assign_to_me', 'upload_id': self.alice_log.upload_id},
        )
        
        # Should get 404 since alice's log isn't in charlie's scope
        self.assertEqual(response.status_code, 404)
        self.alice_log.refresh_from_db()
        self.assertEqual(self.alice_log.recipient_user, self.alice)

    def test_alice_can_delete_own_log(self):
        """Alice can delete her own assigned log."""
        self.client.login(username='alice', password='password123')
        
        response = self.client.post(
            reverse('uploaded_logs'),
            data={'action': 'delete', 'upload_id': self.alice_log.upload_id},
        )
        
        self.alice_log.refresh_from_db()
        self.assertIsNotNone(self.alice_log.deleted_at)

    def test_charlie_can_assign_general_log(self):
        """Any user can assign unassigned general logs."""
        self.client.login(username='charlie', password='password123')
        
        response = self.client.post(
            reverse('uploaded_logs'),
            data={'action': 'assign_to_me', 'upload_id': self.general_log.upload_id},
        )
        
        self.general_log.refresh_from_db()
        self.assertEqual(self.general_log.recipient_user, self.charlie)

    def test_restore_own_deleted_log_works(self):
        """Users can restore their own deleted logs from trash."""
        self.alice_log.deleted_at = timezone.now()
        self.alice_log.save()
        
        self.client.login(username='alice', password='password123')
        
        response = self.client.post(
            reverse('uploads_trash'),
            data={'action': 'restore', 'upload_id': self.alice_log.upload_id},
        )
        
        self.alice_log.refresh_from_db()
        self.assertIsNone(self.alice_log.deleted_at)

    def test_cannot_restore_other_user_deleted_log(self):
        """Users cannot restore logs deleted by other helpers."""
        self.alice_log.deleted_at = timezone.now()
        self.alice_log.save()
        
        self.client.login(username='charlie', password='password123')
        
        response = self.client.post(
            reverse('uploads_trash'),
            data={'action': 'restore', 'upload_id': self.alice_log.upload_id},
        )
        
        self.alice_log.refresh_from_db()
        self.assertIsNotNone(self.alice_log.deleted_at)


