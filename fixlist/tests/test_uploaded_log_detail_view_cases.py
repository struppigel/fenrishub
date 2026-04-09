from django.test import TestCase
from django.urls import reverse

from ..models import UploadedLog
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


class UploadedLogDetailViewTests(UploadedLogSharedSetupMixin, TestCase):

    def test_authenticated_user_can_view_upload_by_id(self):
        uploaded = UploadedLog.objects.create(
            upload_id='bright-river',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[uploaded.upload_id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'payload')

    def test_detail_view_shows_detected_encoding_when_set(self):
        uploaded = UploadedLog.objects.create(
            upload_id='encoded-river',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            detected_encoding='utf-16-le',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[uploaded.upload_id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '>encoding<')
        self.assertContains(response, 'utf-16-le')

    def test_detail_view_omits_encoding_row_when_unset(self):
        uploaded = UploadedLog.objects.create(
            upload_id='plain-river',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[uploaded.upload_id]))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, '>encoding<')

    def test_authenticated_user_can_delete_upload(self):
        uploaded = UploadedLog.objects.create(
            upload_id='quiet-forest',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'delete', 'upload_id': uploaded.upload_id},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('uploaded_logs'))
        uploaded.refresh_from_db()
        self.assertIsNotNone(uploaded.deleted_at)

    def test_authenticated_user_cannot_delete_other_helpers_assigned_upload_from_detail(self):
        uploaded = UploadedLog.objects.create(
            upload_id='private-delete-denied',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('view_uploaded_log', args=[uploaded.upload_id]),
            {'action': 'delete'},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Only the assigned helper can delete private-delete-denied.')
        uploaded.refresh_from_db()
        self.assertIsNone(uploaded.deleted_at)

    def test_delete_button_hidden_for_other_helpers_assigned_upload(self):
        uploaded = UploadedLog.objects.create(
            upload_id='delete-hidden-other-helper',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[uploaded.upload_id]))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'name="action" value="delete"')

    def test_assign_unassigned_upload_to_current_user_from_list(self):
        uploaded = UploadedLog.objects.create(
            upload_id='assign-me-list',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            recipient_user=None,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'assign_to_me', 'upload_id': uploaded.upload_id},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('uploaded_logs'))
        uploaded.refresh_from_db()
        self.assertEqual(uploaded.recipient_user, self.user)

    def test_assign_from_list_preserves_show_all_toggle_on_redirect(self):
        uploaded = UploadedLog.objects.create(
            upload_id='assign-keep-show-all',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            recipient_user=None,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'assign_to_me', 'upload_id': uploaded.upload_id, 'show_all': '1'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"{reverse('uploaded_logs')}?show_all=1")

    def test_assign_from_list_preserves_username_filter_on_redirect(self):
        uploaded = UploadedLog.objects.create(
            upload_id='assign-keep-filter',
            reddit_username='alice_user',
            original_filename='x.txt',
            content='payload',
            recipient_user=None,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'assign_to_me', 'upload_id': uploaded.upload_id, 'u': 'alice_user'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"{reverse('uploaded_logs')}?u=alice_user")

    def test_assign_unassigned_upload_to_current_user_from_detail(self):
        uploaded = UploadedLog.objects.create(
            upload_id='assign-me-detail',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            recipient_user=None,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('view_uploaded_log', args=[uploaded.upload_id]),
            {'action': 'assign_to_me'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('view_uploaded_log', args=[uploaded.upload_id]))
        uploaded.refresh_from_db()
        self.assertEqual(uploaded.recipient_user, self.user)

    def test_assign_to_me_action_rejects_already_assigned_upload(self):
        uploaded = UploadedLog.objects.create(
            upload_id='assign-already-owned',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'assign_to_me', 'upload_id': uploaded.upload_id},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'already assigned')
        uploaded.refresh_from_db()
        self.assertEqual(uploaded.recipient_user, self.user)

    def test_unassign_to_general_from_list(self):
        uploaded = UploadedLog.objects.create(
            upload_id='unassign-list',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'unassign_to_general', 'upload_id': uploaded.upload_id},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('uploaded_logs'))
        uploaded.refresh_from_db()
        self.assertIsNone(uploaded.recipient_user)

    def test_unassign_to_general_from_detail(self):
        uploaded = UploadedLog.objects.create(
            upload_id='unassign-detail',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('view_uploaded_log', args=[uploaded.upload_id]),
            {'action': 'unassign_to_general'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('view_uploaded_log', args=[uploaded.upload_id]))
        uploaded.refresh_from_db()
        self.assertIsNone(uploaded.recipient_user)

    def test_unassign_to_general_denied_for_non_assigned_user(self):
        uploaded = UploadedLog.objects.create(
            upload_id='unassign-denied',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
            recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('view_uploaded_log', args=[uploaded.upload_id]),
            {'action': 'unassign_to_general'},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Only the assigned helper can unassign')
        uploaded.refresh_from_db()
        self.assertEqual(uploaded.recipient_user, self.other_user)

    def test_authenticated_user_can_view_other_helper_channel_upload_by_detail_link(self):
        bob_upload = UploadedLog.objects.create(
            upload_id='bob-private',
            reddit_username='bob_user',
            original_filename='b.txt',
            content='payload',
            recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[bob_upload.upload_id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'payload')

    def test_rename_reddit_username_on_upload_detail(self):
        uploaded = UploadedLog.objects.create(
            upload_id='rename-test',
            reddit_username='old_name',
            original_filename='x.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('view_uploaded_log', args=[uploaded.upload_id]),
            {'action': 'rename_reddit', 'reddit_username': 'new_name'},
        )

        self.assertEqual(response.status_code, 302)
        uploaded.refresh_from_db()
        self.assertEqual(uploaded.reddit_username, 'new_name')

    def test_rename_reddit_ignores_empty_username(self):
        uploaded = UploadedLog.objects.create(
            upload_id='rename-empty',
            reddit_username='keep_this',
            original_filename='x.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        self.client.post(
            reverse('view_uploaded_log', args=[uploaded.upload_id]),
            {'action': 'rename_reddit', 'reddit_username': ''},
        )

        uploaded.refresh_from_db()
        self.assertEqual(uploaded.reddit_username, 'keep_this')

