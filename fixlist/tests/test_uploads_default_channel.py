"""Profile option: open the uploads / trash lists on all channels by default."""

from django.test import TestCase
from django.urls import reverse

from ..models import UploadedLog, UserProfile
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


class UploadsDefaultChannelTests(UploadedLogSharedSetupMixin, TestCase):

    def setUp(self):
        super().setUp()
        UploadedLog.objects.create(
            upload_id='alice-own-log', forum_username='forum_user', content='x', recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='bob-other-log', forum_username='forum_user', content='x', recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

    def _enable_all_channels_default(self):
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.uploads_all_channels_default = True
        profile.save()

    def test_option_is_off_by_default(self):
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        self.assertFalse(profile.uploads_all_channels_default)
        response = self.client.get(reverse('uploaded_logs'))
        self.assertEqual(response.context['channel'], 'mine')
        self.assertContains(response, 'alice-own-log')
        self.assertNotContains(response, 'bob-other-log')

    def test_profile_saves_the_option(self):
        self.client.post(reverse('profile'), {'uploads_all_channels_default': 'on', 'rule_set_mode': 'shared'})
        self.assertTrue(UserProfile.objects.get(user=self.user).uploads_all_channels_default)
        response = self.client.get(reverse('profile'))
        self.assertContains(response, 'name="uploads_all_channels_default" checked')
        self.client.post(reverse('profile'), {'rule_set_mode': 'shared'})
        self.assertFalse(UserProfile.objects.get(user=self.user).uploads_all_channels_default)

    def test_list_opens_on_all_channels_when_enabled(self):
        self._enable_all_channels_default()
        response = self.client.get(reverse('uploaded_logs'))
        self.assertEqual(response.context['channel'], 'all')
        self.assertContains(response, 'alice-own-log')
        self.assertContains(response, 'bob-other-log')
        self.assertEqual(response.context['pagination_query'], '')

    def test_my_channel_can_still_be_chosen_and_is_kept_across_pages(self):
        self._enable_all_channels_default()
        response = self.client.get(reverse('uploaded_logs'), {'channel': 'mine'})
        self.assertEqual(response.context['channel'], 'mine')
        self.assertNotContains(response, 'bob-other-log')
        # 'mine' is no longer the default, so page links must carry it.
        self.assertEqual(response.context['pagination_query'], 'channel=mine')
        self.assertContains(response, '<input type="hidden" name="channel" value="mine">')

    def test_redirect_after_an_action_keeps_a_non_default_channel(self):
        self._enable_all_channels_default()
        unassigned = UploadedLog.objects.create(upload_id='free-log', forum_username='forum_user', content='x')
        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'assign_to_me', 'upload_id': unassigned.upload_id, 'channel': 'mine'},
        )
        self.assertEqual(response.url, f"{reverse('uploaded_logs')}?channel=mine")
        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'unassign_to_general', 'upload_id': unassigned.upload_id, 'channel': 'all'},
        )
        self.assertEqual(response.url, reverse('uploaded_logs'))

    def test_trash_follows_the_option_too(self):
        self._enable_all_channels_default()
        response = self.client.get(reverse('uploads_trash'))
        self.assertEqual(response.context['channel'], 'all')
