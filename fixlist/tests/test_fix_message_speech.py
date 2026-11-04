"""The FRST fix message: one flagged speech, edited in the profile and listed
among the speeches, and copied from any fixlist page.

These describe the workflow from the helper's side, so they hold whatever the
storage looks like: an old fixlist without a response must still give its fix
instructions, and a brand-new account must have them from the start."""

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import Fixlist, Speech, UploadedLog
from ..views.auth import DEFAULT_FRST_FIX_MESSAGE_TEMPLATE


class FixMessageOnFixlistPageTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='pw')
        self.client.login(username='alice', password='pw')
        upload = UploadedLog.objects.create(
            upload_id='amber-raven', forum_username='george', original_filename='FRST.txt',
            content='Running from C:\\Users\\George\\Desktop\\FRST64.exe\nline-1',
        )
        # An old fixlist: made before responses existed, so it has none.
        self.fixlist = Fixlist.objects.create(
            owner=self.user, username='george', content='Start::\nEnd::', source_uploaded_log=upload,
        )

    def test_fixlist_without_response_still_offers_its_fix_message(self):
        response = self.client.get(reverse('view_fixlist', args=[self.fixlist.pk]))

        self.assertContains(response, 'copy fix message')
        self.assertEqual(response.context['frst_fix_message_template'], DEFAULT_FRST_FIX_MESSAGE_TEMPLATE)
        self.assertIn(f'/share/{self.fixlist.share_token}/', response.context['share_url'])
        self.assertEqual(response.context['frst_run_path'], 'C:\\Users\\George\\Desktop')

    def test_fixlist_page_uses_the_text_edited_in_the_profile(self):
        self.client.post(reverse('profile'), {'frst_fix_message': 'mine: {FIXLISTLINK}'})

        response = self.client.get(reverse('view_fixlist', args=[self.fixlist.pk]))

        self.assertEqual(response.context['frst_fix_message_template'], 'mine: {FIXLISTLINK}')


class FixMessageSpeechTests(TestCase):
    def test_new_account_has_the_default_fix_message_speech(self):
        user = User.objects.create_user(username='newbie', password='pw')

        speech = Speech.objects.get(owner=user, is_fix_message=True)
        self.assertEqual(speech.content, DEFAULT_FRST_FIX_MESSAGE_TEMPLATE)
        self.assertTrue(speech.analyzer_users.filter(pk=user.pk).exists())

    def test_account_that_cannot_log_in_gets_none(self):
        user = User.objects.create_user(username='placeholder_account')
        self.assertFalse(Speech.objects.filter(owner=user).exists())

    def test_profile_and_speeches_page_show_the_same_entry(self):
        user = User.objects.create_user(username='alice', password='pw')
        self.client.login(username='alice', password='pw')

        self.client.post(reverse('profile'), {'frst_fix_message': 'edited in the profile'})
        speech = Speech.objects.get(owner=user, is_fix_message=True)
        self.assertEqual(speech.content, 'edited in the profile')
        self.assertEqual(Speech.objects.filter(owner=user, is_fix_message=True).count(), 1)

        self.client.post(reverse('speeches'), {
            'action': 'edit', 'pk': speech.pk, 'name': speech.name,
            'content': 'edited on the speeches page', 'category': speech.category,
        })
        profile_page = self.client.get(reverse('profile'))
        self.assertEqual(profile_page.context['frst_fix_message'], 'edited on the speeches page')

    def test_empty_profile_text_means_the_default(self):
        user = User.objects.create_user(username='alice', password='pw')
        self.client.login(username='alice', password='pw')

        self.client.post(reverse('profile'), {'frst_fix_message': '   '})

        speech = Speech.objects.get(owner=user, is_fix_message=True)
        self.assertEqual(speech.content, DEFAULT_FRST_FIX_MESSAGE_TEMPLATE)

    def test_fix_message_speech_cannot_be_deleted_from_the_speeches_page(self):
        user = User.objects.create_user(username='alice', password='pw')
        self.client.login(username='alice', password='pw')
        speech = Speech.objects.get(owner=user, is_fix_message=True)

        page = self.client.get(reverse('speeches'))
        self.assertContains(page, 'also in your profile')

        self.client.post(reverse('speeches'), {'action': 'delete', 'pk': speech.pk})
        self.assertTrue(Speech.objects.filter(pk=speech.pk).exists())
