import importlib

from django.apps import apps
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import Fixlist, RuleTag, Speech, UploadedLog, UserProfile
from ..views.auth import DEFAULT_FRST_FIX_MESSAGE_TEMPLATE

migration_0079 = importlib.import_module('fixlist.migrations.0079_fix_message_speeches_and_builtin_tags')


class SaveTimePlaceholderTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='pw')
        self.client.login(username='alice', password='pw')
        self.upload = UploadedLog.objects.create(
            upload_id='amber-raven',
            forum_username='george',
            original_filename='FRST.txt',
            content='Running from C:\\Users\\George\\Desktop\\FRST64.exe\nline-1',
        )

    def _create(self, response, **extra):
        data = {'content': 'Start::\nEnd::', 'response': response, **extra}
        self.client.post(reverse('create_fixlist'), data)
        return Fixlist.objects.latest('pk')

    def test_create_fills_fixlist_link_and_frst_path(self):
        fixlist = self._create(
            'link: {FIXLISTLINK}\npath: {FRSTPATH}',
            source_upload_id='amber-raven',
        )
        self.assertIn(f'/share/{fixlist.share_token}/', fixlist.response)
        self.assertNotIn('{FIXLISTLINK}', fixlist.response)
        self.assertIn('path: C:\\Users\\George\\Desktop', fixlist.response)

    def test_create_fills_usernames_left_over_from_insert(self):
        fixlist = self._create('Hi {USERNAME}, {HELPERNAME} here', source_upload_id='amber-raven')
        self.assertEqual(fixlist.response, 'Hi george, alice here')

    def test_token_without_value_stays(self):
        # No source log: no FRST path and no forum user to fill in.
        fixlist = self._create('path: {FRSTPATH}, hi {USERNAME}')
        self.assertEqual(fixlist.response, 'path: {FRSTPATH}, hi {USERNAME}')

    def test_update_in_place_from_analyzer_fills_link(self):
        fixlist = Fixlist.objects.create(owner=self.user, username='george', content='x')
        self.client.post(reverse('create_fixlist'), {
            'content': 'y', 'response': 'see {FIXLISTLINK}', 'fixlist_id': str(fixlist.pk),
        })
        fixlist.refresh_from_db()
        self.assertTrue(fixlist.response.endswith(f'/share/{fixlist.share_token}/'))

    def test_saving_on_fixlist_page_fills_link(self):
        fixlist = Fixlist.objects.create(owner=self.user, username='george', content='x')
        self.client.post(reverse('view_fixlist', args=[fixlist.pk]), {
            'action': 'update', 'username': 'george', 'content': 'x',
            'response': 'see {FIXLISTLINK}',
        })
        fixlist.refresh_from_db()
        self.assertTrue(fixlist.response.endswith(f'/share/{fixlist.share_token}/'))


class FixMessageMigrationTests(TestCase):
    """Migration 0079, for accounts that existed before the new-account signal."""

    def _account_without_speech(self, username, password='pw'):
        user = User.objects.create_user(username=username, password=password)
        Speech.objects.filter(owner=user).delete()
        return user

    def test_default_and_custom_messages_become_flagged_speeches(self):
        default_user = self._account_without_speech('dora')
        custom_user = self._account_without_speech('carl')
        UserProfile.objects.create(user=custom_user, frst_fix_message='my own text')

        migration_0079.create_fix_message_speeches(apps, None)

        default_speech = Speech.objects.get(owner=default_user, is_fix_message=True)
        self.assertEqual(default_speech.content, DEFAULT_FRST_FIX_MESSAGE_TEMPLATE)
        self.assertFalse(default_speech.is_shared)
        self.assertTrue(default_speech.analyzer_users.filter(pk=default_user.pk).exists())
        self.assertEqual(Speech.objects.get(owner=custom_user, is_fix_message=True).content, 'my own text')

    def test_accounts_that_cannot_log_in_get_none(self):
        placeholder = User.objects.create_user(username='passwordless_placeholder')

        migration_0079.create_fix_message_speeches(apps, None)

        self.assertFalse(Speech.objects.filter(owner=placeholder).exists())

    def test_an_existing_speech_named_frst_fix_keeps_its_name(self):
        user = self._account_without_speech('erin')
        Speech.objects.create(owner=user, name='FRST fix', content='own text')

        migration_0079.create_fix_message_speeches(apps, None)

        flagged = Speech.objects.get(owner=user, is_fix_message=True)
        self.assertEqual(flagged.name, 'FRST fix (2)')
        self.assertEqual(Speech.objects.get(owner=user, name='FRST fix').content, 'own text')

    def test_builtin_tags_are_seeded_once(self):
        migration_0079.seed_builtin_tags(apps, None)
        migration_0079.seed_builtin_tags(apps, None)
        codes = sorted(RuleTag.objects.exclude(builtin_code=None).values_list('builtin_code', flat=True))
        self.assertEqual(codes, sorted(code for code, _name, _desc in migration_0079.BUILTIN_TAGS))
