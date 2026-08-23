from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import Speech


class SpeechViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.other_user = User.objects.create_user(username='bob', password='password123')
        self.client.login(username='alice', password='password123')

    def test_own_speeches_shown_by_default(self):
        Speech.objects.create(owner=self.user, name='my speech', content='own content')
        Speech.objects.create(owner=self.other_user, name='bob speech', content='shared', is_shared=True)

        response = self.client.get(reverse('speeches'))

        self.assertContains(response, 'my speech')
        self.assertNotContains(response, 'bob speech')

    def test_shared_by_includes_shared_speeches(self):
        Speech.objects.create(owner=self.user, name='my speech', content='own content')
        Speech.objects.create(owner=self.other_user, name='bob speech', content='shared', is_shared=True)
        Speech.objects.create(owner=self.other_user, name='bob private', content='private', is_shared=False)

        response = self.client.get(reverse('speeches'), {'shared_by': 'bob'})

        self.assertContains(response, 'bob speech')
        self.assertNotContains(response, 'bob private')

    def test_shared_by_selector_shown_when_nobody_shares(self):
        Speech.objects.create(owner=self.user, name='my speech', content='own content')

        response = self.client.get(reverse('speeches'))

        self.assertContains(response, 'name="shared_by"')
        self.assertContains(response, 'no shared speeches yet')

    def test_shared_by_selector_lists_sharing_users(self):
        Speech.objects.create(owner=self.other_user, name='bob speech', content='shared', is_shared=True)

        response = self.client.get(reverse('speeches'))

        self.assertContains(response, 'name="shared_by"')
        self.assertNotContains(response, 'no shared speeches yet')
        self.assertContains(response, '+ bob')

    def test_search_filters_by_name(self):
        Speech.objects.create(owner=self.user, name='all clean', content='content a')
        Speech.objects.create(owner=self.user, name='rerun frst', content='content b')

        response = self.client.get(reverse('speeches'), {'q': 'clean'})

        self.assertContains(response, 'all clean')
        self.assertNotContains(response, 'rerun frst')

    def test_search_filters_by_content(self):
        Speech.objects.create(owner=self.user, name='speech a', content='please reboot your machine')
        Speech.objects.create(owner=self.user, name='speech b', content='run the scan again')

        response = self.client.get(reverse('speeches'), {'q': 'reboot'})

        self.assertContains(response, 'speech a')
        self.assertNotContains(response, 'speech b')

    def test_search_filters_by_owner_with_shared_by(self):
        Speech.objects.create(owner=self.user, name='alice speech', content='x')
        Speech.objects.create(owner=self.other_user, name='bob speech', content='y', is_shared=True)

        response = self.client.get(reverse('speeches'), {'q': 'bob', 'shared_by': 'bob'})

        self.assertContains(response, 'bob speech')
        self.assertNotContains(response, 'alice speech')

    def test_toggle_analyzer_adds_own_speech(self):
        speech = Speech.objects.create(owner=self.user, name='my speech', content='c')
        self.assertFalse(speech.analyzer_users.filter(pk=self.user.pk).exists())

        response = self.client.post(reverse('speeches_toggle_analyzer_api'), {'pk': speech.pk})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['selected'])
        self.assertTrue(speech.analyzer_users.filter(pk=self.user.pk).exists())

    def test_toggle_analyzer_removes_own_speech(self):
        speech = Speech.objects.create(owner=self.user, name='my speech', content='c')
        speech.analyzer_users.add(self.user)

        response = self.client.post(reverse('speeches_toggle_analyzer_api'), {'pk': speech.pk})

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['selected'])
        self.assertFalse(speech.analyzer_users.filter(pk=self.user.pk).exists())

    def test_toggle_analyzer_adds_shared_speech_from_other_user(self):
        speech = Speech.objects.create(owner=self.other_user, name='bob shared', content='c', is_shared=True)

        response = self.client.post(reverse('speeches_toggle_analyzer_api'), {'pk': speech.pk})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['selected'])
        self.assertTrue(speech.analyzer_users.filter(pk=self.user.pk).exists())

    def test_toggle_analyzer_rejects_private_speech_from_other_user(self):
        speech = Speech.objects.create(owner=self.other_user, name='bob private', content='c', is_shared=False)

        response = self.client.post(reverse('speeches_toggle_analyzer_api'), {'pk': speech.pk})

        self.assertEqual(response.status_code, 404)
        self.assertFalse(speech.analyzer_users.filter(pk=self.user.pk).exists())

    def test_analyzer_speech_ids_in_context(self):
        speech = Speech.objects.create(owner=self.user, name='my speech', content='c')
        speech.analyzer_users.add(self.user)

        response = self.client.get(reverse('speeches'))

        self.assertIn(speech.pk, response.context['analyzer_speech_ids'])

    def test_create_speech_with_category(self):
        self.client.post(reverse('speeches'), {
            'action': 'create', 'name': 'cat speech',
            'content': 'c', 'category': 'Closing',
        })
        speech = Speech.objects.get(name='cat speech')
        self.assertEqual(speech.category, 'Closing')

    def test_create_speech_selects_it_for_the_analyzer(self):
        self.client.post(reverse('speeches'), {
            'action': 'create', 'name': 'auto selected', 'content': 'c',
        })
        speech = Speech.objects.get(name='auto selected')
        self.assertTrue(speech.analyzer_users.filter(pk=self.user.pk).exists())

    def test_create_speech_defaults_to_generic_category(self):
        self.client.post(reverse('speeches'), {
            'action': 'create', 'name': 'default cat',
            'content': 'c',
        })
        speech = Speech.objects.get(name='default cat')
        self.assertEqual(speech.category, 'generic')

    def test_create_duplicate_name_is_rejected(self):
        Speech.objects.create(owner=self.user, name='dupe', content='first')

        self.client.post(reverse('speeches'), {
            'action': 'create', 'name': 'dupe', 'content': 'second',
        })

        self.assertEqual(Speech.objects.filter(owner=self.user, name='dupe').count(), 1)

    def test_create_duplicate_name_reports_the_error(self):
        Speech.objects.create(owner=self.user, name='dupe', content='first')

        response = self.client.post(reverse('speeches'), {
            'action': 'create', 'name': 'dupe', 'content': 'second',
        }, follow=True)

        self.assertContains(response, 'A speech named &quot;dupe&quot; already exists.')

    def test_create_blank_name_reports_the_error(self):
        response = self.client.post(reverse('speeches'), {
            'action': 'create', 'name': '  ', 'content': 'body',
        }, follow=True)

        self.assertContains(response, 'Speech name is required.')
        self.assertFalse(Speech.objects.exists())

    def test_create_blank_content_reports_the_error(self):
        response = self.client.post(reverse('speeches'), {
            'action': 'create', 'name': 'greeting', 'content': '  ',
        }, follow=True)

        self.assertContains(response, 'Speech content is required.')
        self.assertFalse(Speech.objects.exists())

    def test_edit_duplicate_name_is_rejected(self):
        Speech.objects.create(owner=self.user, name='taken', content='first')
        speech = Speech.objects.create(owner=self.user, name='mine', content='second')

        self.client.post(reverse('speeches'), {
            'action': 'edit', 'pk': speech.pk, 'name': 'taken', 'content': 'second',
        })

        speech.refresh_from_db()
        self.assertEqual(speech.name, 'mine')

    def test_edit_keeping_own_name_is_allowed(self):
        speech = Speech.objects.create(owner=self.user, name='mine', content='before')

        self.client.post(reverse('speeches'), {
            'action': 'edit', 'pk': speech.pk, 'name': 'mine', 'content': 'after',
        })

        speech.refresh_from_db()
        self.assertEqual(speech.content, 'after')

    def test_edit_speech_changes_category(self):
        speech = Speech.objects.create(
            owner=self.user, name='s', content='c', category='generic',
        )
        self.client.post(reverse('speeches'), {
            'action': 'edit', 'pk': speech.pk,
            'name': 's', 'content': 'c', 'category': 'Intro',
        })
        speech.refresh_from_db()
        self.assertEqual(speech.category, 'Intro')

    def test_edit_speech_blank_category_defaults_to_generic(self):
        speech = Speech.objects.create(
            owner=self.user, name='s', content='c', category='Old',
        )
        self.client.post(reverse('speeches'), {
            'action': 'edit', 'pk': speech.pk,
            'name': 's', 'content': 'c', 'category': '',
        })
        speech.refresh_from_db()
        self.assertEqual(speech.category, 'generic')

    def test_edit_rejects_speech_owned_by_another_user(self):
        speech = Speech.objects.create(owner=self.other_user, name='bob speech', content='c', is_shared=True)

        response = self.client.post(reverse('speeches'), {
            'action': 'edit', 'pk': speech.pk,
            'name': 'hijacked', 'content': 'c',
        })

        self.assertEqual(response.status_code, 404)
        speech.refresh_from_db()
        self.assertEqual(speech.name, 'bob speech')

    def test_delete_speech(self):
        speech = Speech.objects.create(owner=self.user, name='goodbye', content='c')

        self.client.post(reverse('speeches'), {'action': 'delete', 'pk': speech.pk})

        self.assertFalse(Speech.objects.filter(pk=speech.pk).exists())

    def test_filter_by_category(self):
        Speech.objects.create(owner=self.user, name='intro speech', content='c', category='Intro')
        Speech.objects.create(owner=self.user, name='gen speech', content='c', category='generic')

        response = self.client.get(reverse('speeches'), {'category': 'Intro'})

        self.assertContains(response, 'intro speech')
        self.assertNotContains(response, 'gen speech')

    def test_categories_in_context(self):
        Speech.objects.create(owner=self.user, name='a', content='c', category='Alpha')
        Speech.objects.create(owner=self.user, name='b', content='c', category='Beta')

        response = self.client.get(reverse('speeches'))

        self.assertEqual(response.context['categories'], ['Alpha', 'Beta'])

    def test_category_shown_in_speech_list(self):
        Speech.objects.create(owner=self.user, name='my speech', content='c', category='Closing')

        response = self.client.get(reverse('speeches'))

        self.assertContains(response, '[Closing]')

    def test_speeches_api_returns_only_selected_speeches(self):
        selected = Speech.objects.create(owner=self.user, name='selected', content='c')
        selected.analyzer_users.add(self.user)
        Speech.objects.create(owner=self.user, name='not selected', content='c')

        response = self.client.get(reverse('speeches_api'))
        data = response.json()

        names = [s['name'] for s in data['speeches']]
        self.assertIn('selected', names)
        self.assertNotIn('not selected', names)

    def test_speeches_api_suffixes_other_users_names(self):
        shared = Speech.objects.create(owner=self.other_user, name='bob speech', content='c', is_shared=True)
        shared.analyzer_users.add(self.user)

        response = self.client.get(reverse('speeches_api'))

        names = [s['name'] for s in response.json()['speeches']]
        self.assertIn('bob speech (bob)', names)

    def test_speeches_require_login(self):
        self.client.logout()

        response = self.client.get(reverse('speeches'))

        self.assertEqual(response.status_code, 302)

    def test_analyzer_page_exposes_upload_link_bases(self):
        response = self.client.get(reverse('log_analyzer'))

        self.assertEqual(
            response.context['upload_link_helper_base'],
            'http://testserver' + reverse('upload_log_for_helper', args=['alice']),
        )
        self.assertEqual(
            response.context['upload_link_general'],
            'http://testserver' + reverse('upload_log'),
        )
        self.assertContains(response, 'uploadLinkHelperBase')
        self.assertContains(response, 'uploadLinkGeneral')

    def test_speech_placeholders_are_stored_verbatim(self):
        """Substitution happens on insert in the browser; the DB keeps the tokens."""
        content = 'Hi {USERNAME}, upload via {UPLOADLINK_HELPER_PREFILLED} - {HELPERNAME}'
        self.client.post(reverse('speeches'), {
            'action': 'create', 'name': 'greeting', 'content': content,
        })

        speech = Speech.objects.get(name='greeting')
        self.assertEqual(speech.content, content)

    def test_analyzer_page_exposes_selected_speeches(self):
        speech = Speech.objects.create(owner=self.user, name='analyzer speech', content='hello there')
        speech.analyzer_users.add(self.user)
        Speech.objects.create(owner=self.user, name='unselected speech', content='not here')

        response = self.client.get(reverse('log_analyzer'))

        self.assertContains(response, 'analyzer speech')
        self.assertNotContains(response, 'unselected speech')
