from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import FixlistSnippet


class SnippetViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.other_user = User.objects.create_user(username='bob', password='password123')
        self.client.login(username='alice', password='password123')

    def test_own_snippets_shown_by_default(self):
        own = FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='own content')
        other_shared = FixlistSnippet.objects.create(owner=self.other_user, name='bob snippet', content='shared', is_shared=True)

        response = self.client.get(reverse('snippets'))

        self.assertContains(response, 'my snippet')
        self.assertNotContains(response, 'bob snippet')

    def test_show_all_includes_shared_snippets(self):
        own = FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='own content')
        other_shared = FixlistSnippet.objects.create(owner=self.other_user, name='bob snippet', content='shared', is_shared=True)
        other_private = FixlistSnippet.objects.create(owner=self.other_user, name='bob private', content='private', is_shared=False)

        response = self.client.get(reverse('snippets'), {'show_all': '1'})

        self.assertContains(response, 'my snippet')
        self.assertContains(response, 'bob snippet')
        self.assertNotContains(response, 'bob private')

    def test_search_filters_by_name(self):
        FixlistSnippet.objects.create(owner=self.user, name='registry fix', content='content a')
        FixlistSnippet.objects.create(owner=self.user, name='browser reset', content='content b')

        response = self.client.get(reverse('snippets'), {'q': 'registry'})

        self.assertContains(response, 'registry fix')
        self.assertNotContains(response, 'browser reset')

    def test_search_filters_by_content(self):
        FixlistSnippet.objects.create(owner=self.user, name='snippet a', content='delete HKLM key')
        FixlistSnippet.objects.create(owner=self.user, name='snippet b', content='reset chrome')

        response = self.client.get(reverse('snippets'), {'q': 'HKLM'})

        self.assertContains(response, 'snippet a')
        self.assertNotContains(response, 'snippet b')

    def test_search_filters_by_owner_in_show_all(self):
        FixlistSnippet.objects.create(owner=self.user, name='alice snippet', content='x')
        FixlistSnippet.objects.create(owner=self.other_user, name='bob snippet', content='y', is_shared=True)

        response = self.client.get(reverse('snippets'), {'q': 'bob', 'show_all': '1'})

        self.assertContains(response, 'bob snippet')
        self.assertNotContains(response, 'alice snippet')

    def test_toggle_analyzer_adds_own_snippet(self):
        snippet = FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='c')
        self.assertFalse(snippet.analyzer_users.filter(pk=self.user.pk).exists())

        self.client.post(reverse('snippets'), {'action': 'toggle_analyzer', 'pk': snippet.pk})

        self.assertTrue(snippet.analyzer_users.filter(pk=self.user.pk).exists())

    def test_toggle_analyzer_removes_own_snippet(self):
        snippet = FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='c')
        snippet.analyzer_users.add(self.user)

        self.client.post(reverse('snippets'), {'action': 'toggle_analyzer', 'pk': snippet.pk})

        self.assertFalse(snippet.analyzer_users.filter(pk=self.user.pk).exists())

    def test_toggle_analyzer_adds_shared_snippet_from_other_user(self):
        snippet = FixlistSnippet.objects.create(owner=self.other_user, name='bob shared', content='c', is_shared=True)

        self.client.post(reverse('snippets'), {'action': 'toggle_analyzer', 'pk': snippet.pk})

        self.assertTrue(snippet.analyzer_users.filter(pk=self.user.pk).exists())

    def test_toggle_analyzer_rejects_private_snippet_from_other_user(self):
        snippet = FixlistSnippet.objects.create(owner=self.other_user, name='bob private', content='c', is_shared=False)

        response = self.client.post(reverse('snippets'), {'action': 'toggle_analyzer', 'pk': snippet.pk})

        self.assertEqual(response.status_code, 404)
        self.assertFalse(snippet.analyzer_users.filter(pk=self.user.pk).exists())

    def test_analyzer_snippet_ids_in_context(self):
        snippet = FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='c')
        snippet.analyzer_users.add(self.user)

        response = self.client.get(reverse('snippets'))

        self.assertIn(snippet.pk, response.context['analyzer_snippet_ids'])

    def test_create_snippet_with_category(self):
        self.client.post(reverse('snippets'), {
            'action': 'create', 'name': 'cat snippet',
            'content': 'c', 'category': 'Cleanup',
        })
        snippet = FixlistSnippet.objects.get(name='cat snippet')
        self.assertEqual(snippet.category, 'Cleanup')

    def test_create_snippet_defaults_to_generic_category(self):
        self.client.post(reverse('snippets'), {
            'action': 'create', 'name': 'default cat',
            'content': 'c',
        })
        snippet = FixlistSnippet.objects.get(name='default cat')
        self.assertEqual(snippet.category, 'generic')

    def test_edit_snippet_changes_category(self):
        snippet = FixlistSnippet.objects.create(
            owner=self.user, name='s', content='c', category='generic',
        )
        self.client.post(reverse('snippets'), {
            'action': 'edit', 'pk': snippet.pk,
            'name': 's', 'content': 'c', 'category': 'Registry',
        })
        snippet.refresh_from_db()
        self.assertEqual(snippet.category, 'Registry')

    def test_edit_snippet_blank_category_defaults_to_generic(self):
        snippet = FixlistSnippet.objects.create(
            owner=self.user, name='s', content='c', category='Old',
        )
        self.client.post(reverse('snippets'), {
            'action': 'edit', 'pk': snippet.pk,
            'name': 's', 'content': 'c', 'category': '',
        })
        snippet.refresh_from_db()
        self.assertEqual(snippet.category, 'generic')

    def test_filter_by_category(self):
        FixlistSnippet.objects.create(owner=self.user, name='reg snippet', content='c', category='Registry')
        FixlistSnippet.objects.create(owner=self.user, name='gen snippet', content='c', category='generic')

        response = self.client.get(reverse('snippets'), {'category': 'Registry'})

        self.assertContains(response, 'reg snippet')
        self.assertNotContains(response, 'gen snippet')

    def test_categories_in_context(self):
        FixlistSnippet.objects.create(owner=self.user, name='a', content='c', category='Alpha')
        FixlistSnippet.objects.create(owner=self.user, name='b', content='c', category='Beta')

        response = self.client.get(reverse('snippets'))

        self.assertEqual(response.context['categories'], ['Alpha', 'Beta'])

    def test_category_shown_in_snippet_list(self):
        FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='c', category='Cleanup')

        response = self.client.get(reverse('snippets'))

        self.assertContains(response, '[Cleanup]')

    def test_snippets_api_returns_only_selected_snippets(self):
        selected = FixlistSnippet.objects.create(owner=self.user, name='selected', content='c')
        selected.analyzer_users.add(self.user)
        not_selected = FixlistSnippet.objects.create(owner=self.user, name='not selected', content='c')

        response = self.client.get(reverse('snippets_api'))
        data = response.json()

        names = [s['name'] for s in data['snippets']]
        self.assertIn('selected', names)
        self.assertNotIn('not selected', names)
