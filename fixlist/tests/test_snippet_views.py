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

    def test_shared_by_includes_shared_snippets(self):
        own = FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='own content')
        other_shared = FixlistSnippet.objects.create(owner=self.other_user, name='bob snippet', content='shared', is_shared=True)
        other_private = FixlistSnippet.objects.create(owner=self.other_user, name='bob private', content='private', is_shared=False)

        response = self.client.get(reverse('snippets'), {'shared_by': 'bob'})

        self.assertContains(response, 'my snippet')
        self.assertContains(response, 'bob snippet')
        self.assertNotContains(response, 'bob private')

    def test_shared_by_selector_shown_when_nobody_shares(self):
        FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='own content')

        response = self.client.get(reverse('snippets'))

        self.assertContains(response, 'name="shared_by"')
        self.assertContains(response, 'no shared snippets yet')

    def test_shared_by_selector_lists_sharing_users(self):
        FixlistSnippet.objects.create(owner=self.other_user, name='bob snippet', content='shared', is_shared=True)

        response = self.client.get(reverse('snippets'))

        self.assertContains(response, 'name="shared_by"')
        self.assertNotContains(response, 'no shared snippets yet')
        self.assertContains(response, '+ bob')

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

    def test_search_filters_by_owner_with_shared_by(self):
        FixlistSnippet.objects.create(owner=self.user, name='alice snippet', content='x')
        FixlistSnippet.objects.create(owner=self.other_user, name='bob snippet', content='y', is_shared=True)

        response = self.client.get(reverse('snippets'), {'q': 'bob', 'shared_by': 'bob'})

        self.assertContains(response, 'bob snippet')
        self.assertNotContains(response, 'alice snippet')

    def test_toggle_analyzer_adds_own_snippet(self):
        snippet = FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='c')
        self.assertFalse(snippet.analyzer_users.filter(pk=self.user.pk).exists())

        response = self.client.post(reverse('snippets_toggle_analyzer_api'), {'pk': snippet.pk})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['selected'])
        self.assertTrue(snippet.analyzer_users.filter(pk=self.user.pk).exists())

    def test_toggle_analyzer_removes_own_snippet(self):
        snippet = FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='c')
        snippet.analyzer_users.add(self.user)

        response = self.client.post(reverse('snippets_toggle_analyzer_api'), {'pk': snippet.pk})

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['selected'])
        self.assertFalse(snippet.analyzer_users.filter(pk=self.user.pk).exists())

    def test_toggle_analyzer_adds_shared_snippet_from_other_user(self):
        snippet = FixlistSnippet.objects.create(owner=self.other_user, name='bob shared', content='c', is_shared=True)

        response = self.client.post(reverse('snippets_toggle_analyzer_api'), {'pk': snippet.pk})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['selected'])
        self.assertTrue(snippet.analyzer_users.filter(pk=self.user.pk).exists())

    def test_toggle_analyzer_rejects_private_snippet_from_other_user(self):
        snippet = FixlistSnippet.objects.create(owner=self.other_user, name='bob private', content='c', is_shared=False)

        response = self.client.post(reverse('snippets_toggle_analyzer_api'), {'pk': snippet.pk})

        self.assertEqual(response.status_code, 404)
        self.assertFalse(snippet.analyzer_users.filter(pk=self.user.pk).exists())

    def test_analyzer_snippet_ids_in_context(self):
        snippet = FixlistSnippet.objects.create(owner=self.user, name='my snippet', content='c')
        snippet.analyzer_users.add(self.user)

        response = self.client.get(reverse('snippets'))

        self.assertIn(snippet.pk, response.context['analyzer_snippet_ids'])

    def test_create_snippet_with_category(self):
        self.client.post(reverse('add_snippet'), {
            'name': 'cat snippet', 'content': 'c', 'category': 'Cleanup',
        })
        snippet = FixlistSnippet.objects.get(name='cat snippet')
        self.assertEqual(snippet.category, 'Cleanup')

    def test_create_snippet_defaults_to_generic_category(self):
        self.client.post(reverse('add_snippet'), {
            'name': 'default cat', 'content': 'c',
        })
        snippet = FixlistSnippet.objects.get(name='default cat')
        self.assertEqual(snippet.category, 'generic')

    def test_create_snippet_selects_it_for_analyzer(self):
        self.client.post(reverse('add_snippet'), {
            'name': 'new', 'content': 'c', 'is_shared': 'on',
        })
        snippet = FixlistSnippet.objects.get(name='new')
        self.assertTrue(snippet.is_shared)
        self.assertTrue(snippet.analyzer_users.filter(pk=self.user.pk).exists())

    def test_edit_snippet_changes_category(self):
        snippet = FixlistSnippet.objects.create(
            owner=self.user, name='s', content='c', category='generic',
        )
        self.client.post(reverse('edit_snippet', args=[snippet.pk]), {
            'name': 's', 'content': 'c', 'category': 'Registry',
        })
        snippet.refresh_from_db()
        self.assertEqual(snippet.category, 'Registry')

    def test_edit_snippet_blank_category_defaults_to_generic(self):
        snippet = FixlistSnippet.objects.create(
            owner=self.user, name='s', content='c', category='Old',
        )
        self.client.post(reverse('edit_snippet', args=[snippet.pk]), {
            'name': 's', 'content': 'c', 'category': '',
        })
        snippet.refresh_from_db()
        self.assertEqual(snippet.category, 'generic')

    def test_add_page_renders_editor(self):
        response = self.client.get(reverse('add_snippet'))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'snippet_editor.html')
        self.assertFalse(response.context['editing'])

    def test_edit_page_prefills_snippet(self):
        snippet = FixlistSnippet.objects.create(
            owner=self.user, name='prefilled', content='CloseProcesses:', category='Cleanup',
        )

        response = self.client.get(reverse('edit_snippet', args=[snippet.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['editing'])
        self.assertContains(response, 'value="prefilled"')
        self.assertContains(response, 'CloseProcesses:</textarea>')

    def test_edit_other_users_snippet_returns_404(self):
        snippet = FixlistSnippet.objects.create(
            owner=self.other_user, name='bob shared', content='c', is_shared=True,
        )

        get_response = self.client.get(reverse('edit_snippet', args=[snippet.pk]))
        post_response = self.client.post(reverse('edit_snippet', args=[snippet.pk]), {
            'name': 'hijacked', 'content': 'x',
        })

        self.assertEqual(get_response.status_code, 404)
        self.assertEqual(post_response.status_code, 404)
        snippet.refresh_from_db()
        self.assertEqual(snippet.name, 'bob shared')

    def test_create_missing_content_rerenders_with_input(self):
        response = self.client.post(reverse('add_snippet'), {
            'name': 'keep my name', 'content': '', 'category': 'Registry',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Snippet content is required.')
        self.assertContains(response, 'value="keep my name"')
        self.assertFalse(FixlistSnippet.objects.filter(name='keep my name').exists())

    def test_create_duplicate_name_keeps_submitted_content(self):
        FixlistSnippet.objects.create(owner=self.user, name='dup', content='old')

        response = self.client.post(reverse('add_snippet'), {
            'name': 'dup', 'content': 'long content worth keeping',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'A snippet named &quot;dup&quot; already exists.')
        self.assertContains(response, 'long content worth keeping</textarea>')
        self.assertEqual(FixlistSnippet.objects.filter(name='dup').count(), 1)

    def test_edit_duplicate_name_is_rejected(self):
        FixlistSnippet.objects.create(owner=self.user, name='taken', content='c')
        snippet = FixlistSnippet.objects.create(owner=self.user, name='mine', content='c')

        response = self.client.post(reverse('edit_snippet', args=[snippet.pk]), {
            'name': 'taken', 'content': 'edited content',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'edited content</textarea>')
        snippet.refresh_from_db()
        self.assertEqual(snippet.name, 'mine')

    def test_save_redirects_to_list_with_return_q(self):
        snippet = FixlistSnippet.objects.create(owner=self.user, name='s', content='c')

        response = self.client.post(reverse('edit_snippet', args=[snippet.pk]), {
            'name': 's', 'content': 'c2', 'return_q': 'category=Registry&q=hklm',
        })

        self.assertRedirects(
            response, reverse('snippets') + '?category=Registry&q=hklm',
            fetch_redirect_response=False,
        )

    def test_hostile_return_q_falls_back_to_list(self):
        response = self.client.post(reverse('add_snippet'), {
            'name': 'n', 'content': 'c', 'return_q': '//evil.com',
        })

        self.assertRedirects(response, reverse('snippets'), fetch_redirect_response=False)

    def test_list_links_to_editor_pages(self):
        snippet = FixlistSnippet.objects.create(owner=self.user, name='s', content='c')

        response = self.client.get(reverse('snippets'), {'q': 's'})

        self.assertContains(response, reverse('add_snippet') + '?return_q=q%3Ds')
        self.assertContains(response, reverse('edit_snippet', args=[snippet.pk]) + '?return_q=q%3Ds')

    def test_delete_keeps_list_filters(self):
        snippet = FixlistSnippet.objects.create(owner=self.user, name='s', content='c')

        response = self.client.post(reverse('snippets'), {
            'action': 'delete', 'pk': snippet.pk, 'return_q': 'q=x',
        })

        self.assertRedirects(response, reverse('snippets') + '?q=x', fetch_redirect_response=False)
        self.assertFalse(FixlistSnippet.objects.filter(pk=snippet.pk).exists())

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
