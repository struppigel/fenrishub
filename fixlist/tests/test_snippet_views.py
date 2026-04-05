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
