from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import Fixlist


class SharedFixlistWarningTests(TestCase):
    """The warning on the public share page names the user the fixlist was made for,
    so someone who opened another person's link can tell before running it."""

    def setUp(self):
        self.owner = User.objects.create_user(username='helper', password='pw')

    def _share_page(self, username):
        fixlist = Fixlist.objects.create(owner=self.owner, username=username, content='Start::\nEnd::')
        return self.client.get(reverse('shared_fixlist', args=[fixlist.share_token]))

    def test_warning_names_the_intended_user(self):
        response = self._share_page('george')
        self.assertContains(response, 'This fixlist was made for <strong>george</strong>.', html=False)
        self.assertContains(response, 'Continue only if you are george.')

    def test_unknown_user_keeps_the_generic_warning(self):
        response = self._share_page('Unknown')
        self.assertNotContains(response, 'made for')
        self.assertContains(response, 'Continue only if this link was meant for you.')

    def test_username_is_escaped(self):
        response = self._share_page('<b>evil</b>')
        self.assertContains(response, 'made for <strong>&lt;b&gt;evil&lt;/b&gt;</strong>')
        self.assertNotContains(response, 'made for <strong><b>evil</b>')
