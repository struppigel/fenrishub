from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse


class LegalPagesTests(TestCase):
    def test_about_and_privacy_are_public(self):
        for name in ("about", "privacy"):
            with self.subTest(page=name):
                response = self.client.get(reverse(name))
                self.assertEqual(response.status_code, 200)

    def test_footer_links_both_pages_for_anonymous_visitors(self):
        response = self.client.get(reverse("home"))

        self.assertContains(response, f'href="{reverse("about")}"')
        self.assertContains(response, f'href="{reverse("privacy")}"')

    def test_footer_links_both_pages_for_logged_in_helpers(self):
        User.objects.create_user(username="alice", password="password123")
        self.client.login(username="alice", password="password123")

        response = self.client.get(reverse("dashboard"))

        self.assertContains(response, f'href="{reverse("about")}"')
        self.assertContains(response, f'href="{reverse("privacy")}"')
