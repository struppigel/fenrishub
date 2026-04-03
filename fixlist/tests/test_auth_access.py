from unittest.mock import patch

from django.contrib.auth.models import User
from django.http import Http404, HttpResponse
from django.test import RequestFactory, TestCase
from django.urls import reverse

from ..models import Fixlist
from ..views import change_password_view, dashboard_view, view_fixlist


class AuthenticationAndAccessTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.other_user = User.objects.create_user(username="bob", password="password123")
        self.factory = RequestFactory()

        self.fixlist = Fixlist.objects.create(
            owner=self.user,
            title="Owner Fixlist",
            content="ioc-a\nioc-b",
            internal_note="Sensitive internal note",
        )

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_log_analyzer_requires_login(self):
        response = self.client.get(reverse("log_analyzer"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_change_password_requires_login(self):
        response = self.client.get(reverse("change_password"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_change_password_updates_credentials_without_email(self):
        self.user.email = ""
        self.user.save(update_fields=["email"])

        self.assertTrue(self.client.login(username="alice", password="password123"))
        response = self.client.post(
            reverse("change_password"),
            {
                "old_password": "password123",
                "new_password1": "new-password456",
                "new_password2": "new-password456",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("change_password"))

        self.client.logout()
        self.assertFalse(self.client.login(username="alice", password="password123"))
        self.assertTrue(self.client.login(username="alice", password="new-password456"))

    def test_change_password_form_exposes_password_fields_only(self):
        request = self.factory.get(reverse("change_password"))
        request.user = self.user

        with patch("fixlist.views.auth.render", return_value=HttpResponse("ok")) as mock_render:
            response = change_password_view(request)

        rendered_context = mock_render.call_args.args[2]
        form = rendered_context["form"]

        self.assertEqual(response.status_code, 200)
        self.assertIn("old_password", form.fields)
        self.assertIn("new_password1", form.fields)
        self.assertIn("new_password2", form.fields)
        self.assertNotIn("email", form.fields)

    def test_dashboard_only_shows_user_fixlists(self):
        Fixlist.objects.create(owner=self.other_user, title="Other", content="secret")
        request = self.factory.get(reverse("dashboard"))
        request.user = self.user

        with patch("fixlist.views.auth.render", return_value=HttpResponse("ok")) as mock_render:
            response = dashboard_view(request)

        rendered_context = mock_render.call_args.args[2]
        titles = {item.title for item in rendered_context["fixlists"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("Owner Fixlist", titles)
        self.assertNotIn("Other", titles)

    def test_user_cannot_access_other_users_fixlist_edit_page(self):
        request = self.factory.get(reverse("view_fixlist", args=[self.fixlist.pk]))
        request.user = self.other_user

        with self.assertRaises(Http404):
            view_fixlist(request, pk=self.fixlist.pk)

