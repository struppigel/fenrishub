import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser, User
from django.core.cache import cache
from django.http import Http404, HttpResponse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase
from django.test import override_settings
from django.urls import reverse

from ..models import AccessLog, ClassificationRule, Fixlist, UploadedLog
from ..views import log_analyzer_view, shared_fixlist_view, view_fixlist


class SharingAndDownloadTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.factory = RequestFactory()
        self.fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Shareable",
            content="ioc-a\nioc-b",
            internal_note="Internal only",
        )

    def test_shared_view_creates_access_log_for_anonymous_access(self):
        request = self.factory.get(reverse("shared_fixlist", args=[self.fixlist.share_token]))
        request.user = AnonymousUser()

        with patch("fixlist.views.fixlists.render", return_value=HttpResponse("ok")) as mock_render:
            response = shared_fixlist_view(request, token=self.fixlist.share_token)

        rendered_context = mock_render.call_args.args[2]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(rendered_context["fixlist"].pk, self.fixlist.pk)
        self.assertFalse(rendered_context["is_owner"])
        self.assertEqual(AccessLog.objects.filter(fixlist=self.fixlist).count(), 1)

    def test_download_increments_counter_and_returns_attachment(self):
        response = self.client.get(reverse("download_fixlist", args=[self.fixlist.share_token]))

        self.fixlist.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertIn('attachment; filename="Fixlist.txt"', response["Content-Disposition"])
        self.assertEqual(response.content.decode("utf-8"), self.fixlist.content)
        self.assertEqual(self.fixlist.download_count, 1)
        self.assertEqual(AccessLog.objects.filter(fixlist=self.fixlist).count(), 1)

    def test_copy_api_returns_content_and_logs_access(self):
        response = self.client.post(reverse("copy_api", args=[self.fixlist.share_token]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"content": self.fixlist.content})
        self.assertEqual(AccessLog.objects.filter(fixlist=self.fixlist).count(), 1)

    def test_shared_view_marks_owner_in_context_when_logged_in(self):
        request = self.factory.get(reverse("shared_fixlist", args=[self.fixlist.share_token]))
        request.user = self.user

        with patch("fixlist.views.fixlists.render", return_value=HttpResponse("ok")) as mock_render:
            response = shared_fixlist_view(request, token=self.fixlist.share_token)

        rendered_context = mock_render.call_args.args[2]

        self.assertEqual(response.status_code, 200)
        self.assertTrue(rendered_context["is_owner"])
        self.assertFalse(rendered_context["preview_as_guest"])

    def test_shared_view_owner_guest_preview_sets_non_owner_context(self):
        request = self.factory.get(
            reverse("shared_fixlist", args=[self.fixlist.share_token]),
            {"preview": "guest"},
        )
        request.user = self.user

        with patch("fixlist.views.fixlists.render", return_value=HttpResponse("ok")) as mock_render:
            response = shared_fixlist_view(request, token=self.fixlist.share_token)

        rendered_context = mock_render.call_args.args[2]

        self.assertEqual(response.status_code, 200)
        self.assertTrue(rendered_context["preview_as_guest"])
        self.assertFalse(rendered_context["is_owner"])

    def test_shared_view_returns_404_for_anonymous_when_fixlist_disabled(self):
        self.fixlist.is_public = False
        self.fixlist.save(update_fields=["is_public"])

        request = self.factory.get(reverse("shared_fixlist", args=[self.fixlist.share_token]))
        request.user = AnonymousUser()

        with self.assertRaises(Http404):
            shared_fixlist_view(request, token=self.fixlist.share_token)

    def test_download_returns_404_for_anonymous_when_fixlist_disabled(self):
        self.fixlist.is_public = False
        self.fixlist.save(update_fields=["is_public"])

        response = self.client.get(reverse("download_fixlist", args=[self.fixlist.share_token]))
        self.assertEqual(response.status_code, 404)

    def test_copy_api_returns_404_for_anonymous_when_fixlist_disabled(self):
        self.fixlist.is_public = False
        self.fixlist.save(update_fields=["is_public"])

        response = self.client.post(reverse("copy_api", args=[self.fixlist.share_token]))
        self.assertEqual(response.status_code, 404)

    def test_shared_view_allows_other_logged_in_user_when_fixlist_disabled(self):
        self.fixlist.is_public = False
        self.fixlist.save(update_fields=["is_public"])
        User.objects.create_user(username="bob", password="password123")
        self.client.login(username="bob", password="password123")

        response = self.client.get(reverse("shared_fixlist", args=[self.fixlist.share_token]))

        self.assertEqual(response.status_code, 200)

    def test_download_allows_other_logged_in_user_when_fixlist_disabled(self):
        self.fixlist.is_public = False
        self.fixlist.save(update_fields=["is_public"])
        User.objects.create_user(username="bob", password="password123")
        self.client.login(username="bob", password="password123")

        response = self.client.get(reverse("download_fixlist", args=[self.fixlist.share_token]))

        self.assertEqual(response.status_code, 200)

    def test_copy_api_allows_other_logged_in_user_when_fixlist_disabled(self):
        self.fixlist.is_public = False
        self.fixlist.save(update_fields=["is_public"])
        User.objects.create_user(username="bob", password="password123")
        self.client.login(username="bob", password="password123")

        response = self.client.post(reverse("copy_api", args=[self.fixlist.share_token]))

        self.assertEqual(response.status_code, 200)


