import json
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser, User
from django.http import HttpResponse
from django.test import RequestFactory, TestCase
from django.urls import reverse

from ..models import AccessLog, ClassificationRule, Fixlist
from ..views import shared_fixlist_view, view_fixlist


class FixlistCrudViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.client.login(username="alice", password="password123")

    def test_create_fixlist_creates_record_and_redirects(self):
        response = self.client.post(
            reverse("create_fixlist"),
            {
                "title": "Created Via Test",
                "content": "ioc-1\nioc-2",
                "internal_note": "internal context",
            },
        )

        created = Fixlist.objects.get(title="Created Via Test")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[created.pk]))
        self.assertEqual(created.owner, self.user)
        self.assertEqual(created.internal_note, "internal context")

    def test_create_fixlist_ignores_rule_persistence_payload(self):
        pending_changes = [
            {
                "id": "1",
                "line": "MALICIOUS-LINE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_MALWARE,
                "order": 1,
            }
        ]

        response = self.client.post(
            reverse("create_fixlist"),
            {
                "title": "Fixlist Ignores Rule Persist Payload",
                "content": "line-a",
                "internal_note": "",
                "persist_rules": "1",
                "pending_rule_changes_json": json.dumps(pending_changes),
                "selected_rule_change_ids_json": json.dumps(["1"]),
            },
        )

        created = Fixlist.objects.get(title="Fixlist Ignores Rule Persist Payload")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[created.pk]))
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_update_fixlist_changes_content(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            title="Before",
            content="old-content",
            internal_note="old-note",
        )

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {
                "action": "update",
                "title": "After",
                "content": "new-content",
                "internal_note": "new-note",
            },
        )

        fixlist.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[fixlist.pk]))
        self.assertEqual(fixlist.title, "After")
        self.assertEqual(fixlist.content, "new-content")
        self.assertEqual(fixlist.internal_note, "new-note")

    def test_delete_fixlist_removes_record(self):
        fixlist = Fixlist.objects.create(owner=self.user, title="Delete Me", content="x")

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {"action": "delete"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("dashboard"))
        self.assertFalse(Fixlist.objects.filter(pk=fixlist.pk).exists())

    def test_view_fixlist_context_includes_guest_preview_url(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            title="Previewable",
            content="payload",
        )
        request = RequestFactory().get(reverse("view_fixlist", args=[fixlist.pk]))
        request.user = self.user

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
            response = view_fixlist(request, pk=fixlist.pk)

        rendered_context = mock_render.call_args.args[2]
        share_url = rendered_context["share_url"]

        self.assertEqual(response.status_code, 200)
        self.assertIn(f"/share/{fixlist.share_token}/", share_url)
        self.assertEqual(
            rendered_context["guest_preview_url"],
            f"{share_url}?preview=guest",
        )


class SharingAndDownloadTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.factory = RequestFactory()
        self.fixlist = Fixlist.objects.create(
            owner=self.user,
            title="Shareable",
            content="ioc-a\nioc-b",
            internal_note="Internal only",
        )

    def test_shared_view_creates_access_log_for_anonymous_access(self):
        request = self.factory.get(reverse("shared_fixlist", args=[self.fixlist.share_token]))
        request.user = AnonymousUser()

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
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

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
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

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
            response = shared_fixlist_view(request, token=self.fixlist.share_token)

        rendered_context = mock_render.call_args.args[2]

        self.assertEqual(response.status_code, 200)
        self.assertTrue(rendered_context["preview_as_guest"])
        self.assertFalse(rendered_context["is_owner"])

