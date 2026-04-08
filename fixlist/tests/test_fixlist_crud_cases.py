import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser, User
from django.core.cache import cache
from django.http import HttpResponse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase
from django.test import override_settings
from django.urls import reverse

from ..models import AccessLog, ClassificationRule, Fixlist, UploadedLog, UserProfile
from ..views.auth import DEFAULT_FRST_FIX_MESSAGE_TEMPLATE
from ..views import log_analyzer_view, shared_fixlist_view, view_fixlist


class FixlistCrudViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.client.login(username="alice", password="password123")

    def test_create_fixlist_creates_record_and_redirects(self):
        response = self.client.post(
            reverse("create_fixlist"),
            {
                "username": "Created Via Test",
                "content": "ioc-1\nioc-2",
                "internal_note": "internal context",
            },
        )

        created = Fixlist.objects.get(username="Created Via Test")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[created.pk]))
        self.assertEqual(created.owner, self.user)
        self.assertEqual(created.internal_note, "internal context")

    def test_create_fixlist_links_source_upload_when_present(self):
        upload = UploadedLog.objects.create(
            upload_id="linked-log",
            reddit_username="linked_user",
            original_filename="FRST.txt",
            content="line-1",
        )

        response = self.client.post(
            reverse("create_fixlist"),
            {
                "username": "Created With Source",
                "content": "ioc-1\nioc-2",
                "internal_note": "",
                "source_upload_id": upload.upload_id,
            },
        )

        created = Fixlist.objects.get(username="Created With Source")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(created.source_uploaded_log_id, upload.id)

    def test_create_fixlist_ignores_unknown_source_upload_id(self):
        response = self.client.post(
            reverse("create_fixlist"),
            {
                "username": "Created Without Source",
                "content": "ioc-1\nioc-2",
                "internal_note": "",
                "source_upload_id": "does-not-exist",
            },
        )

        created = Fixlist.objects.get(username="Created Without Source")
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(created.source_uploaded_log_id)

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
                "username": "Fixlist Ignores Rule Persist Payload",
                "content": "line-a",
                "internal_note": "",
                "persist_rules": "1",
                "pending_rule_changes_json": json.dumps(pending_changes),
                "selected_rule_change_ids_json": json.dumps(["1"]),
            },
        )

        created = Fixlist.objects.get(username="Fixlist Ignores Rule Persist Payload")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[created.pk]))
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_update_fixlist_changes_content(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Before",
            content="old-content",
            internal_note="old-note",
        )

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {
                "action": "update",
                "username": "After",
                "content": "new-content",
                "internal_note": "new-note",
            },
        )

        fixlist.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[fixlist.pk]))
        self.assertEqual(fixlist.username, "After")
        self.assertEqual(fixlist.content, "new-content")
        self.assertEqual(fixlist.internal_note, "new-note")

    def test_delete_fixlist_moves_to_trash(self):
        fixlist = Fixlist.objects.create(owner=self.user, username="Delete Me", content="x")

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {"action": "delete"},
        )

        fixlist.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("dashboard"))
        self.assertIsNotNone(fixlist.deleted_at)
        self.assertTrue(Fixlist.objects.filter(pk=fixlist.pk).exists())

    def test_disable_public_keeps_fixlist_active(self):
        fixlist = Fixlist.objects.create(owner=self.user, username="Disable Me", content="x")

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {"action": "disable_public"},
        )

        fixlist.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[fixlist.pk]))
        self.assertFalse(fixlist.is_public)
        self.assertIsNone(fixlist.deleted_at)

    def test_enable_public_reopens_sharing(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Enable Me",
            content="x",
            is_public=False,
        )

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {"action": "enable_public"},
        )

        fixlist.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[fixlist.pk]))
        self.assertTrue(fixlist.is_public)

    def test_disable_public_from_dashboard_redirects_to_dashboard(self):
        fixlist = Fixlist.objects.create(owner=self.user, username="Disable Dashboard", content="x")

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {"action": "disable_public", "next": "dashboard"},
        )

        fixlist.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("dashboard"))
        self.assertFalse(fixlist.is_public)

    def test_view_fixlist_context_includes_guest_preview_url(self):
        upload = UploadedLog.objects.create(
            upload_id="preview-source",
            reddit_username="preview_user",
            original_filename="FRST.txt",
            content="Running from C:\\Users\\George\\Desktop\\FRST64.exe\nline-1",
        )
        fixlist = Fixlist.objects.create(
            owner=self.user,
            source_uploaded_log=upload,
            username="Previewable",
            content="payload",
        )
        request = RequestFactory().get(reverse("view_fixlist", args=[fixlist.pk]))
        request.user = self.user

        with patch("fixlist.views.fixlists.render", return_value=HttpResponse("ok")) as mock_render:
            response = view_fixlist(request, pk=fixlist.pk)

        rendered_context = mock_render.call_args.args[2]
        share_url = rendered_context["share_url"]

        self.assertEqual(response.status_code, 200)
        self.assertIn(f"/share/{fixlist.share_token}/", share_url)
        self.assertEqual(
            rendered_context["guest_preview_url"],
            f"{share_url}?preview=guest",
        )
        self.assertEqual(rendered_context["source_uploaded_log"].upload_id, "preview-source")
        self.assertEqual(rendered_context["frst_run_path"], "C:\\Users\\George\\Desktop")

    def test_view_fixlist_context_uses_empty_frst_run_path_when_header_missing(self):
        upload = UploadedLog.objects.create(
            upload_id="preview-no-path",
            reddit_username="preview_user",
            original_filename="FRST.txt",
            content="line-1",
        )
        fixlist = Fixlist.objects.create(
            owner=self.user,
            source_uploaded_log=upload,
            username="Previewable",
            content="payload",
        )
        request = RequestFactory().get(reverse("view_fixlist", args=[fixlist.pk]))
        request.user = self.user

        with patch("fixlist.views.fixlists.render", return_value=HttpResponse("ok")) as mock_render:
            view_fixlist(request, pk=fixlist.pk)

        rendered_context = mock_render.call_args.args[2]
        self.assertEqual(rendered_context["frst_run_path"], "")

    def test_view_fixlist_context_uses_default_frst_fix_message_when_unset(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Previewable",
            content="payload",
        )
        request = RequestFactory().get(reverse("view_fixlist", args=[fixlist.pk]))
        request.user = self.user

        with patch("fixlist.views.fixlists.render", return_value=HttpResponse("ok")) as mock_render:
            response = view_fixlist(request, pk=fixlist.pk)

        rendered_context = mock_render.call_args.args[2]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            rendered_context["frst_fix_message_template"],
            DEFAULT_FRST_FIX_MESSAGE_TEMPLATE,
        )

    def test_view_fixlist_context_uses_custom_profile_frst_fix_message(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Previewable",
            content="payload",
        )
        UserProfile.objects.create(user=self.user, frst_fix_message="custom {FIXLISTLINK}")
        request = RequestFactory().get(reverse("view_fixlist", args=[fixlist.pk]))
        request.user = self.user

        with patch("fixlist.views.fixlists.render", return_value=HttpResponse("ok")) as mock_render:
            response = view_fixlist(request, pk=fixlist.pk)

        rendered_context = mock_render.call_args.args[2]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(rendered_context["frst_fix_message_template"], "custom {FIXLISTLINK}")

    def test_create_fixlist_prefills_username_from_last_loaded_upload_session(self):
        upload = UploadedLog.objects.create(
            upload_id="amber-raven",
            reddit_username="session_user",
            original_filename="FRST.txt",
            content="line-1",
        )

        api_response = self.client.get(reverse("uploaded_log_content_api", args=[upload.upload_id]))
        self.assertEqual(api_response.status_code, 200)

        response = self.client.get(reverse("create_fixlist"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="username"')
        self.assertContains(response, 'value="session_user"', html=False)


