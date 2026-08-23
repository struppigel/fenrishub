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
            forum_username="linked_user",
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

    def test_create_fixlist_derives_username_from_source_upload(self):
        upload = UploadedLog.objects.create(
            upload_id="derive-username",
            forum_username="derived_user",
            original_filename="FRST.txt",
            content="line-1",
        )

        response = self.client.post(
            reverse("create_fixlist"),
            {
                "content": "ioc-1\nioc-2",
                "source_upload_id": upload.upload_id,
            },
        )

        self.assertEqual(response.status_code, 302)
        created = Fixlist.objects.get(source_uploaded_log_id=upload.id)
        self.assertEqual(created.username, "derived_user")

    def test_create_fixlist_falls_back_to_unknown_username(self):
        response = self.client.post(
            reverse("create_fixlist"),
            {
                "content": "ioc-1\nioc-2",
            },
        )

        self.assertEqual(response.status_code, 302)
        created = Fixlist.objects.get(content="ioc-1\nioc-2")
        self.assertEqual(created.username, "Unknown")

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

    def test_update_fixlist_changes_response(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Before",
            content="old-content",
            response="old response",
        )

        self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {
                "action": "update",
                "username": "Before",
                "content": "old-content",
                "response": "  new response  ",
            },
        )

        fixlist.refresh_from_db()
        self.assertEqual(fixlist.response, "new response")

    def test_update_fixlist_preserves_response_when_field_absent(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Before",
            content="old-content",
            response="old response",
        )

        self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {
                "action": "update",
                "username": "Before",
                "content": "new-content",
            },
        )

        fixlist.refresh_from_db()
        self.assertEqual(fixlist.response, "old response")

    def test_update_fixlist_preserves_internal_note_absent_from_the_form(self):
        # The fixlist page no longer renders an internal-note field, so a save
        # from it must leave the stored note alone rather than blanking it.
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Noted",
            content="old-content",
            internal_note="keep this note",
        )

        self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {
                "action": "update",
                "username": "Noted",
                "content": "new-content",
                "response": "reply",
            },
        )

        fixlist.refresh_from_db()
        self.assertEqual(fixlist.internal_note, "keep this note")
        self.assertEqual(fixlist.content, "new-content")

    def test_update_fixlist_redirects_back_to_response_tab(self):
        fixlist = Fixlist.objects.create(owner=self.user, username="Tabbed", content="x")

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {
                "action": "update",
                "username": "Tabbed",
                "content": "x",
                "response": "reply text",
                "tab": "response",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            f'{reverse("view_fixlist", args=[fixlist.pk])}?tab=response',
        )

    def test_view_fixlist_renders_both_tabs(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Tabbed",
            content="fix-content",
            response="reply text",
        )

        response = self.client.get(reverse("view_fixlist", args=[fixlist.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["active_tab"], "content")
        self.assertContains(response, 'name="response"')
        self.assertContains(response, "reply text")
        self.assertContains(response, "fix-content")

    def test_view_fixlist_opens_response_tab_from_query(self):
        fixlist = Fixlist.objects.create(owner=self.user, username="Tabbed", content="x")

        response = self.client.get(
            reverse("view_fixlist", args=[fixlist.pk]), {"tab": "response"}
        )

        self.assertEqual(response.context["active_tab"], "response")

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
            forum_username="preview_user",
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
            forum_username="preview_user",
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
            forum_username="session_user",
            original_filename="FRST.txt",
            content="line-1",
        )

        api_response = self.client.get(reverse("uploaded_log_content_api", args=[upload.upload_id]))
        self.assertEqual(api_response.status_code, 200)

        response = self.client.get(reverse("create_fixlist"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="username"')
        self.assertContains(response, 'value="session_user"', html=False)

    def test_create_fixlist_updates_existing_when_fixlist_id_owned(self):
        upload = UploadedLog.objects.create(
            upload_id="edit-source",
            forum_username="edit_user",
            original_filename="FRST.txt",
            content="line-1",
        )
        fixlist = Fixlist.objects.create(
            owner=self.user,
            source_uploaded_log=upload,
            username="Keep Me",
            content="old-content",
            internal_note="keep-note",
        )

        response = self.client.post(
            reverse("create_fixlist"),
            {
                "content": "reanalyzed-content\nsecond-line",
                "source_upload_id": upload.upload_id,
                "fixlist_id": str(fixlist.pk),
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[fixlist.pk]))
        # No duplicate was created.
        self.assertEqual(Fixlist.objects.count(), 1)
        fixlist.refresh_from_db()
        self.assertEqual(fixlist.content, "reanalyzed-content\nsecond-line")
        self.assertEqual(fixlist.line_count, 2)
        # Content-only update preserves the other fields.
        self.assertEqual(fixlist.username, "Keep Me")
        self.assertEqual(fixlist.internal_note, "keep-note")
        self.assertEqual(fixlist.response, "")
        self.assertEqual(fixlist.source_uploaded_log_id, upload.id)

    def test_create_fixlist_persists_response(self):
        self.client.post(
            reverse("create_fixlist"),
            {
                "username": "With Response",
                "content": "ioc-1",
                "response": "  hello, run FRST please  ",
            },
        )

        created = Fixlist.objects.get(username="With Response")
        self.assertEqual(created.response, "hello, run FRST please")

    def test_create_fixlist_update_branch_replaces_response(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Keep Me",
            content="old-content",
            response="old response",
        )

        self.client.post(
            reverse("create_fixlist"),
            {
                "content": "new-content",
                "response": "new response",
                "fixlist_id": str(fixlist.pk),
            },
        )

        fixlist.refresh_from_db()
        self.assertEqual(fixlist.response, "new response")

    def test_create_fixlist_update_branch_clears_response_when_posted_empty(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Keep Me",
            content="old-content",
            response="old response",
        )

        self.client.post(
            reverse("create_fixlist"),
            {
                "content": "new-content",
                "response": "",
                "fixlist_id": str(fixlist.pk),
            },
        )

        fixlist.refresh_from_db()
        self.assertEqual(fixlist.response, "")

    def test_create_fixlist_update_branch_preserves_response_when_field_absent(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="Keep Me",
            content="old-content",
            response="old response",
        )

        self.client.post(
            reverse("create_fixlist"),
            {
                "content": "new-content",
                "fixlist_id": str(fixlist.pk),
            },
        )

        fixlist.refresh_from_db()
        self.assertEqual(fixlist.response, "old response")

    def test_create_fixlist_ignores_other_users_fixlist_id(self):
        other = User.objects.create_user(username="mallory", password="password123")
        other_fixlist = Fixlist.objects.create(
            owner=other,
            username="Not Yours",
            content="mallory-content",
        )

        response = self.client.post(
            reverse("create_fixlist"),
            {
                "username": "New From Alice",
                "content": "alice-content",
                "fixlist_id": str(other_fixlist.pk),
            },
        )

        self.assertEqual(response.status_code, 302)
        # Mallory's fixlist is untouched...
        other_fixlist.refresh_from_db()
        self.assertEqual(other_fixlist.content, "mallory-content")
        # ...and a brand-new fixlist is created for alice instead.
        created = Fixlist.objects.get(username="New From Alice")
        self.assertEqual(created.owner, self.user)
        self.assertEqual(created.content, "alice-content")

    def test_create_fixlist_ignores_trashed_fixlist_id(self):
        from django.utils import timezone

        trashed = Fixlist.objects.create(
            owner=self.user,
            username="Trashed",
            content="trashed-content",
            deleted_at=timezone.now(),
        )

        response = self.client.post(
            reverse("create_fixlist"),
            {
                "username": "New After Trash",
                "content": "fresh-content",
                "fixlist_id": str(trashed.pk),
            },
        )

        self.assertEqual(response.status_code, 302)
        trashed.refresh_from_db()
        self.assertEqual(trashed.content, "trashed-content")
        created = Fixlist.objects.get(username="New After Trash")
        self.assertNotEqual(created.pk, trashed.pk)
        self.assertEqual(created.content, "fresh-content")

    def test_log_analyzer_view_loads_fixlist_for_editing(self):
        upload = UploadedLog.objects.create(
            upload_id="analyzer-source",
            forum_username="analyzer_user",
            original_filename="FRST.txt",
            content="line-1",
        )
        fixlist = Fixlist.objects.create(
            owner=self.user,
            source_uploaded_log=upload,
            username="Editable",
            content="fixlist-body-line",
            response="stored reply text",
        )

        response = self.client.get(reverse("log_analyzer"), {"fixlist_id": str(fixlist.pk)})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["initial_fixlist_id"], str(fixlist.pk))
        self.assertEqual(response.context["initial_selected_lines"], "fixlist-body-line")
        # Seeding the response panel is what stops the next save from wiping it.
        self.assertEqual(response.context["initial_response_text"], "stored reply text")
        self.assertContains(response, "stored reply text")
        # Source log auto-loads even without an explicit upload_id.
        self.assertEqual(response.context["initial_upload_id"], upload.upload_id)

    def test_log_analyzer_view_ignores_non_owned_fixlist_id(self):
        other = User.objects.create_user(username="mallory", password="password123")
        other_fixlist = Fixlist.objects.create(
            owner=other,
            username="Not Yours",
            content="mallory-body",
        )

        response = self.client.get(reverse("log_analyzer"), {"fixlist_id": str(other_fixlist.pk)})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["initial_fixlist_id"], "")
        # Falls back to the default fixlist template rather than another user's content.
        self.assertNotEqual(response.context["initial_selected_lines"], "mallory-body")
        self.assertEqual(
            response.context["initial_selected_lines"],
            response.context["fixlist_template"],
        )

    def test_log_analyzer_view_response_is_empty_without_fixlist_id(self):
        response = self.client.get(reverse("log_analyzer"))

        self.assertEqual(response.status_code, 200)
        # The fixlist panel falls back to a template; the response does not.
        self.assertEqual(response.context["initial_response_text"], "")
        self.assertNotEqual(response.context["fixlist_template"], "")

    def test_view_fixlist_shows_reanalyze_link_when_source_present(self):
        upload = UploadedLog.objects.create(
            upload_id="reanalyze-source",
            forum_username="reanalyze_user",
            original_filename="FRST.txt",
            content="line-1",
        )
        fixlist = Fixlist.objects.create(
            owner=self.user,
            source_uploaded_log=upload,
            username="Linkable",
            content="payload",
        )

        response = self.client.get(reverse("view_fixlist", args=[fixlist.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "reanalyze &amp; edit")
        self.assertContains(response, f"upload_id={upload.upload_id}")
        self.assertContains(response, f"fixlist_id={fixlist.pk}")

    def test_view_fixlist_hides_reanalyze_link_without_source(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            username="No Source",
            content="payload",
        )

        response = self.client.get(reverse("view_fixlist", args=[fixlist.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "reanalyze &amp; edit")


