from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpResponse
from django.test import RequestFactory, TestCase
from django.urls import reverse

from .models import AccessLog, ClassificationRule, Fixlist
from .views import dashboard_view, shared_fixlist_view, view_fixlist


class FixlistModelTests(TestCase):
    def test_share_token_generated_on_create(self):
        user = User.objects.create_user(username="alice", password="password123")

        fixlist = Fixlist.objects.create(
            owner=user,
            title="Initial",
            content="line1",
        )

        self.assertEqual(len(fixlist.share_token), 32)
        self.assertTrue(fixlist.share_token.isalnum())


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

    def test_dashboard_only_shows_user_fixlists(self):
        Fixlist.objects.create(owner=self.other_user, title="Other", content="secret")
        request = self.factory.get(reverse("dashboard"))
        request.user = self.user

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
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


class TemplateMarkupTests(TestCase):
    @staticmethod
    def _read_template(template_name):
        project_root = Path(__file__).resolve().parent.parent
        template_path = project_root / "templates" / template_name
        return template_path.read_text(encoding="utf-8")

    def test_view_fixlist_template_has_preview_guest_button(self):
        content = self._read_template("view_fixlist.html")

        self.assertIn("preview guest view", content)
        self.assertIn('href="{{ guest_preview_url }}"', content)

    def test_shared_fixlist_template_contains_modal_warning_flow(self):
        content = self._read_template("shared_fixlist.html")

        self.assertIn("id=\"agreement-modal\"", content)
        self.assertIn("access warning: recipient-specific content", content)
        self.assertIn("class=\"muted consent-note\"", content)
        self.assertIn("shared-content-locked", content)
        self.assertNotIn("before you continue", content)
        self.assertNotIn("leave page", content)

    def test_dashboard_template_actions_share_action_button_class(self):
        content = self._read_template("dashboard.html")

        self.assertIn('class="action-btn" onclick="copyShareLink', content)
        self.assertIn('class="action-btn">edit</a>', content)


class LogAnalyzerApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="analyzer", password="password123")

    def test_analyze_api_requires_login(self):
        response = self.client.post(
            reverse("analyze_log_api"),
            data='{"log":"line"}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_analyze_api_returns_known_and_unknown_statuses(self):
        self.client.login(username="analyzer", password="password123")
        ClassificationRule.objects.create(
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="MALICIOUS-LINE",
            description="known malware marker",
        )

        response = self.client.post(
            reverse("analyze_log_api"),
            data='{"log":"MALICIOUS-LINE\\nSOMETHING ELSE"}',
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(payload["lines"]), 2)
        self.assertEqual(payload["lines"][0]["dominant_status"], ClassificationRule.STATUS_MALWARE)
        self.assertEqual(payload["lines"][1]["dominant_status"], ClassificationRule.STATUS_UNKNOWN)
        self.assertEqual(payload["summary"]["unknown_lines"], 1)

    def test_analyze_api_applies_status_precedence(self):
        self.client.login(username="analyzer", password="password123")
        ClassificationRule.objects.create(
            status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="MULTI-MATCH",
        )
        ClassificationRule.objects.create(
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="MULTI-MATCH",
        )

        response = self.client.post(
            reverse("analyze_log_api"),
            data='{"log":"MULTI-MATCH"}',
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["lines"][0]["status_codes"], "BP")
        self.assertEqual(payload["lines"][0]["dominant_status"], ClassificationRule.STATUS_MALWARE)
