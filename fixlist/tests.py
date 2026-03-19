from pathlib import Path
import json
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

    def test_create_fixlist_without_rule_persistence_creates_no_rules(self):
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
                "title": "Fixlist No Rule Persist",
                "content": "line-a",
                "internal_note": "",
                "persist_rules": "0",
                "pending_rule_changes_json": json.dumps(pending_changes),
                "selected_rule_change_ids_json": json.dumps(["1"]),
            },
        )

        created = Fixlist.objects.get(title="Fixlist No Rule Persist")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[created.pk]))
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_fixlist_persists_only_selected_pending_rules(self):
        pending_changes = [
            {
                "id": "1",
                "line": "MALICIOUS-LINE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_MALWARE,
                "order": 1,
            },
            {
                "id": "2",
                "line": "PUP-LINE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_PUP,
                "order": 2,
            },
        ]

        response = self.client.post(
            reverse("create_fixlist"),
            {
                "title": "Fixlist Selected Rule Persist",
                "content": "line-a\nline-b",
                "internal_note": "",
                "persist_rules": "1",
                "pending_rule_changes_json": json.dumps(pending_changes),
                "selected_rule_change_ids_json": json.dumps(["1"]),
            },
        )

        created = Fixlist.objects.get(title="Fixlist Selected Rule Persist")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[created.pk]))
        self.assertTrue(
            ClassificationRule.objects.filter(
                status=ClassificationRule.STATUS_MALWARE,
                source_text="MALICIOUS-LINE",
            ).exists()
        )
        self.assertFalse(
            ClassificationRule.objects.filter(
                status=ClassificationRule.STATUS_PUP,
                source_text="PUP-LINE",
            ).exists()
        )

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

    def test_log_analyzer_template_contains_status_picker_hooks(self):
        content = self._read_template("log_analyzer.html")

        self.assertIn('id="statusPicker"', content)
        self.assertIn("fenrishub_pending_status_changes", content)
        self.assertIn("manual override:", content)
        self.assertNotIn("update_analyzed_line_status_api", content)

    def test_create_fixlist_template_contains_persist_review_modal(self):
        content = self._read_template("create_fixlist.html")

        self.assertIn('id="ruleReviewModal"', content)
        self.assertIn("preview_pending_rule_changes_api", content)
        self.assertIn("save + persist selected rules", content)


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

    def test_analyze_api_returns_incomplete_log_warning(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Scan result of Farbar Recovery Scan Tool\n"
                    "Some FRST content without end markers"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warning_codes = {warning["code"] for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("incomplete_logs", warning_codes)
        self.assertEqual(payload["summary"]["warning_count"], len(payload["warnings"]))

    def test_analyze_api_returns_low_memory_warning(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Percentage of memory in use: 91%\n"
                    "Total physical RAM: 2048 MB\n"
                    "Drive C: (Windows) (Free:50 GB)\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("low_memory", warnings_by_code)
        self.assertIn("RAM usage above 80%", warnings_by_code["low_memory"]["message"])

    def test_analyze_api_accepts_windows_ssd_drive_line_for_memory_check(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "BIOS: LENOVO KZCN40WW 10/18/2023\n"
                    "Motherboard: LENOVO LNVNB161216\n"
                    "Processor: 13th Gen Intel(R) Core(TM) i5-13500H\n"
                    "Percentage of memory in use: 67%\n"
                    "Total physical RAM: 16123.87 MB\n"
                    "Available physical RAM: 5196.51 MB\n"
                    "Total Virtual: 30459.87 MB\n"
                    "Available Virtual: 13730.64 MB\n"
                    "Drive c: (Windows-SSD) (Fixed) (Total:951.65 GB) (Free:260.94 GB) (Model: SAMSUNG MZAL41T0HBLB-00BL2) (Protected) NTFS\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("low_memory", warnings_by_code)

    def test_analyze_api_accepts_drive_c_without_windows_label_for_memory_check(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Percentage of memory in use: 48%\n"
                    "Total physical RAM: 16107.87 MB\n"
                    "Available physical RAM: 8322.04 MB\n"
                    "Drive c: () (Fixed) (Total:952.91 GB) (Free:901.65 GB) (Model: SAMSUNG MZVL21T0HCLR-00BL2) NTFS\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("low_memory", warnings_by_code)

    def test_update_status_api_requires_login(self):
        response = self.client.post(
            reverse("update_analyzed_line_status_api"),
            data=json.dumps({"line": "example", "status": "B", "current_status": "?"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_update_status_api_rejects_invalid_status(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("update_analyzed_line_status_api"),
            data=json.dumps({"line": "example", "status": "X", "current_status": "?"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid status", response.json()["error"])

    def test_update_status_api_rejects_informational_line_edits(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("update_analyzed_line_status_api"),
            data=json.dumps({"line": "example", "status": "B", "current_status": "I"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "Informational lines cannot be edited.")

    def test_update_status_api_validates_payload_without_persisting(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("update_analyzed_line_status_api"),
            data=json.dumps(
                {
                    "line": "MALICIOUS-LINE",
                    "status": ClassificationRule.STATUS_MALWARE,
                    "current_status": ClassificationRule.STATUS_UNKNOWN,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(payload["persisted"])
        self.assertEqual(payload["match_type"], ClassificationRule.MATCH_EXACT)
        self.assertFalse(ClassificationRule.objects.filter(source_text="MALICIOUS-LINE").exists())

    def test_update_status_api_validates_parsed_entry_without_persisting(self):
        self.client.login(username="analyzer", password="password123")
        runkey_line = (
            r"HKU\S-1-5-21-111-222-333-1001\...\Run: [SomeValue] => C:\Users\Alice\AppData\Roaming\Some.exe "
            r"[2024-01-01] (Contoso)"
        )

        response = self.client.post(
            reverse("update_analyzed_line_status_api"),
            data=json.dumps(
                {
                    "line": runkey_line,
                    "status": ClassificationRule.STATUS_PUP,
                    "current_status": ClassificationRule.STATUS_UNKNOWN,
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(payload["persisted"])
        self.assertEqual(payload["match_type"], ClassificationRule.MATCH_PARSED_ENTRY)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_preview_pending_rule_changes_api_requires_login(self):
        response = self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps({"pending_changes": []}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_preview_pending_rule_changes_api_rejects_non_list_payload(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps({"pending_changes": {"id": "1"}}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("must be a list", response.json()["error"])

    def test_preview_pending_rule_changes_reports_conflicts_and_candidates(self):
        self.client.login(username="analyzer", password="password123")

        ClassificationRule.objects.create(
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="CONFLICT-LINE",
            description="existing malware exact",
        )
        ClassificationRule.objects.create(
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="CONFLICT",
            description="existing clean substring",
        )

        response = self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps(
                {
                    "pending_changes": [
                        {
                            "id": "1",
                            "line": "CONFLICT-LINE",
                            "original_status": "?",
                            "new_status": ClassificationRule.STATUS_PUP,
                            "order": 1,
                        }
                    ]
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        summary = payload["summary"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(summary["pending_changes"], 1)
        self.assertEqual(summary["rule_candidates"], 1)
        self.assertEqual(summary["create_candidates"], 1)
        self.assertGreaterEqual(summary["override_conflicts"], 1)
        self.assertGreaterEqual(summary["overlap_conflicts"], 1)
        self.assertEqual(payload["rule_changes"][0]["match_type"], ClassificationRule.MATCH_EXACT)

    def test_preview_pending_rule_changes_marks_existing_rule_as_update(self):
        self.client.login(username="analyzer", password="password123")

        ClassificationRule.objects.create(
            status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="EXISTING-PUP",
            description="already tracked",
        )

        response = self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps(
                {
                    "pending_changes": [
                        {
                            "id": "2",
                            "line": "EXISTING-PUP",
                            "original_status": "?",
                            "new_status": ClassificationRule.STATUS_PUP,
                            "order": 1,
                        }
                    ]
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload["rule_changes"][0]["action"], "update")

    def test_analyze_api_flags_memory_incomplete_when_drive_info_missing(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Percentage of memory in use: 67%\n"
                    "Total physical RAM: 16123.87 MB\n"
                    "Available physical RAM: 5196.51 MB\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("low_memory", warnings_by_code)
        self.assertIn("Memory information incomplete", warnings_by_code["low_memory"]["message"])
