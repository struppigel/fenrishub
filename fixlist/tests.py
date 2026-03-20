from pathlib import Path
import json
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser, User
from django.http import Http404, HttpResponse
from django.test import RequestFactory, TestCase
from django.urls import reverse

from .models import AccessLog, ClassificationRule, Fixlist, ParsedFilepathExclusion
from .views import change_password_view, dashboard_view, shared_fixlist_view, view_fixlist


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

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
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


class TemplateMarkupTests(TestCase):
    @staticmethod
    def _read_template(template_name):
        project_root = Path(__file__).resolve().parent.parent
        template_path = project_root / "templates" / template_name
        return template_path.read_text(encoding="utf-8")

    @staticmethod
    def _read_static_asset(*relative_parts):
        project_root = Path(__file__).resolve().parent.parent
        asset_path = project_root / "static"
        for part in relative_parts:
            asset_path = asset_path / part
        return asset_path.read_text(encoding="utf-8")

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
        script_content = "\n".join(
            [
                self._read_static_asset("js", "log_analyzer", "shared.js"),
                self._read_static_asset("js", "log_analyzer", "analysis.js"),
                self._read_static_asset("js", "log_analyzer", "conflict_wizard.js"),
                self._read_static_asset("js", "log_analyzer", "rule_preview.js"),
                self._read_static_asset("js", "log_analyzer", "bootstrap.js"),
            ]
        )

        self.assertIn('id="statusPicker"', content)
        self.assertIn('id="conflictWizardModal"', content)
        self.assertIn('id="ruleReviewDialog"', content)
        self.assertIn('id="conflictWizardDialog"', content)
        self.assertIn('id="plannedExistingRuleChangesList"', content)
        self.assertIn('id="saveRulesRescanButton"', content)
        self.assertIn('>save changes<', content)
        self.assertIn('data-insert-status="!"', content)
        self.assertIn('id="saveFixlistButton"', content)
        self.assertIn('id="conflictWizardBackButton"', content)
        self.assertIn('role="radiogroup"', content)
        self.assertNotIn("onclick=", content)
        self.assertIn("window.logAnalyzerConfig", content)
        self.assertIn("{% static 'css/log_analyzer.css' %}", content)
        self.assertIn("{% static 'js/log_analyzer/shared.js' %}", content)
        self.assertIn("{% static 'js/log_analyzer/analysis.js' %}", content)
        self.assertIn("{% static 'js/log_analyzer/conflict_wizard.js' %}", content)
        self.assertIn("{% static 'js/log_analyzer/rule_preview.js' %}", content)
        self.assertIn("{% static 'js/log_analyzer/bootstrap.js' %}", content)
        self.assertIn("persistRuleChangesUrl", content)

        self.assertIn("fenrishub_pending_status_changes", script_content)
        self.assertIn("manual override:", script_content)
        self.assertIn("renderContradictionListsForRule", script_content)
        self.assertIn("No dominant-status contradictions were detected.", script_content)
        self.assertIn("advanceConflictWizard", script_content)
        self.assertIn("pending_change_id", script_content)
        self.assertIn("existing status changes", script_content)
        self.assertIn("PERSIST_RULE_CHANGES_URL", script_content)
        self.assertIn("persistPendingRuleChanges", script_content)
        self.assertIn("RULE_SUBMIT_TARGET_RESCAN", script_content)
        self.assertIn("saveRulesAndRescan", script_content)
        self.assertIn("bindAnalyzerButton('saveRulesRescanButton'", script_content)
        self.assertIn("cancelRuleWorkflow", script_content)
        self.assertIn("ruleReviewBackdrop.addEventListener('click', () => cancelRuleWorkflow())", script_content)
        self.assertIn("has-pending-changes", script_content)
        self.assertIn("Object.assign(window", script_content)
        self.assertIn("handleAnalyzerModalOpen", script_content)
        self.assertIn("focusStatusPickerButton", script_content)
        self.assertNotIn("{% url 'analyze_log_api' %}", script_content)

    def test_create_fixlist_template_only_uses_prefill_handoff(self):
        content = self._read_template("create_fixlist.html")

        self.assertIn("fenrishub_prefill_content", content)
        self.assertNotIn('id="persistRulesInput"', content)
        self.assertNotIn('id="pendingRuleChangesInput"', content)
        self.assertNotIn('id="selectedRuleIdsInput"', content)
        self.assertNotIn('id="conflictResolutionsInput"', content)
        self.assertNotIn("fenrishub_persist_rules", content)
        self.assertNotIn("fenrishub_pending_rule_changes", content)
        self.assertNotIn("fenrishub_selected_rule_ids", content)
        self.assertNotIn("fenrishub_conflict_resolutions", content)


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
            owner=self.user,
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

    def test_persist_pending_rule_changes_api_requires_login(self):
        payload = {
            "pending_changes": [
                {
                    "id": "1",
                    "line": "IMMEDIATE-PERSIST-LINE",
                    "original_status": "?",
                    "new_status": ClassificationRule.STATUS_MALWARE,
                    "order": 1,
                }
            ],
            "selected_rule_change_ids": ["1"],
            "conflict_resolutions": [],
        }

        response = self.client.post(
            reverse("persist_pending_rule_changes_api"),
            data=json.dumps(payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_persist_pending_rule_changes_api_affects_next_analysis(self):
        self.client.login(username="analyzer", password="password123")

        payload = {
            "pending_changes": [
                {
                    "id": "1",
                    "line": "IMMEDIATE-PERSIST-LINE",
                    "original_status": "?",
                    "new_status": ClassificationRule.STATUS_MALWARE,
                    "order": 1,
                }
            ],
            "selected_rule_change_ids": ["1"],
            "conflict_resolutions": [],
        }

        persist_response = self.client.post(
            reverse("persist_pending_rule_changes_api"),
            data=json.dumps(payload),
            content_type="application/json",
        )

        persist_payload = persist_response.json()
        self.assertEqual(persist_response.status_code, 200)
        self.assertTrue(persist_payload["ok"])
        self.assertTrue(
            ClassificationRule.objects.filter(
                status=ClassificationRule.STATUS_MALWARE,
                source_text="IMMEDIATE-PERSIST-LINE",
                is_enabled=True,
            ).exists()
        )

        analyze_response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": "IMMEDIATE-PERSIST-LINE"}),
            content_type="application/json",
        )

        analyze_payload = analyze_response.json()
        self.assertEqual(analyze_response.status_code, 200)
        self.assertEqual(
            analyze_payload["lines"][0]["dominant_status"],
            ClassificationRule.STATUS_MALWARE,
        )

    def test_persist_pending_rule_changes_api_rejects_invalid_selected_ids_payload(self):
        self.client.login(username="analyzer", password="password123")

        payload = {
            "pending_changes": [],
            "selected_rule_change_ids": {"id": "1"},
            "conflict_resolutions": [],
        }

        response = self.client.post(
            reverse("persist_pending_rule_changes_api"),
            data=json.dumps(payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json().get("error"),
            'Field "selected_rule_change_ids" must be a list.',
        )

    def test_persist_pending_rule_changes_api_applies_update_existing_status_resolution(self):
        self.client.login(username="analyzer", password="password123")

        existing_rule = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="IMMEDIATE-STATUS-SWAP",
            description="existing clean rule",
        )
        payload = {
            "pending_changes": [
                {
                    "id": "1",
                    "line": "IMMEDIATE-STATUS-SWAP",
                    "original_status": "?",
                    "new_status": ClassificationRule.STATUS_MALWARE,
                    "order": 1,
                }
            ],
            "selected_rule_change_ids": ["1"],
            "conflict_resolutions": [
                {
                    "conflict_key": f"override:1:{existing_rule.id}",
                    "contradiction_type": "override_vs_existing_dominant",
                    "change_id": "1",
                    "existing_rule_id": existing_rule.id,
                    "action": "update_existing_status",
                }
            ],
        }

        response = self.client.post(
            reverse("persist_pending_rule_changes_api"),
            data=json.dumps(payload),
            content_type="application/json",
        )

        existing_rule.refresh_from_db()
        payload_json = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload_json.get("ok"))
        self.assertEqual(payload_json.get("created_rules"), 0)
        self.assertEqual(payload_json.get("updated_rules"), 0)
        self.assertEqual(existing_rule.status, ClassificationRule.STATUS_MALWARE)
        self.assertTrue(existing_rule.is_enabled)
        self.assertEqual(
            ClassificationRule.objects.filter(
                status=ClassificationRule.STATUS_MALWARE,
                match_type=ClassificationRule.MATCH_EXACT,
                source_text="IMMEDIATE-STATUS-SWAP",
            ).count(),
            1,
        )

    def test_analyze_api_applies_status_precedence(self):
        self.client.login(username="analyzer", password="password123")
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="MULTI-MATCH",
        )
        ClassificationRule.objects.create(
            owner=self.user,
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
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="CONFLICT-LINE",
            description="existing malware exact",
        )
        ClassificationRule.objects.create(
            owner=self.user,
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
        self.assertIn("entry_type", payload["rule_changes"][0])
        self.assertIn("normalized_filepath", payload["rule_changes"][0])
        self.assertIn("matching_rules", payload["contradictions"]["override_vs_existing_dominant"][0])
        self.assertTrue(payload["contradictions"]["override_vs_existing_dominant"][0]["matching_rules"])
        self.assertIn("id", payload["contradictions"]["override_vs_existing_dominant"][0]["matching_rules"][0])
        self.assertIn("matching_rules", payload["contradictions"]["overlaps_other_status_rules"][0])
        self.assertIn("match_type", payload["contradictions"]["overlaps_other_status_rules"][0]["matching_rules"][0])

    def test_preview_pending_rule_changes_includes_parsed_groups(self):
        self.client.login(username="analyzer", password="password123")
        runkey_line = (
            r"HKU\S-1-5-21-111-222-333-1001\...\Run: [SomeValue] => C:\Users\Alice\AppData\Roaming\Some.exe "
            r"[2024-01-01] (Contoso)"
        )

        response = self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps(
                {
                    "pending_changes": [
                        {
                            "id": "parsed-1",
                            "line": runkey_line,
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
        rule = payload["rule_changes"][0]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(rule["match_type"], ClassificationRule.MATCH_PARSED_ENTRY)
        self.assertTrue(rule["entry_type"])
        self.assertTrue(rule["name"])
        self.assertTrue(rule["filepath"])
        self.assertTrue(rule["normalized_filepath"])

    def test_parse_rule_line_keeps_parsed_entry_match_type_for_service_lines(self):
        from .analyzer import parse_rule_line

        service_line = (
            r"R3 ProtoVPN Service; C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe "
            r"[477424 2026-03-06] (Proto AG -> ProtoVPN)"
        )

        parsed = parse_rule_line(
            service_line,
            status=ClassificationRule.STATUS_MALWARE,
            source_name="test-suite",
        )

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["match_type"], ClassificationRule.MATCH_PARSED_ENTRY)
        self.assertTrue(parsed["normalized_filepath"])

    def test_persisted_parsed_rule_matches_other_line_with_same_filepath(self):
        self.client.login(username="analyzer", password="password123")
        service_line = (
            r"R3 ProtoVPN Service; C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe "
            r"[477424 2026-03-06] (Proto AG -> ProtoVPN)"
        )
        same_path_line = (
            r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 ____D "
            r"C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe"
        )

        persist_payload = {
            "pending_changes": [
                {
                    "id": "1",
                    "line": service_line,
                    "original_status": "?",
                    "new_status": ClassificationRule.STATUS_MALWARE,
                    "order": 1,
                }
            ],
            "selected_rule_change_ids": ["1"],
            "conflict_resolutions": [],
        }

        persist_response = self.client.post(
            reverse("persist_pending_rule_changes_api"),
            data=json.dumps(persist_payload),
            content_type="application/json",
        )

        self.assertEqual(persist_response.status_code, 200)
        self.assertTrue(
            ClassificationRule.objects.filter(
                status=ClassificationRule.STATUS_MALWARE,
                match_type=ClassificationRule.MATCH_PARSED_ENTRY,
                source_text=service_line,
                is_enabled=True,
            ).exists()
        )

        analyze_response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": f"{service_line}\n{same_path_line}"}),
            content_type="application/json",
        )

        analyze_payload = analyze_response.json()
        self.assertEqual(analyze_response.status_code, 200)
        self.assertEqual(analyze_payload["lines"][0]["matcher"], "parsed_entry")
        self.assertEqual(analyze_payload["lines"][1]["matcher"], "filepath")
        self.assertEqual(analyze_payload["lines"][0]["dominant_status"], ClassificationRule.STATUS_MALWARE)
        self.assertEqual(analyze_payload["lines"][1]["dominant_status"], ClassificationRule.STATUS_MALWARE)

    def test_parsed_fallback_filepath_respects_exclusion_list(self):
        from .analyzer import parse_rule_line, inspect_line_matches

        self.client.login(username="analyzer", password="password123")
        service_line = (
            r"R3 ProtoVPN Service; C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe "
            r"[477424 2026-03-06] (Proto AG -> ProtoVPN)"
        )
        same_path_line = (
            r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 ____D "
            r"C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe"
        )
        service_path = r"C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe"

        parsed_rule = parse_rule_line(
            service_line,
            status=ClassificationRule.STATUS_MALWARE,
            source_name="test-suite",
        )
        self.assertIsNotNone(parsed_rule)
        ClassificationRule.objects.create(owner=self.user, **parsed_rule)

        ParsedFilepathExclusion.objects.create(normalized_filepath=service_path)

        analyze_response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": same_path_line}),
            content_type="application/json",
        )
        analyze_payload = analyze_response.json()

        self.assertEqual(analyze_response.status_code, 200)
        self.assertEqual(analyze_payload["lines"][0]["matcher"], "unknown")
        self.assertEqual(analyze_payload["lines"][0]["dominant_status"], ClassificationRule.STATUS_UNKNOWN)

        inspection = inspect_line_matches(same_path_line)
        self.assertEqual(inspection["effective_matcher"], "unknown")
        self.assertEqual(inspection["dominant_status"], ClassificationRule.STATUS_UNKNOWN)
        self.assertEqual(inspection["matches"], [])

    def test_explicit_filepath_rule_ignores_parsed_fallback_exclusion_list(self):
        from .analyzer import inspect_line_matches

        self.client.login(username="analyzer", password="password123")
        same_path_line = (
            r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 ____D "
            r"C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe"
        )
        service_path = r"C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe"

        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_FILEPATH,
            source_text=service_path,
            source_name="test-suite",
            filepath=service_path,
            normalized_filepath=service_path.lower(),
        )
        ParsedFilepathExclusion.objects.create(normalized_filepath=service_path)

        analyze_response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": same_path_line}),
            content_type="application/json",
        )
        analyze_payload = analyze_response.json()

        self.assertEqual(analyze_response.status_code, 200)
        self.assertEqual(analyze_payload["lines"][0]["matcher"], "filepath")
        self.assertEqual(analyze_payload["lines"][0]["dominant_status"], ClassificationRule.STATUS_MALWARE)

        inspection = inspect_line_matches(same_path_line)
        self.assertEqual(inspection["effective_matcher"], "filepath")
        self.assertTrue(inspection["matches"])
        self.assertEqual(
            {match["status"] for match in inspection["matches"]},
            {ClassificationRule.STATUS_MALWARE},
        )

    def test_inspect_line_matches_prefers_parsed_entry_matcher_over_filepath_for_same_rule(self):
        from .analyzer import inspect_line_matches

        self.client.login(username="analyzer", password="password123")
        service_line = (
            r"R3 ProtoVPN Service; C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe "
            r"[477424 2026-03-06] (Proto AG -> ProtoVPN)"
        )

        persist_payload = {
            "pending_changes": [
                {
                    "id": "1",
                    "line": service_line,
                    "original_status": "?",
                    "new_status": ClassificationRule.STATUS_CLEAN,
                    "order": 1,
                }
            ],
            "selected_rule_change_ids": ["1"],
            "conflict_resolutions": [],
        }

        persist_response = self.client.post(
            reverse("persist_pending_rule_changes_api"),
            data=json.dumps(persist_payload),
            content_type="application/json",
        )
        self.assertEqual(persist_response.status_code, 200)

        persisted_rule = ClassificationRule.objects.get(
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY,
            source_text=service_line,
        )

        inspection = inspect_line_matches(service_line)
        rule_matches = [item for item in inspection["matches"] if item["id"] == persisted_rule.id]

        self.assertEqual(len(rule_matches), 1)
        self.assertEqual(rule_matches[0]["matcher"], "parsed_entry")

    def test_inspect_line_matches_uses_runtime_precedence_and_tracks_shadowed_matches(self):
        from .analyzer import inspect_line_matches, parse_rule_line

        self.client.login(username="analyzer", password="password123")
        service_line = (
            r"R3 ProtoVPN Service; C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe "
            r"[477424 2026-03-06] (Proto AG -> ProtoVPN)"
        )
        service_path = r"C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe"

        parsed_rule = parse_rule_line(
            service_line,
            status=ClassificationRule.STATUS_CLEAN,
            source_name="test-suite",
        )
        self.assertIsNotNone(parsed_rule)

        ClassificationRule.objects.create(owner=self.user, **parsed_rule)
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_FILEPATH,
            source_text=service_path,
            source_name="test-suite",
            filepath=service_path,
            normalized_filepath=service_path.lower(),
        )

        inspection = inspect_line_matches(service_line)

        self.assertEqual(inspection["effective_matcher"], "parsed_entry")
        self.assertEqual(inspection["dominant_status"], ClassificationRule.STATUS_CLEAN)
        self.assertTrue(inspection["matches"])
        self.assertEqual({match["status"] for match in inspection["matches"]}, {ClassificationRule.STATUS_CLEAN})

        shadowed_statuses = {match["status"] for match in inspection["shadowed_matches"]}
        shadowed_matchers = {match["matcher"] for match in inspection["shadowed_matches"]}
        self.assertIn(ClassificationRule.STATUS_MALWARE, shadowed_statuses)
        self.assertIn("filepath", shadowed_matchers)

    def test_preview_pending_rule_changes_uses_effective_matches_for_contradictions(self):
        from .analyzer import parse_rule_line

        self.client.login(username="analyzer", password="password123")
        service_line = (
            r"R3 ProtoVPN Service; C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe "
            r"[477424 2026-03-06] (Proto AG -> ProtoVPN)"
        )
        service_path = r"C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe"

        parsed_rule = parse_rule_line(
            service_line,
            status=ClassificationRule.STATUS_CLEAN,
            source_name="test-suite",
        )
        self.assertIsNotNone(parsed_rule)

        ClassificationRule.objects.create(owner=self.user, **parsed_rule)
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_FILEPATH,
            source_text=service_path,
            source_name="test-suite",
            filepath=service_path,
            normalized_filepath=service_path.lower(),
        )

        response = self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps(
                {
                    "pending_changes": [
                        {
                            "id": "precedence-1",
                            "line": service_line,
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

        override_conflicts = payload["contradictions"]["override_vs_existing_dominant"]
        self.assertEqual(len(override_conflicts), 1)
        self.assertEqual(override_conflicts[0]["existing_dominant_status"], ClassificationRule.STATUS_CLEAN)
        self.assertEqual(
            {item["status"] for item in override_conflicts[0]["matching_rules"]},
            {ClassificationRule.STATUS_CLEAN},
        )

        overlap_conflicts = payload["contradictions"]["overlaps_other_status_rules"]
        self.assertEqual(len(overlap_conflicts), 1)
        self.assertEqual(overlap_conflicts[0]["overlap_statuses"], [ClassificationRule.STATUS_CLEAN])
        self.assertNotIn(ClassificationRule.STATUS_MALWARE, overlap_conflicts[0]["overlap_statuses"])

    def test_preview_pending_rule_changes_marks_existing_rule_as_update(self):
        self.client.login(username="analyzer", password="password123")

        ClassificationRule.objects.create(
            owner=self.user,
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
