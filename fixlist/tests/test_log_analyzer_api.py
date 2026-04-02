import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory

from ..models import ClassificationRule, ParsedFilepathExclusion, UploadedLog
from ..views import log_analyzer_view


class LogAnalyzerCleanSaveTests(TestCase):
    """Tests for the superuser-only 'remaining = C' feature in the log analyzer."""

    def test_superuser_context_is_true(self):
        superuser = User.objects.create_superuser(username="admin", password="password123")
        request = RequestFactory().get(reverse("log_analyzer"))
        request.user = superuser

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
            log_analyzer_view(request)

        rendered_context = mock_render.call_args.args[2]
        self.assertTrue(rendered_context.get("is_superuser"))

    def test_regular_user_context_is_false(self):
        user = User.objects.create_user(username="regular", password="password123")
        request = RequestFactory().get(reverse("log_analyzer"))
        request.user = user

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
            log_analyzer_view(request)

        rendered_context = mock_render.call_args.args[2]
        self.assertFalse(rendered_context.get("is_superuser"))

    def test_template_contains_superuser_button_conditionally(self):
        from pathlib import Path

        project_root = Path(__file__).resolve().parent.parent.parent
        content = (project_root / "templates" / "log_analyzer.html").read_text(encoding="utf-8")

        self.assertIn('id="addRemainingCleanButton"', content)
        self.assertIn("remaining = C", content)
        self.assertIn("{% if is_superuser %}", content)
        self.assertIn("isSuperuser", content)

    def test_js_contains_add_remaining_as_clean_function(self):
        from pathlib import Path

        project_root = Path(__file__).resolve().parent.parent.parent
        js_path = project_root / "static" / "js" / "log_analyzer" / "analysis.js"
        js_content = js_path.read_text(encoding="utf-8")

        self.assertIn("function addRemainingAsClean()", js_content)
        self.assertIn("ATTENTION", js_content)
        self.assertIn("No File", js_content)
        self.assertIn("Access Denied", js_content)
        self.assertIn("entry_type", js_content)


class LogAnalyzerApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="analyzer", password="password123")
        self.other_user = User.objects.create_user(username="other_helper", password="password123")

    def test_analyze_api_requires_login(self):
        response = self.client.post(
            reverse("analyze_log_api"),
            data='{"log":"line"}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_uploaded_log_content_api_requires_login(self):
        uploaded = UploadedLog.objects.create(
            upload_id='rapid-trail',
            reddit_username='reddit_name',
            original_filename='content.txt',
            content='line-1',
        )

        response = self.client.get(reverse('uploaded_log_content_api', args=[uploaded.upload_id]))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_uploaded_log_content_api_returns_json_payload(self):
        self.client.login(username='analyzer', password='password123')
        uploaded = UploadedLog.objects.create(
            upload_id='rapid-trail',
            reddit_username='reddit_name',
            original_filename='content.txt',
            content='line-1\nline-2',
        )

        response = self.client.get(reverse('uploaded_log_content_api', args=[uploaded.upload_id]))
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['upload_id'], 'rapid-trail')
        self.assertEqual(payload['original_filename'], 'content.txt')
        self.assertEqual(payload['reddit_username'], 'reddit_name')
        self.assertEqual(payload['content'], 'line-1\nline-2')

    def test_uploaded_log_content_api_blocks_other_helper_channel_upload(self):
        self.client.login(username='analyzer', password='password123')
        uploaded = UploadedLog.objects.create(
            upload_id='private-rapid-trail',
            reddit_username='reddit_name',
            original_filename='content.txt',
            content='line-1\nline-2',
            recipient_user=self.other_user,
        )

        response = self.client.get(reverse('uploaded_log_content_api', args=[uploaded.upload_id]))

        self.assertEqual(response.status_code, 404)

    def test_analyze_line_details_api_requires_login(self):
        response = self.client.post(
            reverse("analyze_line_details_api"),
            data=json.dumps({"line": "example", "status": "?"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_analyze_line_details_api_returns_parsed_components(self):
        self.client.login(username="analyzer", password="password123")
        runkey_line = (
            r"HKU\S-1-5-21-111-222-333-1001\...\Run: [SomeValue] => C:\Users\Alice\AppData\Roaming\Some.exe "
            r"[2024-01-01] (Contoso)"
        )

        response = self.client.post(
            reverse("analyze_line_details_api"),
            data=json.dumps({"line": runkey_line, "status": ClassificationRule.STATUS_PUP}),
            content_type="application/json",
        )

        payload = response.json()
        parsed_rule = payload.get("parsed_rule") or {}
        inspection = payload.get("inspection") or {}

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload.get("line"), runkey_line)
        self.assertEqual(parsed_rule.get("match_type"), ClassificationRule.MATCH_PARSED_ENTRY)
        self.assertTrue(parsed_rule.get("entry_type"))
        self.assertTrue(parsed_rule.get("name"))
        self.assertTrue(parsed_rule.get("filepath"))
        self.assertIn("dominant_status", inspection)
        self.assertIn("matches", inspection)

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

    def test_analyze_api_updates_stats_for_selected_upload_only(self):
        self.client.login(username="analyzer", password="password123")
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="MALICIOUS-LINE",
        )
        selected_upload = UploadedLog.objects.create(
            upload_id='swift-river',
            reddit_username='stats_user',
            original_filename='one.txt',
            content='placeholder',
        )
        other_upload = UploadedLog.objects.create(
            upload_id='quiet-harbor',
            reddit_username='stats_user',
            original_filename='two.txt',
            content='placeholder',
        )

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": "MALICIOUS-LINE\nUNKNOWN-LINE", "upload_id": selected_upload.upload_id}),
            content_type="application/json",
        )

        selected_upload.refresh_from_db()
        other_upload.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(selected_upload.total_line_count, 2)
        self.assertEqual(selected_upload.count_malware, 1)
        self.assertEqual(selected_upload.count_unknown, 1)
        self.assertEqual(other_upload.total_line_count, 0)
        self.assertEqual(other_upload.count_malware, 0)
        self.assertEqual(other_upload.count_unknown, 0)

    def test_analyze_api_does_not_update_out_of_scope_upload(self):
        self.client.login(username="analyzer", password="password123")
        uploaded = UploadedLog.objects.create(
            upload_id='blocked-update',
            reddit_username='stats_user',
            original_filename='blocked.txt',
            log_type='FRST',
            content='Scan result of Farbar Recovery Scan Tool\nMAL-LINE',
            recipient_user=self.other_user,
        )

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({
                "log": "Scan result of Farbar Recovery Scan Tool\\nMAL-LINE",
                "upload_id": uploaded.upload_id,
            }),
            content_type="application/json",
        )

        uploaded.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(uploaded.total_line_count, 0)
        self.assertEqual(uploaded.count_malware, 0)

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

    def test_analyze_api_returns_alert_warning_from_matched_alert_rule_description(self):
        self.client.login(username="analyzer", password="password123")
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="ALERT-LINE",
            description="Investigate this suspicious pattern",
        )

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": "ALERT-LINE\nOTHER-LINE"}),
            content_type="application/json",
        )

        payload = response.json()
        warnings = payload["warnings"]
        alert_warnings = [w for w in warnings if w.get("title") == "Alert rule matched"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(alert_warnings), 1)
        self.assertEqual(alert_warnings[0]["message"], "Investigate this suspicious pattern")

    def test_analyze_api_deduplicates_alert_warnings_for_same_description(self):
        self.client.login(username="analyzer", password="password123")
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="ALERT-LINE-1",
            description="Shared alert description",
        )
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="ALERT-LINE-2",
            description="Shared alert description",
        )

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": "ALERT-LINE-1\nALERT-LINE-2"}),
            content_type="application/json",
        )

        payload = response.json()
        warnings = payload["warnings"]
        alert_warnings = [w for w in warnings if w.get("title") == "Alert rule matched"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(alert_warnings), 1)
        self.assertEqual(alert_warnings[0]["message"], "Shared alert description")

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

    def test_analyze_api_warns_when_multiple_enabled_av_entries_found(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "AV: Malwarebytes (Enabled - Up to date) {A537353A-1D6A-F6B5-9153-CE1CF80FBE66}\n"
                    "AV: Windows Defender (Enabled - Up to date) {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}\n"
                    "AV: ESET Security (Enabled - Up to date) {26E0861C-6FB9-CEF9-E4F0-531986211ACE}\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("multiple_enabled_av", warnings_by_code)
        self.assertIn("Multiple AV products are enabled", warnings_by_code["multiple_enabled_av"]["message"])

    def test_analyze_api_does_not_warn_for_same_av_product_multiple_entries(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "AV: Kaspersky (Enabled - Up to date) {DABD1ABC-6D70-BB0E-89E6-BFA3FC920FD1}\n"
                    "AV: Kaspersky (Enabled - Up to date) {70E35457-C7D9-669C-FEA5-55382EABDC78}\n"
                    "AV: Windows Defender (Disabled - Up to date) {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}\n"
                    "AV: Kaspersky (Enabled - Up to date) {4F76F112-43EB-40E8-11D8-F7BD1853EA23}\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warning_codes = {warning["code"] for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("multiple_enabled_av", warning_codes)

    def test_analyze_api_does_not_warn_for_single_enabled_av_entry(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "AV: Windows Defender (Enabled - Up to date) {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}\n"
                    "AV: ESET Security (Disabled - Out of date) {26E0861C-6FB9-CEF9-E4F0-531986211ACE}\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warning_codes = {warning["code"] for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("multiple_enabled_av", warning_codes)

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

    def test_update_status_api_rejects_alert_line_edits(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("update_analyzed_line_status_api"),
            data=json.dumps({"line": "example", "status": "B", "current_status": "A"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "Alert lines cannot be edited.")

    def test_update_status_api_rejects_setting_alert_status(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("update_analyzed_line_status_api"),
            data=json.dumps({"line": "example", "status": "A", "current_status": "?"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "Setting alert status from analyzer is not allowed.")

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
        from ..analyzer import parse_rule_line

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
        from ..analyzer import parse_rule_line, inspect_line_matches

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
        from ..analyzer import inspect_line_matches

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
        from ..analyzer import inspect_line_matches

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
        from ..analyzer import inspect_line_matches, parse_rule_line

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
        from ..analyzer import parse_rule_line

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

    def test_match_type_precedence_parsed_over_substring(self):
        """Parsed entry match takes precedence over a substring match on the same line."""
        from ..analyzer import inspect_line_matches, parse_rule_line

        self.client.login(username="analyzer", password="password123")
        service_line = (
            r"R3 TestService; C:\Program Files\TestApp\service.exe "
            r"[123456 2026-01-01] (TestCorp -> TestApp)"
        )

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
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="TestService",
        )

        inspection = inspect_line_matches(service_line)

        self.assertEqual(inspection["effective_matcher"], "parsed_entry")
        self.assertEqual(inspection["dominant_status"], ClassificationRule.STATUS_CLEAN)
        shadowed_matchers = {m["matcher"] for m in inspection["shadowed_matches"]}
        self.assertIn("substring", shadowed_matchers)

    def test_match_type_precedence_exact_over_parsed(self):
        """Exact match takes precedence over a parsed entry match."""
        from ..analyzer import inspect_line_matches, parse_rule_line

        self.client.login(username="analyzer", password="password123")
        service_line = (
            r"R3 ExactTestSvc; C:\Program Files\ExactApp\svc.exe "
            r"[654321 2026-02-01] (ExactCorp -> ExactApp)"
        )

        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text=service_line,
        )

        parsed_rule = parse_rule_line(
            service_line,
            status=ClassificationRule.STATUS_CLEAN,
            source_name="test-suite",
        )
        self.assertIsNotNone(parsed_rule)
        ClassificationRule.objects.create(owner=self.user, **parsed_rule)

        inspection = inspect_line_matches(service_line)

        self.assertEqual(inspection["effective_matcher"], "exact")
        self.assertEqual(inspection["dominant_status"], ClassificationRule.STATUS_MALWARE)
        shadowed_matchers = {m["matcher"] for m in inspection["shadowed_matches"]}
        self.assertIn("parsed_entry", shadowed_matchers)

    def test_match_type_precedence_filepath_over_regex(self):
        """Filepath match takes precedence over a regex match."""
        from ..analyzer import inspect_line_matches

        self.client.login(username="analyzer", password="password123")
        # Use a FRST-style line so extract_any_frst_path can find the path
        line_with_path = (
            r"2026-01-01 12:00 - 2026-01-01 12:00 - 0001234 _____ "
            r"C:\Windows\System32\fptest.dll"
        )

        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_FILEPATH,
            source_text=r"C:\Windows\System32\fptest.dll",
            filepath=r"C:\Windows\System32\fptest.dll",
            normalized_filepath=r"c:\windows\system32\fptest.dll",
        )

        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_REGEX,
            source_text=r"fptest\.dll",
        )

        inspection = inspect_line_matches(line_with_path)

        self.assertEqual(inspection["effective_matcher"], "filepath")
        self.assertEqual(inspection["dominant_status"], ClassificationRule.STATUS_CLEAN)
        shadowed_matchers = {m["matcher"] for m in inspection["shadowed_matches"]}
        self.assertIn("regex", shadowed_matchers)

    def test_preview_conflict_includes_match_type_for_precedence(self):
        """Preview API includes match_type on both new and existing rules for precedence display."""
        from ..analyzer import parse_rule_line

        self.client.login(username="analyzer", password="password123")
        service_line = (
            r"R3 PrecedenceSvc; C:\Program Files\PrecApp\svc.exe "
            r"[111111 2026-01-15] (PrecCorp -> PrecApp)"
        )

        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="PrecedenceSvc",
        )

        response = self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps(
                {
                    "pending_changes": [
                        {
                            "id": "mt-1",
                            "line": service_line,
                            "original_status": "?",
                            "new_status": ClassificationRule.STATUS_CLEAN,
                            "order": 1,
                        }
                    ]
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        self.assertEqual(response.status_code, 200)

        rule_change = payload["rule_changes"][0]
        self.assertIn("match_type", rule_change)

        overlap_conflicts = payload["contradictions"]["overlaps_other_status_rules"]
        if overlap_conflicts:
            for match in overlap_conflicts[0]["matching_rules"]:
                self.assertIn("match_type", match)


class RuleOwnershipTests(TestCase):
    """Tests for rule ownership enforcement in preview and persist APIs."""

    def setUp(self):
        self.alice = User.objects.create_user(username="alice", password="password123")
        self.bob = User.objects.create_user(username="bob", password="password123")

    def _preview(self, pending_changes):
        return self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps({"pending_changes": pending_changes}),
            content_type="application/json",
        )

    def _persist(self, pending_changes, selected_ids, conflict_resolutions):
        return self.client.post(
            reverse("persist_pending_rule_changes_api"),
            data=json.dumps({
                "pending_changes": pending_changes,
                "selected_rule_change_ids": selected_ids,
                "conflict_resolutions": conflict_resolutions,
            }),
            content_type="application/json",
        )

    # -- owner_username in preview API --

    def test_preview_conflict_matching_rules_include_owner_username(self):
        """Matching rules in contradictions include the owner_username field."""
        self.client.login(username="alice", password="password123")
        ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="OWNERSHIP-LINE",
        )

        response = self._preview([{
            "id": "1",
            "line": "OWNERSHIP-LINE",
            "original_status": "?",
            "new_status": ClassificationRule.STATUS_CLEAN,
            "order": 1,
        }])

        payload = response.json()
        self.assertEqual(response.status_code, 200)

        all_matching_rules = []
        for conflict in payload["contradictions"]["override_vs_existing_dominant"]:
            all_matching_rules.extend(conflict["matching_rules"])
        for conflict in payload["contradictions"]["overlaps_other_status_rules"]:
            all_matching_rules.extend(conflict["matching_rules"])

        self.assertTrue(all_matching_rules)
        for match in all_matching_rules:
            self.assertIn("owner_username", match)

    def test_preview_conflict_matching_rule_shows_correct_owner(self):
        """owner_username matches the actual rule owner, not the requesting user."""
        self.client.login(username="alice", password="password123")
        ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="BOB-RULE-LINE",
        )

        response = self._preview([{
            "id": "1",
            "line": "BOB-RULE-LINE",
            "original_status": "?",
            "new_status": ClassificationRule.STATUS_CLEAN,
            "order": 1,
        }])

        payload = response.json()
        override_conflicts = payload["contradictions"]["override_vs_existing_dominant"]
        self.assertTrue(override_conflicts)
        bob_rules = [
            match
            for conflict in override_conflicts
            for match in conflict["matching_rules"]
            if match["owner_username"] == "bob"
        ]
        self.assertTrue(bob_rules)

    def test_preview_own_rule_shows_own_username(self):
        """owner_username shows the requesting user's name for their own rules."""
        self.client.login(username="alice", password="password123")
        ClassificationRule.objects.create(
            owner=self.alice,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="ALICE-RULE-LINE",
        )

        response = self._preview([{
            "id": "1",
            "line": "ALICE-RULE-LINE",
            "original_status": "?",
            "new_status": ClassificationRule.STATUS_CLEAN,
            "order": 1,
        }])

        payload = response.json()
        override_conflicts = payload["contradictions"]["override_vs_existing_dominant"]
        self.assertTrue(override_conflicts)
        alice_rules = [
            match
            for conflict in override_conflicts
            for match in conflict["matching_rules"]
            if match["owner_username"] == "alice"
        ]
        self.assertTrue(alice_rules)

    # -- persist API cross-user enforcement --

    def test_persist_update_existing_status_ignores_other_users_rule(self):
        """update_existing_status resolution is silently ignored for another user's rule."""
        self.client.login(username="alice", password="password123")
        bobs_rule = ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="CROSS-USER-UPDATE",
        )

        response = self._persist(
            pending_changes=[{
                "id": "1",
                "line": "CROSS-USER-UPDATE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_MALWARE,
                "order": 1,
            }],
            selected_ids=["1"],
            conflict_resolutions=[{
                "conflict_key": f"override:1:{bobs_rule.id}",
                "contradiction_type": "override_vs_existing_dominant",
                "change_id": "1",
                "existing_rule_id": bobs_rule.id,
                "action": "update_existing_status",
            }],
        )

        bobs_rule.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(bobs_rule.status, ClassificationRule.STATUS_CLEAN)

    def test_persist_disable_other_ignores_other_users_rule(self):
        """keep_new_disable_other resolution does not disable another user's rule."""
        self.client.login(username="alice", password="password123")
        bobs_rule = ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="CROSS-USER-DISABLE",
        )

        response = self._persist(
            pending_changes=[{
                "id": "1",
                "line": "CROSS-USER-DISABLE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_CLEAN,
                "order": 1,
            }],
            selected_ids=["1"],
            conflict_resolutions=[{
                "conflict_key": f"override:1:{bobs_rule.id}",
                "contradiction_type": "override_vs_existing_dominant",
                "change_id": "1",
                "existing_rule_id": bobs_rule.id,
                "action": "keep_new_disable_other",
            }],
        )

        bobs_rule.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(bobs_rule.is_enabled)

    def test_persist_update_existing_status_works_for_own_rule(self):
        """update_existing_status correctly updates the requesting user's own rule."""
        self.client.login(username="alice", password="password123")
        alices_rule = ClassificationRule.objects.create(
            owner=self.alice,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="OWN-RULE-UPDATE",
        )

        response = self._persist(
            pending_changes=[{
                "id": "1",
                "line": "OWN-RULE-UPDATE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_MALWARE,
                "order": 1,
            }],
            selected_ids=["1"],
            conflict_resolutions=[{
                "conflict_key": f"override:1:{alices_rule.id}",
                "contradiction_type": "override_vs_existing_dominant",
                "change_id": "1",
                "existing_rule_id": alices_rule.id,
                "action": "update_existing_status",
            }],
        )

        alices_rule.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(alices_rule.status, ClassificationRule.STATUS_MALWARE)

    def test_persist_disable_other_works_for_own_rule(self):
        """keep_new_disable_other correctly disables the requesting user's own rule."""
        self.client.login(username="alice", password="password123")
        alices_rule = ClassificationRule.objects.create(
            owner=self.alice,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="OWN-RULE-DISABLE",
        )

        response = self._persist(
            pending_changes=[{
                "id": "1",
                "line": "OWN-RULE-DISABLE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_CLEAN,
                "order": 1,
            }],
            selected_ids=["1"],
            conflict_resolutions=[{
                "conflict_key": f"override:1:{alices_rule.id}",
                "contradiction_type": "override_vs_existing_dominant",
                "change_id": "1",
                "existing_rule_id": alices_rule.id,
                "action": "keep_new_disable_other",
            }],
        )

        alices_rule.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(alices_rule.is_enabled)

    # -- inspect_line_matches includes owner_username --

    def test_inspect_line_matches_includes_owner_username(self):
        """inspect_line_matches returns owner_username on each matching rule."""
        from ..analyzer import inspect_line_matches

        ClassificationRule.objects.create(
            owner=self.bob,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="OWNER-IN-INSPECTION",
        )

        inspection = inspect_line_matches("OWNER-IN-INSPECTION")

        self.assertTrue(inspection["matches"])
        self.assertEqual(inspection["matches"][0]["owner_username"], "bob")

