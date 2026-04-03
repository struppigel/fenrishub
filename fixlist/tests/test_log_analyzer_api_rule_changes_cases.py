import json

from django.urls import reverse

from ..models import ClassificationRule
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase


class LogAnalyzerApiRuleChangeTests(LogAnalyzerApiBaseTestCase):

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
