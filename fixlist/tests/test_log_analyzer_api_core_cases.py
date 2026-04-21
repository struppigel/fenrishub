import json

from django.urls import reverse

from ..models import ClassificationRule, UploadedLog
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase


class LogAnalyzerApiCoreTests(LogAnalyzerApiBaseTestCase):

    def test_endpoints_require_login(self):
        uploaded = UploadedLog.objects.create(
            upload_id='rapid-trail',
            reddit_username='reddit_name',
            original_filename='content.txt',
            content='line-1',
        )
        cases = [
            ('analyze_log_api', 'post',
             reverse('analyze_log_api'), '{"log":"line"}'),
            ('uploaded_log_content_api', 'get',
             reverse('uploaded_log_content_api', args=[uploaded.upload_id]), None),
            ('analyze_line_details_api', 'post',
             reverse('analyze_line_details_api'),
             json.dumps({"line": "example", "status": "?"})),
        ]
        for label, method, url, body in cases:
            with self.subTest(endpoint=label):
                if method == 'post':
                    response = self.client.post(url, data=body, content_type='application/json')
                else:
                    response = self.client.get(url)
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

    def test_uploaded_log_content_api_allows_viewing_other_helper_channel_upload(self):
        """All logged-in users can view logs assigned to other helpers."""
        self.client.login(username='analyzer', password='password123')
        uploaded = UploadedLog.objects.create(
            upload_id='private-rapid-trail',
            reddit_username='reddit_name',
            original_filename='content.txt',
            content='line-1\nline-2',
            recipient_user=self.other_user,
        )

        response = self.client.get(reverse('uploaded_log_content_api', args=[uploaded.upload_id]))
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(payload['upload_id'], 'private-rapid-trail')
        self.assertEqual(payload['content'], 'line-1\nline-2')

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
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="CONFLICT-LINE",
            description="existing clean exact",
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
