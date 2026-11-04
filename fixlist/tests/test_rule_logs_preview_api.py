import json
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import UploadedLog
from .factories import make_rule, make_uploaded_log, make_user


class RuleLogsPreviewApiTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.login(username="alice", password="password123")
        self.url = reverse("test_rule_logs_api")

    def _post(self, payload):
        return self.client.post(self.url, json.dumps(payload), content_type="application/json")

    def _lines_by_text(self, data):
        return {result["line"]: result for result in data["results"]}

    # -- Auth & validation --

    def test_requires_login(self):
        self.client.logout()
        response = self._post({"source_text": "x", "match_type": "substring"})
        self.assertEqual(response.status_code, 302)

    def test_rejects_get(self):
        self.assertEqual(self.client.get(self.url).status_code, 405)

    def test_rejects_empty_source_text(self):
        response = self._post({"source_text": "", "match_type": "substring"})
        self.assertEqual(response.status_code, 400)

    def test_rejects_invalid_regex(self):
        make_uploaded_log("log-a", content="anything")
        response = self._post({"source_text": "(unclosed", "match_type": "regex"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    def test_script_rules_need_a_moderator(self):
        response = self._post({"source_text": "result = True", "match_type": "script"})
        self.assertEqual(response.status_code, 403)

    def test_refuses_slow_regex(self):
        make_uploaded_log("log-a", content="anything")
        slow = {
            "stdlib_ok": True, "stdlib_error": None, "re2_ok": False, "re2_error": "x",
            "is_slow": True, "worst_ms": 900.0, "worst_input": "aaaa",
        }
        with patch("fixlist.views.rules.evaluate_regex_pattern", return_value=slow):
            response = self._post({"source_text": "a+b", "match_type": "regex"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("too slow", response.json()["error"])

    # -- Matching --

    def test_collapses_identical_lines_across_logs(self):
        make_uploaded_log("log-a", content="header\nC:\\evil\\evil.exe\nfooter")
        make_uploaded_log("log-b", content="C:\\evil\\evil.exe\nC:\\evil\\evil.exe\nother")
        make_uploaded_log("log-c", content="nothing here")

        data = self._post({"source_text": "evil.exe", "match_type": "substring", "status": "B"}).json()

        self.assertEqual(len(data["results"]), 1)
        result = data["results"][0]
        self.assertTrue(result["matched"])
        self.assertEqual(result["line"], "C:\\evil\\evil.exe")
        self.assertEqual(result["log_count"], 2)
        refs = {ref["upload_id"]: ref["line_number"] for ref in result["logs"]}
        self.assertEqual(refs, {"log-a": 2, "log-b": 1})
        self.assertEqual(result["match_ranges"], [[8, 16]])
        self.assertEqual(data["logs_scanned"], 3)
        self.assertEqual(data["logs_matched"], 2)
        self.assertFalse(data["truncated"])
        self.assertFalse(data["timed_out"])

    def test_most_widespread_line_comes_first(self):
        make_uploaded_log("log-a", content="evil one")
        make_uploaded_log("log-b", content="evil two")
        make_uploaded_log("log-c", content="evil two")

        data = self._post({"source_text": "evil", "match_type": "substring"}).json()

        self.assertEqual([r["line"] for r in data["results"]], ["evil two", "evil one"])

    def test_exact_match_ignores_surrounding_whitespace(self):
        make_uploaded_log("log-a", content="  EVIL-PROCESS.EXE  \r\nEVIL-PROCESS.EXE.bak")

        data = self._post({"source_text": "EVIL-PROCESS.EXE", "match_type": "exact"}).json()

        self.assertEqual([r["line"] for r in data["results"]], ["EVIL-PROCESS.EXE"])

    def test_skips_trashed_logs(self):
        make_uploaded_log("log-a", content="evil", deleted_at=timezone.now())

        data = self._post({"source_text": "evil", "match_type": "substring"}).json()

        self.assertEqual(data["results"], [])
        self.assertEqual(data["logs_scanned"], 0)

    def test_skips_logs_sent_to_another_helper(self):
        other = make_user("bob")
        make_uploaded_log("log-bob", content="evil", recipient_user=other)
        make_uploaded_log("log-mine", content="evil", recipient_user=self.user)

        data = self._post({"source_text": "evil", "match_type": "substring"}).json()

        self.assertEqual([ref["upload_id"] for ref in data["results"][0]["logs"]], ["log-mine"])

    def test_reports_existing_rules_on_matched_lines(self):
        make_uploaded_log("log-a", content="evil.exe")
        make_rule("evil.exe", status="C", match_type="exact")

        data = self._post({"source_text": "evil", "match_type": "substring", "status": "B"}).json()

        result = self._lines_by_text(data)["evil.exe"]
        self.assertEqual(result["existing_status"], "C")
        self.assertEqual(len(result["existing_matches"]), 1)

    def test_excludes_the_rule_being_edited(self):
        make_uploaded_log("log-a", content="evil.exe")
        rule = make_rule("evil.exe", status="B", match_type="exact", owner=self.user)

        data = self._post({
            "source_text": "evil.exe", "match_type": "exact", "status": "B",
            "exclude_rule_id": rule.pk,
        }).json()

        self.assertEqual(data["results"][0]["existing_matches"], [])

    # -- Limits --

    def test_stops_after_max_distinct_lines(self):
        make_uploaded_log("log-a", content="evil 1\nevil 2\nevil 3")

        with patch("fixlist.views.rules.LOG_PREVIEW_MAX_LINES", 2):
            data = self._post({"source_text": "evil", "match_type": "substring"}).json()

        self.assertEqual(len(data["results"]), 2)
        self.assertTrue(data["truncated"])

    def test_scans_only_the_newest_logs(self):
        make_uploaded_log("log-old", content="evil old")
        make_uploaded_log("log-new", content="evil new")
        # auto_now_add ignores a passed value, and two quick creates can share a tick.
        UploadedLog.objects.filter(upload_id="log-old").update(
            created_at=timezone.now() - timedelta(days=1)
        )

        with patch("fixlist.views.rules.LOG_PREVIEW_MAX_LOGS", 1):
            data = self._post({"source_text": "evil", "match_type": "substring"}).json()

        self.assertEqual([r["line"] for r in data["results"]], ["evil new"])
        self.assertEqual(data["max_logs"], 1)

    def test_reports_running_out_of_time(self):
        make_uploaded_log("log-a", content="evil")

        with patch("fixlist.views.rules.LOG_PREVIEW_TIME_BUDGET_S", -1):
            data = self._post({"source_text": "evil", "match_type": "substring"}).json()

        self.assertTrue(data["timed_out"])
        self.assertEqual(data["logs_scanned"], 0)

    # -- Whole-log alerts --

    def test_whole_log_rule_lists_the_logs_it_fires_on(self):
        make_uploaded_log("log-a", content="first\nevil\nevil again")
        make_uploaded_log("log-b", content="clean")

        data = self._post({
            "source_text": "evil", "match_type": "regex", "status": "A", "whole_log": True,
        }).json()

        self.assertTrue(data["whole_log"])
        self.assertEqual(data["logs"], [{"upload_id": "log-a", "match_count": 2}])
        self.assertEqual(data["logs_scanned"], 2)

    def test_whole_log_rejects_other_match_types(self):
        response = self._post({
            "source_text": "evil", "match_type": "substring", "status": "A", "whole_log": True,
        })
        self.assertEqual(response.status_code, 400)


class RuleEditorLogPreviewPanelTests(TestCase):
    def setUp(self):
        make_user()
        self.client.login(username="alice", password="password123")

    def test_add_page_offers_the_log_preview(self):
        response = self.client.get(reverse("add_rule"))
        self.assertContains(response, 'id="logMatchesToggle"')
        self.assertContains(response, reverse("test_rule_logs_api"))
