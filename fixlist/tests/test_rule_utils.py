"""Regression tests for the rule-creation path used by the analyzer UI.

Bug history: `_rule_defaults_from_parsed` was missing `attributes` and
`is_hidden` in its defaults dict, so every rule created via
`persist_pending_rule_changes_api` (the analyzer "save selected changes"
flow) ended up with `attributes=""` and `is_hidden=False` regardless of what
the parser actually produced. That broke FrstEntry equality at match time —
the rule's stored entry no longer compared equal to freshly-parsed log lines,
and only the filepath bucket would fire.
"""

import json

from django.urls import reverse

from ..analyzer import parse_rule_line
from ..models import ClassificationRule
from ..rule_utils import _rule_defaults_from_parsed
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase


ONEMONTH_LINE = (
    r"2026-05-02 05:29 - 2020-03-22 01:30 - 000000000 ____D "
    r"C:\Program Files (x86)\LightingService"
)
HIDDEN_INSTALL_LINE = (
    r"Adobe AIR (HKLM-x32\...\{10E33ABF-D7FB-4F47-900A-7973854AB45A}) "
    r"(Version: 32.0.0.144 - Adobe) Hidden"
)


class RuleDefaultsFromParsedTests(LogAnalyzerApiBaseTestCase):
    """Direct unit tests for the helper that builds rule defaults."""

    def test_defaults_include_attributes(self):
        parsed = parse_rule_line(
            ONEMONTH_LINE,
            status=ClassificationRule.STATUS_MALWARE,
        )
        defaults = _rule_defaults_from_parsed(parsed)
        self.assertEqual(defaults["attributes"], "____D")

    def test_defaults_include_is_hidden(self):
        parsed = parse_rule_line(
            HIDDEN_INSTALL_LINE,
            status=ClassificationRule.STATUS_MALWARE,
        )
        defaults = _rule_defaults_from_parsed(parsed)
        self.assertTrue(defaults["is_hidden"])

    def test_defaults_is_hidden_false_for_non_hidden_line(self):
        parsed = parse_rule_line(
            ONEMONTH_LINE,
            status=ClassificationRule.STATUS_MALWARE,
        )
        defaults = _rule_defaults_from_parsed(parsed)
        self.assertFalse(defaults["is_hidden"])


class PersistPendingRuleChangesStoresParsedFieldsTests(LogAnalyzerApiBaseTestCase):
    """End-to-end coverage via the analyzer-UI API endpoint."""

    def _persist(self, line, new_status=ClassificationRule.STATUS_MALWARE):
        self.client.login(username="analyzer", password="password123")
        payload = {
            "pending_changes": [
                {
                    "id": "1",
                    "line": line,
                    "original_status": "?",
                    "new_status": new_status,
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
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])

    def test_persist_stores_attributes_for_onemonth_directory_line(self):
        self._persist(ONEMONTH_LINE)
        rule = ClassificationRule.objects.get(source_text=ONEMONTH_LINE)
        self.assertEqual(rule.match_type, ClassificationRule.MATCH_PARSED_ENTRY)
        self.assertEqual(rule.entry_type, "onemonth")
        self.assertEqual(rule.attributes, "____D")
        self.assertFalse(rule.is_hidden)

    def test_persist_stores_is_hidden_for_hidden_installed_software(self):
        self._persist(HIDDEN_INSTALL_LINE)
        rule = ClassificationRule.objects.get(source_text=HIDDEN_INSTALL_LINE)
        self.assertEqual(rule.entry_type, "installed_software")
        self.assertTrue(rule.is_hidden)

    def test_persisted_onemonth_rule_matches_via_parsed_entry(self):
        """The whole point of the bug fix: after persisting an onemonth rule,
        re-analyzing the same line must classify it (proves the parsed-entry
        bucket fires, not just the filepath fallback)."""
        self._persist(ONEMONTH_LINE)
        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": ONEMONTH_LINE}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        line_result = response.json()["lines"][0]
        self.assertEqual(
            line_result["dominant_status"],
            ClassificationRule.STATUS_MALWARE,
        )


class PreviewPendingRuleChangesIncludesParsedFieldsTests(LogAnalyzerApiBaseTestCase):
    """The preview endpoint must surface attributes/is_hidden in rule_changes
    so the UI can show what's about to be stored."""

    def test_preview_rule_changes_includes_attributes_and_is_hidden(self):
        self.client.login(username="analyzer", password="password123")
        payload = {
            "pending_changes": [
                {
                    "id": "1",
                    "line": ONEMONTH_LINE,
                    "original_status": "?",
                    "new_status": ClassificationRule.STATUS_MALWARE,
                    "order": 1,
                },
                {
                    "id": "2",
                    "line": HIDDEN_INSTALL_LINE,
                    "original_status": "?",
                    "new_status": ClassificationRule.STATUS_PUP,
                    "order": 2,
                },
            ],
        }
        response = self.client.post(
            reverse("preview_pending_rule_changes_api"),
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        rule_changes = {rc["id"]: rc for rc in response.json()["rule_changes"]}
        self.assertEqual(rule_changes["1"]["attributes"], "____D")
        self.assertFalse(rule_changes["1"]["is_hidden"])
        self.assertEqual(rule_changes["2"]["attributes"], "")
        self.assertTrue(rule_changes["2"]["is_hidden"])
