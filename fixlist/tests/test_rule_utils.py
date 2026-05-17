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
FIREWALL_LINE = (
    r"FirewallRules: [{854C03D7-A445-4A50-AA06-CA6E5F44A529}] => (Allow) "
    r"C:\Program Files\WindowsApps\MicrosoftTeams_24215.1105.3082.1600_x64__8wekyb3d8bbwe\msteams.exe "
    r"(Microsoft Corporation -> Microsoft Corporation)"
)
SCHEDULED_TASK_LINE = (
    r"Task: {CA037D06-C97D-49EF-BBBB-DF2B661CC4E6} - "
    r"System32\Tasks\NetworkDiagnosticService => "
    r"C:\Windows\system32\wscript.exe [181760 2025-05-14] "
    r"(Microsoft Windows -> Microsoft Corporation) -> "
    r'"%LOCALAPPDATA%\DiagnosticsNET\update.vbs"'
)
BHO_LINE = (
    r"BHO: Test BHO -> {AE805869-2E5C-4ED4-8F7B-F1F7851A4497} -> "
    r"C:\Program Files\Test\test.dll [12345 2024-01-01] (Test Vendor)"
)
NAMED_INSTALL_LINE = (
    r"Some Tool (HKLM-x32\...\Some Tool) (Version: 1.2.3 - Vendor)"
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

    def test_persist_firewall_rule_stores_empty_clsid(self):
        """Firewall rule GUIDs are per-system random — must not be stored."""
        self._persist(FIREWALL_LINE)
        rule = ClassificationRule.objects.get(source_text=FIREWALL_LINE)
        self.assertEqual(rule.entry_type, "firewall")
        self.assertEqual(rule.clsid, "")

    def test_persist_scheduled_task_stores_empty_clsid_and_task_path_in_name(self):
        """Scheduled-task GUIDs are per-system random (clsid must be empty);
        the task path goes into `name` so two tasks with different paths but
        the same binary don't collapse."""
        self._persist(SCHEDULED_TASK_LINE)
        rule = ClassificationRule.objects.get(source_text=SCHEDULED_TASK_LINE)
        self.assertEqual(rule.entry_type, "scheduled_task")
        self.assertEqual(rule.clsid, "")
        self.assertEqual(rule.name, r"System32\Tasks\NetworkDiagnosticService")
        self.assertEqual(
            rule.arguments,
            r'"%LOCALAPPDATA%\DiagnosticsNET\update.vbs"',
        )

    def test_persist_installed_software_with_guid_stores_empty_clsid(self):
        """MSI Product Codes are NOT captured into clsid — they may be per-
        install for third-party / PUP installers and would silently break
        cross-system matching."""
        self._persist(HIDDEN_INSTALL_LINE)
        rule = ClassificationRule.objects.get(source_text=HIDDEN_INSTALL_LINE)
        self.assertEqual(rule.entry_type, "installed_software")
        self.assertEqual(rule.clsid, "")

    def test_persist_installed_software_with_named_key_stores_empty_clsid(self):
        self._persist(NAMED_INSTALL_LINE)
        rule = ClassificationRule.objects.get(source_text=NAMED_INSTALL_LINE)
        self.assertEqual(rule.entry_type, "installed_software")
        self.assertEqual(rule.clsid, "")

    def test_persist_bho_rule_stores_semantic_clsid(self):
        """COM class IDs ARE stable across systems — must be stored for entry
        types where clsid is semantic (BHO, custom_clsid, etc.)."""
        self._persist(BHO_LINE)
        rule = ClassificationRule.objects.get(source_text=BHO_LINE)
        self.assertEqual(rule.entry_type, "bho")
        self.assertEqual(rule.clsid, "AE805869-2E5C-4ED4-8F7B-F1F7851A4497")

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
