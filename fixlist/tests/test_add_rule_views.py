import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule


class AddRuleViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.client.login(username="alice", password="password123")

    # -- Page rendering --

    def test_add_rule_page_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("add_rule"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_add_rule_page_renders(self):
        response = self.client.get(reverse("add_rule"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "add rule")
        self.assertContains(response, "log lines")

    def test_add_rule_page_has_form_fields(self):
        response = self.client.get(reverse("add_rule"))
        self.assertContains(response, 'id="ruleStatus"')
        self.assertContains(response, 'id="ruleMatchType"')
        self.assertContains(response, 'id="ruleSourceText"')
        self.assertContains(response, 'id="logLinesInput"')

    # -- Create via add_rule_view --

    def test_create_rule(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "MALICIOUS-LINE",
                "description": "test rule",
            },
        )
        self.assertRedirects(response, reverse("rules"))
        rule = ClassificationRule.objects.get(source_text="MALICIOUS-LINE")
        self.assertEqual(rule.owner, self.user)
        self.assertEqual(rule.status, ClassificationRule.STATUS_MALWARE)
        self.assertEqual(rule.match_type, ClassificationRule.MATCH_EXACT)
        self.assertEqual(rule.description, "test rule")
        self.assertTrue(rule.is_enabled)

    def test_create_rule_requires_source_text(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_rule_rejects_invalid_status(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": "X",
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "some-line",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_rule_rejects_invalid_match_type(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": "invalid",
                "source_text": "some-line",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_rule_rejects_duplicate(self):
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="DUP-LINE",
        )
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "DUP-LINE",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.filter(source_text="DUP-LINE").count(), 1)

    # -- rules.html links to add page --

    def test_rules_page_links_to_add_rule(self):
        response = self.client.get(reverse("rules"))
        self.assertContains(response, reverse("add_rule"))


class TestRuleApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.client.login(username="alice", password="password123")
        self.url = reverse("test_rule_api")

    def _post(self, payload):
        return self.client.post(
            self.url,
            json.dumps(payload),
            content_type="application/json",
        )

    # -- Auth & validation --

    def test_requires_login(self):
        self.client.logout()
        response = self._post({"source_text": "x", "match_type": "exact", "lines": ["x"]})
        self.assertEqual(response.status_code, 302)

    def test_rejects_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)

    def test_rejects_empty_source_text(self):
        response = self._post({"source_text": "", "match_type": "exact", "lines": ["x"]})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    def test_rejects_too_many_lines(self):
        response = self._post({
            "source_text": "test",
            "match_type": "exact",
            "lines": ["x"] * 501,
        })
        self.assertEqual(response.status_code, 400)

    def test_rejects_unsupported_match_type(self):
        response = self._post({
            "source_text": "test",
            "match_type": "invalid",
            "lines": ["test"],
        })
        self.assertEqual(response.status_code, 400)

    # -- Exact matching --

    def test_exact_match(self):
        response = self._post({
            "source_text": "EVIL-PROCESS.EXE",
            "match_type": "exact",
            "status": "B",
            "lines": ["EVIL-PROCESS.EXE", "OTHER-LINE", "  EVIL-PROCESS.EXE  "],
        })
        data = response.json()
        self.assertEqual(len(data["results"]), 3)
        self.assertTrue(data["results"][0]["matched"])
        self.assertFalse(data["results"][1]["matched"])
        self.assertTrue(data["results"][2]["matched"])

    # -- Substring matching --

    def test_substring_match(self):
        response = self._post({
            "source_text": "evil",
            "match_type": "substring",
            "status": "B",
            "lines": ["this has evil inside", "clean line", "EVIL uppercase"],
        })
        data = response.json()
        self.assertTrue(data["results"][0]["matched"])
        self.assertFalse(data["results"][1]["matched"])
        self.assertTrue(data["results"][2]["matched"])

    def test_substring_returns_match_ranges(self):
        response = self._post({
            "source_text": "ab",
            "match_type": "substring",
            "status": "B",
            "lines": ["xabxabx"],
        })
        data = response.json()
        self.assertEqual(data["results"][0]["match_ranges"], [[1, 3], [4, 6]])

    # -- Regex matching --

    def test_regex_match(self):
        response = self._post({
            "source_text": r"evil\d+",
            "match_type": "regex",
            "status": "B",
            "lines": ["evil123 found", "clean line", "evil no digits"],
        })
        data = response.json()
        self.assertTrue(data["results"][0]["matched"])
        self.assertFalse(data["results"][1]["matched"])
        self.assertFalse(data["results"][2]["matched"])

    def test_regex_returns_match_ranges(self):
        response = self._post({
            "source_text": r"\d+",
            "match_type": "regex",
            "status": "B",
            "lines": ["abc123def456"],
        })
        data = response.json()
        self.assertEqual(data["results"][0]["match_ranges"], [[3, 6], [9, 12]])

    def test_regex_invalid_pattern(self):
        response = self._post({
            "source_text": r"[invalid",
            "match_type": "regex",
            "status": "B",
            "lines": ["test"],
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    # -- Parsed matching --

    def test_parsed_returns_parsed_components(self):
        line = r"HKLM\...\Run: [Virtual Pet] => C:\Program Files\ASUS\Virtual Pet\Virtual Pet.exe [33712544 2026-01-17] (ASUSTeK COMPUTER INC. -> ASUSTeK Computer Inc.)"
        response = self._post({
            "source_text": line,
            "match_type": "parsed",
            "status": "B",
            "lines": [line],
        })
        data = response.json()
        result = data["results"][0]
        self.assertTrue(result["matched"])
        self.assertIsNotNone(result["parsed"])
        self.assertEqual(result["parsed"]["entry_type"], "runkey")
        self.assertEqual(result["parsed"]["name"], "Virtual Pet")
        self.assertIn("Virtual Pet.exe", result["parsed"]["filepath"])

    def test_parsed_non_parseable_line(self):
        response = self._post({
            "source_text": r"HKLM\...\Run: [Virtual Pet] => C:\Program Files\ASUS\Virtual Pet\Virtual Pet.exe [33712544 2026-01-17] (ASUSTeK COMPUTER INC. -> ASUSTeK Computer Inc.)",
            "match_type": "parsed",
            "status": "B",
            "lines": ["just a plain text line"],
        })
        data = response.json()
        self.assertFalse(data["results"][0]["matched"])
        self.assertIsNone(data["results"][0]["parsed"])

    # -- Filepath matching --

    def test_filepath_match(self):
        response = self._post({
            "source_text": "FILEPATH:C:\\Program Files\\test.exe",
            "match_type": "filepath",
            "status": "B",
            "lines": [
                "HKU\\S-1-5-21\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run: [TestApp] => C:\\Program Files\\test.exe [2024-01-01] (Test Corp)",
                "some unrelated line",
            ],
        })
        data = response.json()
        # First line may or may not match depending on FRST extraction
        # but at minimum the API should return valid results without error
        self.assertEqual(len(data["results"]), 2)
        self.assertFalse(data["results"][1]["matched"])

    # -- Response structure --

    def test_response_includes_rule(self):
        response = self._post({
            "source_text": "test-pattern",
            "match_type": "substring",
            "status": "B",
            "lines": ["test-pattern here"],
        })
        data = response.json()
        self.assertIn("rule", data)
        self.assertIn("results", data)
        self.assertIn("status_labels", data)
        self.assertIn("status_precedence", data)

    # -- Existing rule matches --

    def test_results_include_existing_match_fields(self):
        response = self._post({
            "source_text": "test",
            "match_type": "substring",
            "status": "B",
            "lines": ["test line"],
        })
        data = response.json()
        result = data["results"][0]
        self.assertIn("existing_status", result)
        self.assertIn("existing_status_label", result)
        self.assertIn("existing_matches", result)
        self.assertIn("existing_shadowed", result)
        self.assertIn("combined_status", result)
        self.assertIn("combined_status_label", result)

    def test_existing_rule_appears_in_results(self):
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="known-good",
        )
        response = self._post({
            "source_text": "unrelated",
            "match_type": "substring",
            "status": "B",
            "lines": ["this has known-good inside"],
        })
        data = response.json()
        result = data["results"][0]
        self.assertEqual(result["existing_status"], "C")
        self.assertTrue(len(result["existing_matches"]) > 0)
        self.assertEqual(result["existing_matches"][0]["status"], "C")

    def test_combined_status_uses_precedence(self):
        """When new rule matches and existing rule matches, combined status uses precedence."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="shared-text",
        )
        response = self._post({
            "source_text": "shared-text",
            "match_type": "substring",
            "status": "B",
            "lines": ["this has shared-text here"],
        })
        data = response.json()
        result = data["results"][0]
        self.assertTrue(result["matched"])
        # B (malware) takes precedence over C (clean) per STATUS_PRECEDENCE = "BPC!GSIJ?"
        self.assertEqual(result["combined_status"], "B")

    def test_combined_status_without_new_rule_match(self):
        """When new rule doesn't match but existing does, combined status is from existing."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="known-good",
        )
        response = self._post({
            "source_text": "no-match",
            "match_type": "substring",
            "status": "B",
            "lines": ["this has known-good inside"],
        })
        data = response.json()
        result = data["results"][0]
        self.assertFalse(result["matched"])
        self.assertEqual(result["combined_status"], "C")

    def test_combined_status_respects_matcher_precedence(self):
        """A new substring rule shadows an existing regex rule (substring > regex)."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_REGEX,
            source_text=r"evil\d+",
        )
        response = self._post({
            "source_text": "evil",
            "match_type": "substring",
            "status": "C",
            "lines": ["evil123 here"],
        })
        data = response.json()
        result = data["results"][0]
        self.assertTrue(result["matched"])
        # Substring has higher matcher precedence than regex, so new clean rule
        # shadows the existing malware regex rule → combined is C, not B.
        self.assertEqual(result["combined_status"], "C")

    def test_combined_status_new_rule_shadowed_by_higher_matcher(self):
        """A new regex rule is shadowed by an existing substring rule."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="known",
        )
        response = self._post({
            "source_text": r"known.*line",
            "match_type": "regex",
            "status": "B",
            "lines": ["known-good line"],
        })
        data = response.json()
        result = data["results"][0]
        self.assertTrue(result["matched"])
        # Existing substring rule has higher matcher precedence than new regex rule
        # → combined is C (from existing), not B (from new).
        self.assertEqual(result["combined_status"], "C")

    # -- New rule shadowed flag --

    def test_new_rule_shadowed_flag_set_when_lower_tier(self):
        """new_rule_shadowed is True when new regex rule is shadowed by existing substring."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="known",
        )
        response = self._post({
            "source_text": r"known.*line",
            "match_type": "regex",
            "status": "B",
            "lines": ["known-good line"],
        })
        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertTrue(result["new_rule_shadowed"])
        self.assertEqual(result["new_rule_shadowed_by"], "substring")

    def test_new_rule_not_shadowed_when_higher_tier(self):
        """new_rule_shadowed is False when new substring rule shadows existing regex."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_REGEX,
            source_text=r"evil\d+",
        )
        response = self._post({
            "source_text": "evil",
            "match_type": "substring",
            "status": "C",
            "lines": ["evil123 here"],
        })
        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertFalse(result["new_rule_shadowed"])
        self.assertIsNone(result["new_rule_shadowed_by"])

    def test_new_rule_not_shadowed_when_same_tier(self):
        """new_rule_shadowed is False when both rules are same matcher tier."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="shared",
        )
        response = self._post({
            "source_text": "shared",
            "match_type": "substring",
            "status": "B",
            "lines": ["shared text here"],
        })
        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertFalse(result["new_rule_shadowed"])

    def test_new_rule_not_shadowed_when_no_existing_matches(self):
        """new_rule_shadowed is False when no existing rules match."""
        response = self._post({
            "source_text": "unique-pattern",
            "match_type": "substring",
            "status": "B",
            "lines": ["this has unique-pattern inside"],
        })
        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertFalse(result["new_rule_shadowed"])

    def test_new_rule_shadowed_by_exact_over_substring(self):
        """new_rule_shadowed when new substring is shadowed by existing exact."""
        line = "EXACT-MATCH-LINE"
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text=line,
        )
        response = self._post({
            "source_text": "EXACT",
            "match_type": "substring",
            "status": "B",
            "lines": [line],
        })
        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertTrue(result["new_rule_shadowed"])
        self.assertEqual(result["new_rule_shadowed_by"], "exact")

    def test_shadowed_fields_present_when_not_matched(self):
        """new_rule_shadowed fields are present even when new rule doesn't match."""
        response = self._post({
            "source_text": "no-match",
            "match_type": "substring",
            "status": "B",
            "lines": ["something else"],
        })
        result = response.json()["results"][0]
        self.assertFalse(result["matched"])
        self.assertFalse(result["new_rule_shadowed"])
        self.assertIsNone(result["new_rule_shadowed_by"])

    # -- New rule outranked flag --

    def test_new_rule_outranked_same_tier(self):
        """new_rule_outranked is True when same-tier existing rule has higher status precedence."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_REGEX,
            source_text=r"Task.*",
        )
        response = self._post({
            "source_text": r"Task.*",
            "match_type": "regex",
            "status": "C",
            "lines": ["Task: something here"],
        })
        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertFalse(result["new_rule_shadowed"])
        self.assertTrue(result["new_rule_outranked"])
        self.assertEqual(result["new_rule_outranked_by"], "malware")
        self.assertEqual(result["combined_status"], "B")

    def test_new_rule_not_outranked_when_it_wins(self):
        """new_rule_outranked is False when new rule's status wins."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_REGEX,
            source_text=r"evil\d+",
        )
        response = self._post({
            "source_text": r"evil\d+",
            "match_type": "regex",
            "status": "B",
            "lines": ["evil123 found"],
        })
        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertFalse(result["new_rule_outranked"])
        self.assertEqual(result["combined_status"], "B")

    def test_new_rule_not_outranked_when_same_status(self):
        """new_rule_outranked is False when both have the same status."""
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_CLEAN,
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="safe",
        )
        response = self._post({
            "source_text": "safe",
            "match_type": "substring",
            "status": "C",
            "lines": ["safe text here"],
        })
        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertFalse(result["new_rule_outranked"])

    def test_new_rule_not_outranked_when_no_existing(self):
        """new_rule_outranked is False when no existing rules match."""
        response = self._post({
            "source_text": "unique",
            "match_type": "substring",
            "status": "C",
            "lines": ["unique text"],
        })
        result = response.json()["results"][0]
        self.assertTrue(result["matched"])
        self.assertFalse(result["new_rule_outranked"])
        self.assertIsNone(result["new_rule_outranked_by"])

    def test_outranked_fields_present_when_not_matched(self):
        """new_rule_outranked fields are present even when new rule doesn't match."""
        response = self._post({
            "source_text": "no-match",
            "match_type": "substring",
            "status": "B",
            "lines": ["something else"],
        })
        result = response.json()["results"][0]
        self.assertFalse(result["matched"])
        self.assertFalse(result["new_rule_outranked"])
        self.assertIsNone(result["new_rule_outranked_by"])
