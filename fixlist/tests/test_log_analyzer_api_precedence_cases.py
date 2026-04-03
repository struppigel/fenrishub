import json

from django.urls import reverse

from ..analyzer import inspect_line_matches, parse_rule_line
from ..models import ClassificationRule, ParsedFilepathExclusion
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase


class LogAnalyzerApiPrecedenceTests(LogAnalyzerApiBaseTestCase):

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

    def test_parse_rule_line_keeps_parsed_entry_match_type_for_service_lines(self):
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

    def test_match_type_precedence_parsed_over_substring(self):
        """Parsed entry match takes precedence over a substring match on the same line."""
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
