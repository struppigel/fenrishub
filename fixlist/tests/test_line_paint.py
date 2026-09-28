"""How the analyzer colours a line: every matching rule paints it, lowest priority
first, so the highest priority ends up on top. Substring and file path rules
paint only what they matched unless they opt into `color_whole_line`; every other
rule paints the whole line. The verdict (dominant_status) is unaffected -- it
still comes from the winning priority tier alone."""

import json
from unittest import mock

from django.urls import reverse

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT, analyze_log_text, parse_rule_line
from ..models import ClassificationRule
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

B = ClassificationRule.STATUS_MALWARE
C = ClassificationRule.STATUS_CLEAN
W = ClassificationRule.STATUS_WARNING

SERVICE_LINE = (
    r"R3 ProtoVPN Service; C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe "
    r"[477424 2026-03-06] (Proto AG -> ProtoVPN)"
)
SERVICE_PATH = r"C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe"
# A different line carrying the same path, so a parsed rule for SERVICE_LINE
# matches it only through the path (the filepath fallback).
PATH_LINE = r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 ____D " + SERVICE_PATH


class LinePaintTests(LogAnalyzerApiBaseTestCase):

    def _rule(self, source_text, status=B, match_type=ClassificationRule.MATCH_SUBSTRING, **overrides):
        return ClassificationRule.objects.create(
            owner=self.user, status=status, match_type=match_type, source_text=source_text, **overrides,
        )

    def _filepath_rule(self, status=B, **overrides):
        return self._rule(
            SERVICE_PATH, status=status, match_type=ClassificationRule.MATCH_FILEPATH,
            filepath=SERVICE_PATH, normalized_filepath=SERVICE_PATH.lower(), **overrides,
        )

    def _parsed_rule_for_service_line(self, status=B):
        parsed = parse_rule_line(SERVICE_LINE, status=status, source_name="test-suite")
        return ClassificationRule.objects.create(owner=self.user, **parsed)

    def _analyze_line(self, line):
        return analyze_log_text(line)["lines"][0]

    @staticmethod
    def _spans(result):
        return [(h["start"], h["end"], h["status"], h["priority"]) for h in result["highlights"]]

    # -- substring rules --

    def test_new_rules_default_to_matched_part_only(self):
        self.assertFalse(self._rule("evil").color_whole_line)

    def test_substring_rule_colours_only_the_match(self):
        self.client.login(username="analyzer", password="password123")
        self._rule("evil.example")
        line = "Hosts: 1.2.3.4 evil.example"

        response = self.client.post(
            reverse("analyze_log_api"), data=json.dumps({"log": line}), content_type="application/json",
        )

        payload = response.json()
        result = payload["lines"][0]
        self.assertEqual(payload["format"], ANALYSIS_PAYLOAD_FORMAT)
        self.assertEqual(result["dominant_status"], B)
        self.assertEqual(result["verdict_priority"], 7)
        self.assertEqual(result["css_class"], "status-unknown")
        self.assertIsNone(result["paint_base"])
        start = line.index("evil.example")
        self.assertEqual(
            result["highlights"],
            [{"start": start, "end": start + len("evil.example"), "status": B, "priority": 7}],
        )
        self.assertFalse(result["fallback_only"])

    def test_every_occurrence_is_coloured(self):
        self._rule("bad")

        result = self._analyze_line("bad and more bad")

        self.assertEqual(self._spans(result), [(0, 3, B, 7), (13, 16, B, 7)])

    def test_color_whole_line_colours_the_whole_line(self):
        self._rule("evil", color_whole_line=True)

        result = self._analyze_line("some evil line")

        self.assertEqual(result["css_class"], "status-b")
        self.assertEqual(result["paint_base"], {"status": B, "priority": 7})
        self.assertEqual(result["highlights"], [])

    def test_each_match_keeps_its_own_status(self):
        self._rule("Microsoft", status=C)
        self._rule("evil.exe")

        result = self._analyze_line("Microsoft loads evil.exe")

        self.assertEqual(result["dominant_status"], B)
        self.assertEqual(self._spans(result), [(0, 9, C, 7), (16, 24, B, 7)])

    # -- layering --

    def test_partial_match_paints_over_a_lower_whole_line_rule(self):
        self._rule("some", status=W, match_type=ClassificationRule.MATCH_REGEX, priority=3)
        self._rule("evil.exe")

        result = self._analyze_line("some evil.exe line")

        self.assertEqual(result["dominant_status"], B)  # the verdict tier is priority 7
        self.assertEqual(result["css_class"], "status-w")  # the regex still colours the line
        self.assertEqual(result["paint_base"], {"status": W, "priority": 3})
        self.assertEqual(self._spans(result), [(5, 13, B, 7)])

    def test_higher_whole_line_rule_hides_a_lower_partial_one(self):
        line = "some evil.exe line"
        self._rule(line, status=C, match_type=ClassificationRule.MATCH_EXACT)
        self._rule("evil.exe")

        result = self._analyze_line(line)

        self.assertEqual(result["dominant_status"], C)
        self.assertEqual(result["css_class"], "status-c")
        self.assertEqual(result["highlights"], [])

    def test_a_tie_puts_the_stronger_status_on_top(self):
        self._rule("line", status=C, color_whole_line=True)
        self._rule("evil")

        result = self._analyze_line("some evil line")

        # Same priority: the malware span is painted after the clean line colour.
        self.assertEqual(result["css_class"], "status-c")
        self.assertEqual(self._spans(result), [(5, 9, B, 7)])

    def test_a_tie_can_hide_the_weaker_partial_match(self):
        self._rule("line", status=B, color_whole_line=True)
        self._rule("evil", status=C)

        result = self._analyze_line("some evil line")

        self.assertEqual(result["css_class"], "status-b")
        self.assertEqual(result["highlights"], [])

    def test_overlap_at_one_priority_goes_to_the_stronger_status(self):
        self._rule("abcdef", status=C)
        self._rule("cd")

        result = self._analyze_line("xabcdefx")

        self.assertEqual(self._spans(result), [(1, 3, C, 7), (3, 5, B, 7), (5, 7, C, 7)])

    def test_overlap_goes_to_the_higher_priority_even_with_a_weaker_status(self):
        self._rule("abcdef", status=C, priority=9)
        self._rule("cd")

        result = self._analyze_line("xabcdefx")

        self.assertEqual(result["dominant_status"], C)
        self.assertEqual(self._spans(result), [(1, 7, C, 9)])

    def test_whole_log_rules_do_not_paint(self):
        self._rule("evil", status=ClassificationRule.STATUS_ALERT,
                   match_type=ClassificationRule.MATCH_REGEX, whole_log=True)
        self._rule("evil")

        result = self._analyze_line("some evil line")

        self.assertEqual(result["css_class"], "status-unknown")
        self.assertEqual(self._spans(result), [(5, 9, B, 7)])

    # -- file paths --

    def test_file_path_rule_colours_only_the_path(self):
        self._filepath_rule()

        result = self._analyze_line(PATH_LINE)

        self.assertEqual(result["matcher"], "filepath")
        self.assertEqual(result["dominant_status"], B)
        self.assertEqual(result["css_class"], "status-unknown")
        self.assertFalse(result["fallback_only"])
        self.assertEqual(self._spans(result), [(PATH_LINE.index("C:\\"), len(PATH_LINE), B, 11)])

    def test_file_path_rule_with_color_whole_line_colours_the_whole_line(self):
        self._filepath_rule(color_whole_line=True)

        result = self._analyze_line(PATH_LINE)

        self.assertEqual(result["css_class"], "status-b")
        self.assertEqual(result["highlights"], [])

    def test_file_path_rule_colours_the_whole_line_when_the_path_cannot_be_located(self):
        self._filepath_rule()

        with mock.patch("fixlist.analyzer._locate_line_path", return_value=None):
            result = self._analyze_line(PATH_LINE)

        self.assertEqual(result["css_class"], "status-b")
        self.assertEqual(result["highlights"], [])

    def test_fallback_paints_nothing_when_the_path_cannot_be_located(self):
        self._parsed_rule_for_service_line()

        with mock.patch("fixlist.analyzer._locate_line_path", return_value=None):
            result = self._analyze_line(PATH_LINE)

        self.assertEqual(result["dominant_status"], B)
        self.assertTrue(result["fallback_only"])
        self.assertEqual(result["css_class"], "status-unknown")
        self.assertEqual(result["highlights"], [])

    def test_fallback_paints_its_path_over_a_priority_zero_rule(self):
        self._parsed_rule_for_service_line()
        self._rule("ProtoVPN", status=W, match_type=ClassificationRule.MATCH_REGEX, priority=0)

        result = self._analyze_line(PATH_LINE)

        self.assertEqual(result["dominant_status"], B)
        self.assertEqual(result["verdict_priority"], 1)
        self.assertTrue(result["fallback_only"])
        self.assertEqual(result["css_class"], "status-w")
        self.assertEqual(self._spans(result), [(PATH_LINE.index("C:\\"), len(PATH_LINE), B, 1)])

    def test_a_rule_matching_both_literally_and_by_path_paints_once(self):
        # A substring rule whose text is a path also lands in the filepath bucket.
        self._rule(SERVICE_PATH)

        result = self._analyze_line(PATH_LINE)

        self.assertFalse(result["fallback_only"])
        self.assertEqual(self._spans(result), [(PATH_LINE.index("C:\\"), len(PATH_LINE), B, 7)])

    def test_substring_span_paints_over_a_fallback_path(self):
        self._parsed_rule_for_service_line(status=C)
        self._rule("ProtoVPNService")

        result = self._analyze_line(PATH_LINE)

        path_start = PATH_LINE.index("C:\\")
        token_start = PATH_LINE.index("ProtoVPNService")
        self.assertEqual(result["dominant_status"], B)
        self.assertFalse(result["fallback_only"])
        self.assertEqual(self._spans(result), [
            (path_start, token_start, C, 1),
            (token_start, token_start + len("ProtoVPNService"), B, 7),
            (token_start + len("ProtoVPNService"), len(PATH_LINE), C, 1),
        ])

    # -- unmatched --

    def test_unmatched_line_has_no_paint(self):
        result = self._analyze_line("nothing to see here")

        self.assertEqual(result["css_class"], "status-unknown")
        self.assertIsNone(result["paint_base"])
        self.assertEqual(result["highlights"], [])
        self.assertIsNone(result["verdict_priority"])
        self.assertFalse(result["fallback_only"])
