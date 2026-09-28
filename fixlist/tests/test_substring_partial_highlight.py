"""Substring rules colour only the text they matched unless they opt into
`color_whole_line`. The verdict (dominant_status) is the same either way; only
the presentation -- css_class plus substring_highlights -- differs."""

import json

from django.urls import reverse

from ..analyzer import analyze_log_text
from ..models import ClassificationRule
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase


class SubstringPartialHighlightTests(LogAnalyzerApiBaseTestCase):

    def _rule(self, source_text, status=ClassificationRule.STATUS_MALWARE, **overrides):
        return ClassificationRule.objects.create(
            owner=self.user,
            status=status,
            match_type=overrides.pop('match_type', ClassificationRule.MATCH_SUBSTRING),
            source_text=source_text,
            **overrides,
        )

    def _analyze_line(self, line):
        return analyze_log_text(line)["lines"][0]

    def test_new_rules_default_to_matched_part_only(self):
        self.assertFalse(self._rule("evil").color_whole_line)

    def test_default_substring_rule_colours_only_the_match(self):
        self.client.login(username="analyzer", password="password123")
        self._rule("evil.example")
        line = "Hosts: 1.2.3.4 evil.example"

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": line}),
            content_type="application/json",
        )

        result = response.json()["lines"][0]
        self.assertEqual(result["dominant_status"], ClassificationRule.STATUS_MALWARE)
        self.assertEqual(result["css_class"], "status-unknown")
        start = line.index("evil.example")
        self.assertEqual(
            result["substring_highlights"],
            [{"start": start, "end": start + len("evil.example"), "status": "B", "css_class": "status-b"}],
        )
        self.assertIsNone(result["filepath_highlight"])

    def test_every_occurrence_is_highlighted(self):
        self._rule("bad")
        line = "bad and more bad"

        result = self._analyze_line(line)

        self.assertEqual(
            [(h["start"], h["end"]) for h in result["substring_highlights"]],
            [(0, 3), (13, 16)],
        )

    def test_color_whole_line_rule_colours_the_whole_line(self):
        self._rule("evil", color_whole_line=True)

        result = self._analyze_line("some evil line")

        self.assertEqual(result["css_class"], "status-b")
        self.assertEqual(result["substring_highlights"], [])

    def test_one_whole_line_rule_in_the_winning_group_colours_the_whole_line(self):
        self._rule("evil")
        self._rule("line", status=ClassificationRule.STATUS_CLEAN, color_whole_line=True)

        result = self._analyze_line("some evil line")

        self.assertEqual(result["dominant_status"], ClassificationRule.STATUS_MALWARE)
        self.assertEqual(result["css_class"], "status-b")
        self.assertEqual(result["substring_highlights"], [])

    def test_each_match_keeps_its_own_status(self):
        self._rule("Microsoft", status=ClassificationRule.STATUS_CLEAN)
        self._rule("evil.exe")
        line = "Microsoft loads evil.exe"

        result = self._analyze_line(line)

        self.assertEqual(result["dominant_status"], ClassificationRule.STATUS_MALWARE)
        self.assertEqual(result["css_class"], "status-unknown")
        self.assertEqual(
            [(h["start"], h["end"], h["status"]) for h in result["substring_highlights"]],
            [(0, 9, "C"), (16, 24, "B")],
        )

    def test_overlapping_matches_give_the_overlap_to_the_stronger_status(self):
        self._rule("abcdef", status=ClassificationRule.STATUS_CLEAN)
        self._rule("cd")

        result = self._analyze_line("xabcdefx")

        self.assertEqual(
            [(h["start"], h["end"], h["status"]) for h in result["substring_highlights"]],
            [(1, 3, "C"), (3, 5, "B"), (5, 7, "C")],
        )

    def test_shadowed_substring_rule_leaves_no_highlight(self):
        line = "some evil line"
        self._rule("evil")
        self._rule(line, status=ClassificationRule.STATUS_CLEAN, match_type=ClassificationRule.MATCH_EXACT)

        result = self._analyze_line(line)

        self.assertEqual(result["dominant_status"], ClassificationRule.STATUS_CLEAN)
        self.assertEqual(result["css_class"], "status-c")
        self.assertEqual(result["substring_highlights"], [])

    def test_unmatched_line_carries_an_empty_list(self):
        result = self._analyze_line("nothing to see here")

        self.assertEqual(result["substring_highlights"], [])
