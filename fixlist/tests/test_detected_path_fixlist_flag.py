from django.test import TestCase

from ..analyzer import analyze_log_text, invalidate_rule_buckets_cache
from ..models import ClassificationRule


class DetectedPathFixlistFlagTests(TestCase):
    """The `fixlist_path_only` flag must reflect the parsed entry's real shape,
    independent of which matcher (if any) classified the line — a matching rule
    rewrites `entry_type`, so the frontend relies on this flag instead."""

    def setUp(self):
        invalidate_rule_buckets_cache()

    def _line_result(self, line):
        result = analyze_log_text(line)
        self.assertEqual(len(result["lines"]), 1)
        return result["lines"][0]

    def test_unmatched_detected_path_sets_flag(self):
        line = (
            r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
            r"\CLIPStudioPaint.exe; process:_pid:15976,ProcessStart:134246096727081648"
        )
        result = self._line_result(line)
        self.assertTrue(result["fixlist_path_only"])
        self.assertEqual(result["entry_type"], "detected_path")
        self.assertTrue(result["components"]["filepath"].endswith(r"\CLIPStudioPaint.exe"))

    def test_flag_survives_a_matching_substring_rule(self):
        # A substring rule classifies the line and rewrites `entry_type` to the
        # matcher label, but the path-only flag must remain set.
        ClassificationRule.objects.create(
            match_type=ClassificationRule.MATCH_SUBSTRING,
            source_text="CLIPStudioPaint.exe",
            status="B",
        )
        invalidate_rule_buckets_cache()
        line = (
            r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
            r"\CLIPStudioPaint.exe; process:_pid:15976,ProcessStart:134246096727081648"
        )
        result = self._line_result(line)
        self.assertEqual(result["dominant_status"], "B")
        self.assertNotEqual(result["entry_type"], "detected_path")  # matcher label won
        self.assertTrue(result["fixlist_path_only"])  # still path-only

    def test_ordinary_line_does_not_set_flag(self):
        line = (
            r"HKLM\...\Run: [Virtual Pet] => "
            r"C:\Program Files\ASUS\Virtual Pet\Virtual Pet.exe "
            r"[33712544 2026-01-17] (ASUSTeK COMPUTER INC. -> ASUSTeK Computer Inc.)"
        )
        result = self._line_result(line)
        self.assertFalse(result["fixlist_path_only"])
