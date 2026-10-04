from django.test import TestCase

from ..analyzer import analyze_log_text, parse_rule_line
from ..frst_extractors import (
    extract_any_frst_path,
    extract_frst_startup,
    extract_frst_startup_dir,
    get_frst_entry,
)
from ..models import ClassificationRule
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

# A Startup folder redirected into a random Temp folder, with FRST's trailing
# backslash and ATTENTION marker.
TEMP_LINE = r"StartupDir: C:\Users\X1CARB~1\AppData\Local\Temp\6fb2af726d\ <==== ATTENTION"
TEMP_PATH = r"C:\Users\username\AppData\Local\Temp\6fb2af726d"


class ExtractFrstStartupDirTests(TestCase):
    """Tests for the StartupDir: FRST entry extractor."""

    def test_redirected_temp_folder(self):
        entry = extract_frst_startup_dir(TEMP_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "startup_dir")
        self.assertEqual(entry.filepath, TEMP_PATH)
        self.assertEqual(entry.filename, "6fb2af726d")

    def test_attention_marker_and_trailing_backslash_excluded(self):
        entry = extract_frst_startup_dir(TEMP_LINE)
        self.assertNotIn("ATTENTION", entry.filepath)
        self.assertFalse(entry.filepath.endswith("\\"))

    def test_drive_normalized_and_spaces_preserved(self):
        line = r"StartupDir: K:\Roaming\Microsoft\Windows\Start Menu\Programs\Startup <==== ATTENTION"
        entry = extract_frst_startup_dir(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filepath, r"C:\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        self.assertEqual(entry.filename, "Startup")

    def test_without_marker_still_parses(self):
        entry = extract_frst_startup_dir(r"StartupDir: C:\Users\bob\AppData\Local\Temp\6fb2af726d")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filepath, TEMP_PATH)

    def test_trailing_backslash_does_not_change_entry(self):
        with_slash = extract_frst_startup_dir(r"StartupDir: C:\Users\bob\AppData\Local\Temp\6fb2af726d\ ")
        without_slash = extract_frst_startup_dir(r"StartupDir: C:\Users\bob\AppData\Local\Temp\6fb2af726d")
        self.assertEqual(with_slash, without_slash)

    def test_different_usernames_give_equal_entries(self):
        other_user = TEMP_LINE.replace("X1CARB~1", "alice")
        self.assertEqual(extract_frst_startup_dir(TEMP_LINE), extract_frst_startup_dir(other_user))

    def test_not_confused_with_startup_entries(self):
        startup_line = (
            r"Startup: C:\Users\bob\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\foo.lnk [2026-01-02]"
        )
        self.assertIsNone(extract_frst_startup(TEMP_LINE))
        self.assertIsNone(extract_frst_startup_dir(startup_line))

    def test_get_frst_entry_finds_startup_dir(self):
        entry = get_frst_entry(TEMP_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "startup_dir")

    def test_any_frst_path_finds_folder(self):
        self.assertEqual(extract_any_frst_path(TEMP_LINE), TEMP_PATH)

    def test_empty_line_returns_none(self):
        self.assertIsNone(extract_frst_startup_dir(""))

    def test_parse_rule_line_gives_parsed_rule(self):
        rule = parse_rule_line(TEMP_LINE, ClassificationRule.STATUS_MALWARE)
        self.assertEqual(rule["match_type"], ClassificationRule.MATCH_PARSED_ENTRY)
        self.assertEqual(rule["entry_type"], "startup_dir")
        self.assertEqual(rule["normalized_filepath"], TEMP_PATH.lower())


class StartupDirRuleMatchingTests(LogAnalyzerApiBaseTestCase):

    def test_parsed_rule_matches_same_folder_for_other_user(self):
        parsed = parse_rule_line(TEMP_LINE, ClassificationRule.STATUS_MALWARE, "test-suite")
        ClassificationRule.objects.create(owner=self.user, **parsed)

        result = analyze_log_text(TEMP_LINE.replace("X1CARB~1", "alice"))["lines"][0]

        self.assertEqual(result["matcher"], "parsed_entry")
        self.assertEqual(result["dominant_status"], ClassificationRule.STATUS_MALWARE)
        # A parsed rule colours the whole line, not just the folder.
        self.assertEqual(result["css_class"], "status-b")
        self.assertEqual(result["highlights"], [])
        self.assertFalse(result["fallback_only"])
