r"""Tests for the bare-path fallback in `extract_any_frst_path`.

FRST emits lines that are nothing but a filesystem path (file-search results),
and analysts paste such lines out of fixlist drafts into the analyzer. No
extractor recognizes them, so before this fallback they yielded no filepath at
all and filepath rules could never match them.

The fallback only runs after every extractor has declined the line, so a real
FRST entry still parses through its own extractor.
"""

from django.test import TestCase

from ..analyzer import inspect_line_matches, invalidate_rule_buckets_cache, parse_rule_line
from ..frst_extractors import extract_any_frst_path, normalize_path
from ..models import ClassificationRule
from .factories import make_rule, make_user


class BarePathExtractionTests(TestCase):
    def test_plain_path_is_returned(self):
        line = r"C:\Users\Lucian\AppData\Local\Temp\dropper.exe"
        self.assertEqual(extract_any_frst_path(line), line)

    def test_directory_path_with_spaces_is_returned_whole(self):
        line = r"C:\Users\Lucian\AppData\Roaming\Some Bad Folder"
        self.assertEqual(extract_any_frst_path(line), line)

    def test_non_c_drive_is_returned(self):
        line = r"D:\Tools\bad.exe"
        self.assertEqual(extract_any_frst_path(line), line)

    def test_unc_path_is_returned(self):
        line = r"\\server\share\payload.dll"
        self.assertEqual(extract_any_frst_path(line), line)

    def test_attention_marker_is_stripped(self):
        line = r"C:\ProgramData\Zam\zam.exe <==== ATTENTION"
        self.assertEqual(extract_any_frst_path(line), r"C:\ProgramData\Zam\zam.exe")

    def test_description_suffix_is_stripped(self):
        line = r"C:\ProgramData\Zam\zam.exe|||Description: Zemana leftovers"
        self.assertEqual(extract_any_frst_path(line), r"C:\ProgramData\Zam\zam.exe")

    def test_trailing_arguments_are_dropped(self):
        line = r"C:\Users\Lucian\AppData\Local\Temp\dropper.exe -silent /install"
        self.assertEqual(
            extract_any_frst_path(line),
            r"C:\Users\Lucian\AppData\Local\Temp\dropper.exe",
        )

    def test_quoted_path_with_arguments(self):
        line = r'"C:\Program Files (x86)\Bad App\bad.exe" --run'
        self.assertEqual(
            extract_any_frst_path(line),
            r"C:\Program Files (x86)\Bad App\bad.exe",
        )

    def test_trailing_frst_metadata_after_binary_is_dropped(self):
        line = r"C:\Windows\System32\wininit.exe [2022-09-17 09:56][002094592]"
        self.assertEqual(extract_any_frst_path(line), r"C:\Windows\System32\wininit.exe")

    def test_no_file_marker_yields_no_path(self):
        # Matches how the extractor loop already treats `(No File)`: FRST has
        # reported the file as absent, so there is no path to match on.
        self.assertIsNone(extract_any_frst_path(r"C:\ProgramData\Zam\zam.exe (No File)"))

    def test_second_colon_is_rejected(self):
        # Two paths on one line is some other entry shape — don't guess.
        self.assertIsNone(
            extract_any_frst_path(r"C:\Users\Lucian\link.lnk -> C:\Windows\System32\cmd.exe")
        )

    def test_trailing_timestamp_without_binary_is_rejected(self):
        self.assertIsNone(
            extract_any_frst_path(r"C:\Users\Lucian\Raxec [2026-04-14 18:05]")
        )

    def test_non_path_line_yields_no_path(self):
        self.assertIsNone(extract_any_frst_path("Loaded Profiles: Lucian"))

    def test_drive_root_alone_yields_no_path(self):
        self.assertIsNone(extract_any_frst_path("C:"))

    def test_real_frst_entry_still_uses_its_own_extractor(self):
        # The fallback must not hijack a line an extractor already handles.
        line = (
            r"2026-04-14 18:05 - 2026-04-14 18:05 - 000000000 ____D "
            r"C:\Users\Lucian\Raxec"
        )
        self.assertEqual(extract_any_frst_path(line), r"C:\Users\username\Raxec")


class BarePathRuleMatchingTests(TestCase):
    """The point of the fallback: filepath rules match bare path log lines."""

    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        self.user = make_user("barepathuser")

    def _filepath_rule(self, path, status=ClassificationRule.STATUS_MALWARE):
        return make_rule(
            path,
            owner=self.user,
            status=status,
            match_type=ClassificationRule.MATCH_FILEPATH,
            filepath=path,
            normalized_filepath=normalize_path(path).lower().strip(),
        )

    def test_filepath_rule_matches_bare_path_line(self):
        self._filepath_rule(r"C:\ProgramData\Zam\zam.exe")
        result = inspect_line_matches(r"C:\ProgramData\Zam\zam.exe")
        self.assertEqual(result["dominant_status"], ClassificationRule.STATUS_MALWARE)
        self.assertEqual(result["effective_matcher"], "filepath")

    def test_filepath_rule_matches_bare_path_line_of_another_user(self):
        # The rule stores the normalized path; the line carries the real user.
        self._filepath_rule(r"C:\Users\username\AppData\Local\Temp\dropper.exe")
        result = inspect_line_matches(
            r"C:\Users\Lucian\AppData\Local\Temp\dropper.exe"
        )
        self.assertEqual(result["dominant_status"], ClassificationRule.STATUS_MALWARE)

    def test_unrelated_bare_path_line_stays_unknown(self):
        self._filepath_rule(r"C:\ProgramData\Zam\zam.exe")
        result = inspect_line_matches(r"C:\ProgramData\Other\other.exe")
        self.assertEqual(result["dominant_status"], "?")

    def test_bare_path_line_becomes_a_filepath_rule(self):
        parsed = parse_rule_line(
            r"C:\ProgramData\Zam\zam.exe <==== ATTENTION",
            ClassificationRule.STATUS_MALWARE,
        )
        self.assertEqual(parsed["match_type"], ClassificationRule.MATCH_FILEPATH)
        # The FRST marker is no longer carried into the stored path.
        self.assertEqual(parsed["filepath"], r"C:\ProgramData\Zam\zam.exe")
        self.assertEqual(
            parsed["normalized_filepath"], r"c:\programdata\zam\zam.exe"
        )
