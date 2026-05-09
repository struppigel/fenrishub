"""Tests for the path-denormalization helpers used by rule highlighting.

Background: rules built from FRST log lines store filepath in normalized form
(`C:\\Users\\username\\...`, drive forced to C:, Firefox profile name → "profile").
The literal stored value no longer appears in the original line, so a plain
substring match misses it. `find_value_position` falls back to a regex built by
`_denormalize_path_pattern` that allows the normalized parts to match the
original. These tests cover the user-reported bug case (`Lucian` → only the
filename was highlighted instead of the full path).
"""

from django.test import TestCase

from ..frst_extractors import (
    _denormalize_path_pattern,
    find_value_position,
)


class FindValuePositionLiteralTests(TestCase):
    def test_literal_match_returns_span(self):
        source = "prefix C:\\ProgramData\\Zam suffix"
        result = find_value_position("C:\\ProgramData\\Zam", source, field_name="filepath")
        self.assertIsNotNone(result)
        start, end = result
        self.assertEqual(source[start:end], "C:\\ProgramData\\Zam")

    def test_literal_match_is_case_insensitive(self):
        source = "row C:\\Program Files\\App\\thing.exe"
        result = find_value_position("c:\\program files\\app\\thing.exe", source, field_name="filepath")
        self.assertIsNotNone(result)
        start, end = result
        self.assertEqual(source[start:end].lower(), "c:\\program files\\app\\thing.exe")

    def test_empty_value_returns_none(self):
        self.assertIsNone(find_value_position("", "anything", field_name="filepath"))

    def test_empty_source_returns_none(self):
        self.assertIsNone(find_value_position("C:\\foo", "", field_name="filepath"))

    def test_no_match_returns_none(self):
        self.assertIsNone(
            find_value_position("C:\\absent", "totally unrelated text", field_name="filepath")
        )


class FindValuePositionDenormalizedTests(TestCase):
    """The user's reported bug: normalized rule.filepath should still locate
    the original path inside source_text after normalize_path() rewrites."""

    def test_username_normalization_matches_original_user(self):
        # Reproduces user example #2: rule stored "username", line has "Lucian".
        source = (
            r"2026-04-14 18:05 - 2026-04-14 18:05 - 000000000 ____D "
            r"C:\Users\Lucian\Raxec"
        )
        result = find_value_position(
            r"C:\Users\username\Raxec", source, field_name="filepath"
        )
        self.assertIsNotNone(result)
        start, end = result
        self.assertEqual(source[start:end], r"C:\Users\Lucian\Raxec")

    def test_drive_letter_normalization_matches_other_drive(self):
        # normalize_path forces the drive to C:; original line had D:.
        source = "FRST line referring to D:\\Tools\\bad.exe"
        result = find_value_position(
            r"C:\Tools\bad.exe", source, field_name="filepath"
        )
        self.assertIsNotNone(result)
        start, end = result
        self.assertEqual(source[start:end], "D:\\Tools\\bad.exe")

    def test_firefox_profile_normalization_matches_actual_profile(self):
        source = (
            r"FF Extension at "
            r"C:\Users\Lucian\AppData\Roaming\Mozilla\Firefox\Profiles\abc123.default-release\extensions"
        )
        normalized = (
            r"C:\Users\username\AppData\Roaming\Mozilla\Firefox\Profiles\profile\extensions"
        )
        result = find_value_position(normalized, source, field_name="filepath")
        self.assertIsNotNone(result)
        start, end = result
        self.assertEqual(
            source[start:end],
            r"C:\Users\Lucian\AppData\Roaming\Mozilla\Firefox\Profiles\abc123.default-release\extensions",
        )

    def test_non_path_field_does_not_use_fuzzy_fallback(self):
        # `name` shouldn't be treated as a path; if literal misses, return None.
        source = "Some line with username Lucian on it"
        # Stored normalized value is "username" — literal match would succeed,
        # so use a value that doesn't appear at all but resembles a path.
        self.assertIsNone(
            find_value_position(r"C:\Users\username\Raxec", source, field_name="name")
        )

    def test_filename_field_also_uses_fuzzy_fallback(self):
        # `filename` is also a path-bearing field per the helper's contract.
        source = r"C:\Users\Lucian\Raxec"
        result = find_value_position(
            r"C:\Users\username\Raxec", source, field_name="filename"
        )
        self.assertIsNotNone(result)


class DenormalizePathPatternTests(TestCase):
    def test_returns_none_for_empty_input(self):
        self.assertIsNone(_denormalize_path_pattern(""))
        self.assertIsNone(_denormalize_path_pattern(None))

    def test_pattern_matches_user_substitution(self):
        import re
        pattern = _denormalize_path_pattern(r"C:\Users\username\Raxec")
        self.assertIsNotNone(pattern)
        self.assertIsNotNone(re.search(pattern, r"C:\Users\Lucian\Raxec", re.IGNORECASE))

    def test_pattern_matches_any_drive_letter(self):
        import re
        pattern = _denormalize_path_pattern(r"C:\Tools\bad.exe")
        self.assertIsNotNone(re.search(pattern, r"D:\Tools\bad.exe", re.IGNORECASE))
        self.assertIsNotNone(re.search(pattern, r"E:\Tools\bad.exe", re.IGNORECASE))

    def test_pattern_does_not_overmatch(self):
        import re
        pattern = _denormalize_path_pattern(r"C:\Users\username\Raxec")
        # Any user, but the trailing component must still match literally.
        self.assertIsNone(re.search(pattern, r"C:\Users\Lucian\Different", re.IGNORECASE))
