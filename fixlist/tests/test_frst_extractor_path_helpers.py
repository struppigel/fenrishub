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
    _ALL_EXTRACTORS,
    _PATH_EXTRACTORS,
    _denormalize_path_pattern,
    extract_custom_appcompatflags,
    extract_frst_service,
    extract_installed_software,
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

    def test_chromium_profile_normalization_matches_numbered_profile(self):
        source = (
            r"CHR Extension: (McAfee WebAdvisor) - "
            r"C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Profile 2\Extensions\fheoggkfdfchfphceeifdbepaooicaho"
        )
        normalized = (
            r"c:\users\username\appdata\local\google\chrome\user data\profile\extensions\fheoggkfdfchfphceeifdbepaooicaho"
        )
        result = find_value_position(normalized, source, field_name="filepath")
        self.assertIsNotNone(result)
        start, end = result
        self.assertEqual(
            source[start:end],
            r"C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Profile 2\Extensions\fheoggkfdfchfphceeifdbepaooicaho",
        )

    def test_chromium_profile_normalization_matches_default_profile(self):
        source = (
            r"CHR Extension: (X) - "
            r"C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Default\Extensions\fheoggkfdfchfphceeifdbepaooicaho"
        )
        normalized = (
            r"c:\users\username\appdata\local\google\chrome\user data\profile\extensions\fheoggkfdfchfphceeifdbepaooicaho"
        )
        result = find_value_position(normalized, source, field_name="filepath")
        self.assertIsNotNone(result)
        start, end = result
        self.assertEqual(
            source[start:end],
            r"C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Default\Extensions\fheoggkfdfchfphceeifdbepaooicaho",
        )

    def test_chromium_profile_normalization_matches_edge(self):
        source = r"Edge Extension: (X) - C:\Users\jsnip\AppData\Local\Microsoft\Edge\User Data\Profile 1\Extensions\abc"
        normalized = r"c:\users\username\appdata\local\microsoft\edge\user data\profile\extensions\abc"
        result = find_value_position(normalized, source, field_name="filepath")
        self.assertIsNotNone(result)
        start, end = result
        self.assertEqual(
            source[start:end],
            r"C:\Users\jsnip\AppData\Local\Microsoft\Edge\User Data\Profile 1\Extensions\abc",
        )

    def test_chromium_profile_normalization_matches_brave(self):
        source = r"BRA Extension: (X) - C:\Users\jsnip\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions\abc"
        normalized = r"c:\users\username\appdata\local\bravesoftware\brave-browser\user data\profile\extensions\abc"
        result = find_value_position(normalized, source, field_name="filepath")
        self.assertIsNotNone(result)
        start, end = result
        self.assertEqual(
            source[start:end],
            r"C:\Users\jsnip\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions\abc",
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

    def test_pattern_matches_chromium_profile_variants(self):
        import re
        pattern = _denormalize_path_pattern(
            r"c:\users\username\appdata\local\google\chrome\user data\profile\extensions\abc"
        )
        for original in (
            r"C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Default\Extensions\abc",
            r"C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Profile 2\Extensions\abc",
            r"C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Profile 17\Extensions\abc",
            r"C:\Users\jsnip\AppData\Local\Google\Chrome\User Data\Guest Profile\Extensions\abc",
        ):
            self.assertIsNotNone(
                re.search(pattern, original, re.IGNORECASE),
                f"pattern should match {original!r}",
            )


class ExtractorRegistryTests(TestCase):
    """Guard against accidentally dropping an extractor from the registry tables
    or wiring up a path-eligible extractor that yields no filepath."""

    def test_all_extractors_count(self):
        self.assertEqual(len(_ALL_EXTRACTORS), 21)

    def test_path_extractors_excludes_non_path_yielders(self):
        from ..frst_extractors import extract_frst_scheduled_task_command
        self.assertNotIn(extract_installed_software, _PATH_EXTRACTORS)
        self.assertNotIn(extract_custom_appcompatflags, _PATH_EXTRACTORS)
        self.assertNotIn(extract_frst_scheduled_task_command, _PATH_EXTRACTORS)
        self.assertEqual(len(_PATH_EXTRACTORS), len(_ALL_EXTRACTORS) - 3)

    def test_path_extractors_preserves_order(self):
        # _PATH_EXTRACTORS must be a strict subsequence of _ALL_EXTRACTORS so
        # first-match-wins semantics carry over from get_frst_entry.
        path_iter = iter(_PATH_EXTRACTORS)
        current = next(path_iter, None)
        for fn in _ALL_EXTRACTORS:
            if fn is current:
                current = next(path_iter, None)
        self.assertIsNone(current)

    def test_known_extractor_present(self):
        self.assertIn(extract_frst_service, _ALL_EXTRACTORS)
