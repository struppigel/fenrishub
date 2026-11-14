from django.test import TestCase

from ..analyzer import analyze_log_text, invalidate_rule_buckets_cache
from ..frst_extractors import defender_exclusion_path, defender_exclusion_snippet


class DefenderExclusionSnippetTests(TestCase):
    """The `defender_exclusion_snippet` helper turns a Windows Defender exclusion
    registry line into a FRST `PowerShell:` Remove-MpPreference directive."""

    def test_paths_exclusion(self):
        line = (
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
            r"|C:\Users\Oskar\AppData\Local\Temp"
        )
        self.assertEqual(
            defender_exclusion_snippet(line),
            'PowerShell: Remove-MpPreference -ExclusionPath '
            r'"C:\Users\Oskar\AppData\Local\Temp"',
        )

    def test_extensions_exclusion(self):
        line = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions|exe"
        self.assertEqual(
            defender_exclusion_snippet(line),
            'PowerShell: Remove-MpPreference -ExclusionExtension "exe"',
        )

    def test_processes_exclusion(self):
        line = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes|rundll32.exe"
        self.assertEqual(
            defender_exclusion_snippet(line),
            'PowerShell: Remove-MpPreference -ExclusionProcess "rundll32.exe"',
        )

    def test_ipaddresses_exclusion(self):
        line = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses|10.0.0.5"
        self.assertEqual(
            defender_exclusion_snippet(line),
            'PowerShell: Remove-MpPreference -ExclusionIpAddress "10.0.0.5"',
        )

    def test_value_with_spaces_is_quoted_intact(self):
        line = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths|F:\Vortex Mods"
        snippet = defender_exclusion_snippet(line)
        self.assertIn(r'-ExclusionPath "F:\Vortex Mods"', snippet)

    def test_real_username_is_preserved(self):
        # The value must be literal — never normalized to "username" — so the
        # fixlist removes the exclusion on the actual machine.
        line = (
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
            r"|C:\Users\Oskar\AppData\Local\Temp"
        )
        snippet = defender_exclusion_snippet(line)
        self.assertIn(r"C:\Users\Oskar\AppData\Local\Temp", snippet)
        self.assertNotIn("username", snippet)

    def test_wildcard_value_passes_through(self):
        line = (
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
            r"|C:\Users\*\AppData\Local\com.celemony.melodyne\Separations"
        )
        snippet = defender_exclusion_snippet(line)
        self.assertIn(
            r'"C:\Users\*\AppData\Local\com.celemony.melodyne\Separations"',
            snippet,
        )

    def test_trailing_attention_marker_stripped(self):
        line = (
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes"
            r"|powershell.exe <==== ATTENTION"
        )
        self.assertEqual(
            defender_exclusion_snippet(line),
            'PowerShell: Remove-MpPreference -ExclusionProcess "powershell.exe"',
        )

    def test_type_lookup_is_case_insensitive(self):
        line = r"hklm\software\microsoft\windows defender\exclusions\paths|C:\foo"
        snippet = defender_exclusion_snippet(line)
        self.assertIn('-ExclusionPath "C:\\foo"', snippet)

    def test_temporarypaths_uses_deletevalue(self):
        # TemporaryPaths has no Remove-MpPreference parameter — remove the single
        # exclusion via FRST's native DeleteValue directive (path = value name).
        line = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths|C:\foo"
        self.assertEqual(
            defender_exclusion_snippet(line),
            r"DeleteValue: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths|C:\foo",
        )

    def test_temporarypaths_deletevalue_ignores_trailing_marker(self):
        line = (
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths"
            r"|C:\foo <==== ATTENTION"
        )
        self.assertEqual(
            defender_exclusion_snippet(line),
            r"DeleteValue: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths|C:\foo",
        )

    def test_temporarypaths_default_value_leaves_name_empty(self):
        line = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths|(Default)"
        self.assertEqual(
            defender_exclusion_snippet(line),
            r"DeleteValue: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths|",
        )

    def test_temporarypaths_empty_value_leaves_name_empty(self):
        line = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths|"
        self.assertEqual(
            defender_exclusion_snippet(line),
            r"DeleteValue: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths|",
        )

    def test_truly_unknown_exclusion_type_returns_none(self):
        line = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Bogus|C:\foo"
        self.assertIsNone(defender_exclusion_snippet(line))

    def test_non_defender_line_returns_none(self):
        self.assertIsNone(
            defender_exclusion_snippet(r"HKLM\...\Run: [TestApp] => C:\test.exe")
        )
        self.assertIsNone(defender_exclusion_snippet(""))
        self.assertIsNone(defender_exclusion_snippet(None))


class DefenderExclusionAnalyzerFlagTests(TestCase):
    """`analyze_log_text` attaches the snippet as `fixlist_replacement` so the
    frontend can insert it into the Fixlist instead of the raw line."""

    def setUp(self):
        invalidate_rule_buckets_cache()

    def _line_result(self, line):
        result = analyze_log_text(line)
        self.assertEqual(len(result["lines"]), 1)
        return result["lines"][0]

    def test_exclusion_line_sets_fixlist_replacement(self):
        line = (
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
            r"|C:\Users\Oskar\AppData\Local\Temp"
        )
        result = self._line_result(line)
        self.assertEqual(
            result["fixlist_replacement"],
            'PowerShell: Remove-MpPreference -ExclusionPath '
            r'"C:\Users\Oskar\AppData\Local\Temp"',
        )

    def test_ordinary_line_has_no_fixlist_replacement(self):
        line = (
            r"HKLM\...\Run: [Virtual Pet] => "
            r"C:\Program Files\ASUS\Virtual Pet\Virtual Pet.exe "
            r"[33712544 2026-01-17] (ASUSTeK COMPUTER INC. -> ASUSTeK Computer Inc.)"
        )
        result = self._line_result(line)
        self.assertIsNone(result["fixlist_replacement"])


class DefenderExclusionPathTests(TestCase):
    """`defender_exclusion_path` pulls the excluded path off the line, and the
    analyzer exposes it as the `filepath` component for the line copy menu."""

    KEY = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions"

    def setUp(self):
        invalidate_rule_buckets_cache()

    def test_paths_value_is_returned_literally(self):
        line = rf"{self.KEY}\Paths|C:\Users\SamRo\AppData\Roaming\Current\Keywords.exe"
        self.assertEqual(
            defender_exclusion_path(line),
            r"C:\Users\SamRo\AppData\Roaming\Current\Keywords.exe",
        )

    def test_path_with_spaces_and_trailing_marker(self):
        line = rf"{self.KEY}\Paths|C:\Program Files\Black Tree Gaming Ltd\Vortex <==== ATTENTION"
        self.assertEqual(
            defender_exclusion_path(line), r"C:\Program Files\Black Tree Gaming Ltd\Vortex"
        )

    def test_temporarypaths_value(self):
        self.assertEqual(defender_exclusion_path(rf"{self.KEY}\TemporaryPaths|C:\foo"), r"C:\foo")
        self.assertIsNone(defender_exclusion_path(rf"{self.KEY}\TemporaryPaths|(Default)"))
        self.assertIsNone(defender_exclusion_path(rf"{self.KEY}\TemporaryPaths|"))

    def test_processes_only_when_a_full_path(self):
        self.assertEqual(
            defender_exclusion_path(rf"{self.KEY}\Processes|C:\Tools\evil.exe"), r"C:\Tools\evil.exe"
        )
        self.assertIsNone(defender_exclusion_path(rf"{self.KEY}\Processes|rundll32.exe"))

    def test_non_path_types_return_none(self):
        self.assertIsNone(defender_exclusion_path(rf"{self.KEY}\Extensions|exe"))
        self.assertIsNone(defender_exclusion_path(rf"{self.KEY}\IpAddresses|10.0.0.5"))
        self.assertIsNone(defender_exclusion_path(r"HKLM\...\Run: [TestApp] => C:\test.exe"))
        self.assertIsNone(defender_exclusion_path(None))

    def test_analyzer_exposes_path_as_filepath_component(self):
        line = rf"{self.KEY}\Paths|C:\ProgramData\opra.exe"
        components = analyze_log_text(line)["lines"][0]["components"]
        self.assertEqual(components.get("filepath"), r"C:\ProgramData\opra.exe")

    def test_analyzer_omits_filepath_for_extension_exclusion(self):
        components = analyze_log_text(rf"{self.KEY}\Extensions|exe")["lines"][0]["components"]
        self.assertNotIn("filepath", components)
