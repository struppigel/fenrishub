from django.test import TestCase

from ..analyzer import analyze_log_text, invalidate_rule_buckets_cache
from ..frst_extractors import browser_extension_snippet


class BrowserExtensionSnippetTests(TestCase):
    """`browser_extension_snippet` turns a `<BROWSER> Extension:` line into a
    `Comment:` naming the extension plus the folder FRST should delete."""

    def test_chrome_extension(self):
        line = (
            r"CHR Extension: (Google Docs Offline) - "
            r"C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default"
            r"\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi [2026-04-01]"
        )
        self.assertEqual(
            browser_extension_snippet(line),
            "Comment: Browser extension - Google Docs Offline\n"
            r"C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default"
            r"\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi",
        )

    def test_edge_brave_and_firefox_prefixes(self):
        for prefix in ("Edge", "BRA", "FF"):
            with self.subTest(prefix=prefix):
                line = rf"{prefix} Extension: (Some Ext) - C:\ext\abcd [2026-05-30]"
                self.assertEqual(
                    browser_extension_snippet(line),
                    "Comment: Browser extension - Some Ext\n" + r"C:\ext\abcd",
                )

    def test_name_with_nested_parentheses(self):
        line = (
            r"BRA Extension: (Brave Ad Block Updater (Brave First Party Adblock "
            r"Filters (plaintext))) - C:\Users\Administrator\AppData\Local"
            r"\BraveSoftware\Brave-Browser\User Data\adcocjohghhfpidemphmcmlmhnfgikei "
            r"[2026-05-08]"
        )
        self.assertEqual(
            browser_extension_snippet(line),
            "Comment: Browser extension - Brave Ad Block Updater "
            "(Brave First Party Adblock Filters (plaintext))\n"
            r"C:\Users\Administrator\AppData\Local\BraveSoftware\Brave-Browser"
            r"\User Data\adcocjohghhfpidemphmcmlmhnfgikei",
        )

    def test_missing_date_bracket(self):
        line = r"CHR Extension: (Some Ext) - C:\ext\abcd"
        self.assertEqual(
            browser_extension_snippet(line),
            "Comment: Browser extension - Some Ext\n" + r"C:\ext\abcd",
        )

    def test_attention_marker_is_stripped(self):
        line = (
            r"CHR Extension: (Bad Ext) - C:\ext\abcd [2026-05-30] <==== ATTENTION"
        )
        self.assertEqual(
            browser_extension_snippet(line),
            "Comment: Browser extension - Bad Ext\n" + r"C:\ext\abcd",
        )

    def test_real_username_is_preserved(self):
        # The path must be literal — never normalized to "username" — so the
        # fixlist deletes the folder on the actual machine.
        line = (
            r"CHR Extension: (Some Ext) - C:\Users\Oskar\AppData\Local\Google"
            r"\Chrome\User Data\Default\Extensions\abcd [2026-05-30]"
        )
        snippet = browser_extension_snippet(line)
        self.assertIn(r"C:\Users\Oskar\AppData", snippet)
        self.assertNotIn("username", snippet)

    def test_registry_forced_extension_line_returns_none(self):
        # These carry an extension ID, not a path — FRST removes them as written.
        self.assertIsNone(
            browser_extension_snippet(
                r"CHR HKLM\...\Chrome\Extension: [ihcjicgdanjaechkgeegckofjjedodee]"
            )
        )
        self.assertIsNone(
            browser_extension_snippet(
                r"Edge HKLM-x32\...\Edge\Extension: [bojobppfploabceghnmlahpoonbcbacn]"
            )
        )

    def test_other_browser_lines_return_none(self):
        self.assertIsNone(
            browser_extension_snippet(
                r"CHR Profile: C:\Users\Administrator\AppData\Local\Google\Chrome"
                r"\User Data\Default [2026-05-30]"
            )
        )
        self.assertIsNone(
            browser_extension_snippet(
                r"FF Plugin: @java.com/DTPlugin,version=11.471.0 -> "
                r"A:\java\bin\dtplugin\npDeployJava1.dll [2025-09-25] "
                r"(Oracle America, Inc. -> Oracle Corporation)"
            )
        )
        self.assertIsNone(browser_extension_snippet(""))
        self.assertIsNone(browser_extension_snippet(None))


class BrowserExtensionAnalyzerFlagTests(TestCase):
    """`analyze_log_text` attaches the snippet as `fixlist_replacement` so the
    frontend inserts it into the Fixlist instead of the raw line."""

    def setUp(self):
        invalidate_rule_buckets_cache()

    def _line_result(self, line):
        result = analyze_log_text(line)
        self.assertEqual(len(result["lines"]), 1)
        return result["lines"][0]

    def test_extension_line_sets_fixlist_replacement(self):
        line = (
            r"CHR Extension: (Google Docs Offline) - C:\Users\Administrator"
            r"\AppData\Local\Google\Chrome\User Data\Default\Extensions"
            r"\ghbmnnjooekpmoecnnnilnnbdlolhkhi [2026-04-01]"
        )
        result = self._line_result(line)
        self.assertEqual(
            result["fixlist_replacement"],
            "Comment: Browser extension - Google Docs Offline\n"
            r"C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default"
            r"\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi",
        )

    def test_defender_exclusion_still_wins_its_own_line(self):
        line = (
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
            r"|C:\Users\Oskar\AppData\Local\Temp"
        )
        result = self._line_result(line)
        self.assertTrue(
            result["fixlist_replacement"].startswith("PowerShell: Remove-MpPreference")
        )
