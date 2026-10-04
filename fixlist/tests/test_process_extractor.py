from django.test import TestCase

from ..analyzer import analyze_log_text, parse_rule_line
from ..frst_extractors import extract_any_frst_path, extract_process, get_frst_entry
from ..models import ClassificationRule
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

OPERA_PARENT = r"C:\Users\nunol\AppData\Local\Programs\Opera GX\opera.exe"
OPERA_LINE = (
    "(" + OPERA_PARENT + r" ->) (Opera Norway AS -> Opera Software) "
    r"C:\Users\nunol\AppData\Local\Programs\Opera GX\136.0.6008.67\opera_crashreporter.exe"
)
# An unsigned process from a Portuguese system: FRST translates the tag.
UNSIGNED_PT_LINE = (
    "(" + OPERA_PARENT + r" ->) (uploadhaven) [Arquivo não assinado] "
    r"C:\Users\nunol\AppData\Local\SteamUnlocked Launcher\steamunlocked-launcher.exe"
)
UNSIGNED_EN_LINE = UNSIGNED_PT_LINE.replace("[Arquivo não assinado]", "[File not signed]")
WEBVIEW_LINE = (
    r"(C:\Users\nunol\AppData\Local\SteamUnlocked Launcher\steamunlocked-launcher.exe ->) "
    r"(Microsoft Corporation -> Microsoft Corporation) "
    r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.37\msedgewebview2.exe"
)


class ExtractProcessTests(TestCase):

    def test_signed_process_with_parent(self):
        entry = extract_process(OPERA_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "process")
        self.assertEqual(entry.company, "Opera Norway AS -> Opera Software")
        self.assertEqual(
            entry.filepath,
            r"C:\Users\username\AppData\Local\Programs\Opera GX\136.0.6008.67\opera_crashreporter.exe",
        )
        self.assertEqual(entry.filename, "opera_crashreporter.exe")
        self.assertFalse(entry.file_not_signed)

    def test_parent_path_is_normalized_and_lowercased(self):
        entry = extract_process(OPERA_LINE)
        self.assertEqual(entry.name, r"c:\users\username\appdata\local\programs\opera gx\opera.exe")

    def test_unsigned_process_with_translated_tag(self):
        entry = extract_process(UNSIGNED_PT_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.company, "uploadhaven")
        self.assertEqual(
            entry.filepath,
            r"C:\Users\username\AppData\Local\SteamUnlocked Launcher\steamunlocked-launcher.exe",
        )
        self.assertTrue(entry.file_not_signed)

    def test_parent_with_other_program_files_child(self):
        entry = extract_process(WEBVIEW_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "msedgewebview2.exe")
        self.assertEqual(
            entry.name, r"c:\users\username\appdata\local\steamunlocked launcher\steamunlocked-launcher.exe"
        )

    def test_same_process_tree_for_another_user_is_equal(self):
        self.assertEqual(extract_process(OPERA_LINE), extract_process(OPERA_LINE.replace("nunol", "other")))

    def test_parent_casing_does_not_matter(self):
        upper = r"(C:\WINDOWS\explorer.exe ->) (Foo Inc) C:\Program Files\Foo\foo.exe"
        lower = r"(C:\Windows\explorer.exe ->) (Foo Inc) C:\Program Files\Foo\foo.exe"
        self.assertEqual(extract_process(upper), extract_process(lower))

    def test_bare_parent_is_lowercased(self):
        entry = extract_process(r"(Explorer.EXE ->) (Foo Inc) C:\Program Files\Foo\foo.exe")
        self.assertEqual(entry.name, "explorer.exe")

    def test_translated_and_english_tags_give_equal_entries(self):
        self.assertEqual(extract_process(UNSIGNED_PT_LINE), extract_process(UNSIGNED_EN_LINE))

    def test_several_tags_and_no_parent(self):
        two_tags = (
            r"(C:\Program Files (x86)\Stream Controller\Stream Controller.exe ->) (Node.js) "
            r"[File not signed] [File is in use] C:\Users\bob\AppData\Roaming\HotSpot\plugin.exe"
        )
        no_parent = r"() [File not signed] C:\Users\bob\AppData\Local\RuneLite\RuneLite.exe"
        double_space = (
            r"(D:\XboxGames\Roblox\Content\RobloxPlayerBeta.exe ->) (Access Denied)  [File not signed?] "
            r"D:\XboxGames\Roblox\Content\RobloxCrashHandler.exe"
        )
        entry = extract_process(two_tags)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "plugin.exe")
        self.assertTrue(entry.file_not_signed)

        entry = extract_process(no_parent)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "")
        self.assertEqual(entry.company, "")
        self.assertEqual(entry.filename, "RuneLite.exe")

        entry = extract_process(double_space)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "RobloxCrashHandler.exe")

    def test_get_frst_entry_and_any_path_find_unsigned_process(self):
        self.assertEqual(get_frst_entry(UNSIGNED_PT_LINE).entry_type, "process")
        self.assertEqual(
            extract_any_frst_path(UNSIGNED_PT_LINE),
            r"C:\Users\username\AppData\Local\SteamUnlocked Launcher\steamunlocked-launcher.exe",
        )

    def test_parse_rule_line_gives_parsed_rule_for_unsigned_process(self):
        rule = parse_rule_line(UNSIGNED_PT_LINE, ClassificationRule.STATUS_MALWARE)
        self.assertEqual(rule["match_type"], ClassificationRule.MATCH_PARSED_ENTRY)
        self.assertEqual(rule["entry_type"], "process")
        self.assertTrue(rule["file_not_signed"])


class ProcessRuleMatchingTests(LogAnalyzerApiBaseTestCase):

    def test_unsigned_process_rule_matches_other_user_as_parsed_entry(self):
        parsed = parse_rule_line(UNSIGNED_PT_LINE, ClassificationRule.STATUS_MALWARE, "test-suite")
        ClassificationRule.objects.create(owner=self.user, **parsed)

        result = analyze_log_text(UNSIGNED_EN_LINE.replace("nunol", "other"))["lines"][0]

        self.assertEqual(result["matcher"], "parsed_entry")
        self.assertEqual(result["dominant_status"], ClassificationRule.STATUS_MALWARE)
        self.assertEqual(result["css_class"], "status-b")
        self.assertEqual(result["highlights"], [])
        self.assertFalse(result["fallback_only"])

    def test_copied_parent_keeps_the_line_spelling(self):
        result = analyze_log_text(OPERA_LINE)["lines"][0]
        self.assertEqual(result["components"]["name"], OPERA_PARENT)
