from django.test import TestCase

from ..frst_extractors import extract_frst_startup, get_frst_entry


class ExtractFrstStartupTests(TestCase):
    """Tests for the Startup: FRST entry extractor."""

    def test_standard_startup_entry(self):
        line = (
            r"Startup: C:\Users\aelmo\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\executor_ctrl.lnk [2026-04-18]"
        )
        entry = extract_frst_startup(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "startup")
        self.assertEqual(entry.filename, "executor_ctrl.lnk")
        self.assertEqual(entry.date, "2026-04-18")
        self.assertIn("Startup", entry.filepath)
        self.assertTrue(entry.filepath.endswith("executor_ctrl.lnk"))

    def test_second_standard_startup_entry(self):
        line = (
            r"Startup: C:\Users\aelmo\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\interfacebroker.lnk [2026-04-17]"
        )
        entry = extract_frst_startup(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "interfacebroker.lnk")
        self.assertEqual(entry.date, "2026-04-17")

    def test_username_normalized(self):
        line = (
            r"Startup: C:\Users\aelmo\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\executor_ctrl.lnk [2026-04-18]"
        )
        entry = extract_frst_startup(line)
        self.assertIsNotNone(entry)
        self.assertIn("username", entry.filepath)
        self.assertNotIn("aelmo", entry.filepath)

    def test_path_with_spaces_preserved(self):
        line = (
            r"Startup: C:\Users\bob\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\my app.lnk [2026-01-02]"
        )
        entry = extract_frst_startup(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "my app.lnk")
        self.assertIn(r"Start Menu\Programs\Startup", entry.filepath)

    def test_missing_date_still_parses(self):
        line = (
            r"Startup: C:\Users\bob\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\foo.lnk"
        )
        entry = extract_frst_startup(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "foo.lnk")
        self.assertEqual(entry.date, "")

    def test_non_startup_line_returns_none(self):
        self.assertIsNone(extract_frst_startup(r"HKLM\...\Run: [TestApp] => C:\test.exe"))

    def test_attention_marker_excluded_from_filepath(self):
        line = (
            r"Startup: C:\Users\Benjamin\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\StackBroker_win64.lnk "
            r"[2026-03-15] <==== ATTENTION"
        )
        entry = extract_frst_startup(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "StackBroker_win64.lnk")
        self.assertEqual(entry.date, "2026-03-15")
        self.assertNotIn("ATTENTION", entry.filepath)
        self.assertNotIn("2026-03-15", entry.filepath)

    def test_file_not_signed_marker_does_not_become_date(self):
        line = (
            r"Startup: C:\Program Files\Foo\foo.lnk "
            r"[2026-01-01] [File not signed]"
        )
        entry = extract_frst_startup(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.date, "2026-01-01")
        self.assertTrue(entry.file_not_signed)
        self.assertNotIn("File not signed", entry.filepath)

    def test_all_trailing_markers_combined(self):
        line = (
            r"Startup: C:\Program Files\Foo\foo.lnk "
            r"[2026-01-01] [File not signed] <==== ATTENTION"
        )
        entry = extract_frst_startup(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.date, "2026-01-01")
        self.assertTrue(entry.file_not_signed)
        self.assertNotIn("ATTENTION", entry.filepath)

    def test_no_file_marker_without_date(self):
        line = r"Startup: C:\Program Files\Foo\foo.lnk (No File)"
        entry = extract_frst_startup(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "foo.lnk")
        self.assertNotIn("No File", entry.filepath)

    def test_empty_line_returns_none(self):
        self.assertIsNone(extract_frst_startup(""))

    def test_get_frst_entry_finds_startup(self):
        line = (
            r"Startup: C:\Users\aelmo\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\executor_ctrl.lnk [2026-04-18]"
        )
        entry = get_frst_entry(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "startup")
        self.assertEqual(entry.filename, "executor_ctrl.lnk")
