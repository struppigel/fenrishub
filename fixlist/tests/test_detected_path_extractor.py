from django.test import TestCase

from ..frst_extractors import (
    extract_any_frst_path,
    extract_detected_path,
    get_frst_entry,
)


class ExtractDetectedPathTests(TestCase):
    """Tests for the detection-report path extractor (`Path: file:_` / `Process Name:`)."""

    def test_path_file_prefix(self):
        line = (
            r"Path: file:_C:\Users\Samantha\AppData\Roaming\Trimble Connect for SketchUp"
            r"\Logs\f04816f766cedd422ed6559a0c0e9ad4\gamelan.py"
        )
        entry = extract_detected_path(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "detected_path")
        self.assertEqual(entry.filename, "gamelan.py")
        self.assertTrue(entry.filepath.endswith(r"\gamelan.py"))
        # Prefix noise must not leak into the filepath component.
        self.assertNotIn("file:_", entry.filepath)
        self.assertTrue(entry.filepath.startswith("C:\\"))

    def test_path_file_prefix_program_files(self):
        line = (
            r"Path: file:_C:\Program Files\CELSYS\CLIP STUDIO 1.5"
            r"\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
        )
        entry = extract_detected_path(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "CLIPStudioPaint.exe")
        self.assertIn(r"Program Files\CELSYS", entry.filepath)
        self.assertEqual(entry.arguments, "")

    def test_process_name_prefix(self):
        line = r"Process Name: C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe"
        entry = extract_detected_path(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "detected_path")
        self.assertEqual(entry.filename, "TabTip.exe")
        self.assertTrue(entry.filepath.endswith(r"ink\TabTip.exe"))
        self.assertNotIn("Process Name", entry.filepath)

    def test_bare_path_with_process_metadata_suffix(self):
        line = (
            r"C:\Program Files\CELSYS\CLIP STUDIO 1.5\CLIP STUDIO PAINT"
            r"\CLIPStudioPaint.exe; process:_pid:15976,ProcessStart:134246096727081648"
        )
        entry = extract_detected_path(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "detected_path")
        self.assertEqual(entry.filename, "CLIPStudioPaint.exe")
        self.assertTrue(entry.filepath.endswith(r"\CLIPStudioPaint.exe"))
        # The trailing process metadata must not bleed into the filepath / arguments.
        self.assertNotIn("process", entry.filepath)
        self.assertNotIn("pid", entry.filepath)
        self.assertEqual(entry.arguments, "")

    def test_bare_path_without_known_suffix_returns_none(self):
        # A standalone path with no recognised prefix/suffix must not be swallowed.
        self.assertIsNone(extract_detected_path(r"C:\Windows\System32\notepad.exe"))

    def test_username_normalized(self):
        line = (
            r"Path: file:_C:\Users\Samantha\AppData\Roaming\Trimble Connect for SketchUp"
            r"\Logs\f04816f766cedd422ed6559a0c0e9ad4\gamelan.py"
        )
        entry = extract_detected_path(line)
        self.assertIsNotNone(entry)
        self.assertIn("username", entry.filepath)
        self.assertNotIn("Samantha", entry.filepath)

    def test_non_matching_line_returns_none(self):
        self.assertIsNone(extract_detected_path(r"HKLM\...\Run: [TestApp] => C:\test.exe"))
        self.assertIsNone(extract_detected_path("Path: not a windows path"))
        self.assertIsNone(extract_detected_path(""))

    def test_get_frst_entry_finds_detected_path(self):
        line = r"Process Name: C:\Program Files\Common Files\microsoft shared\ink\TabTip.exe"
        entry = get_frst_entry(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "detected_path")
        self.assertEqual(entry.filename, "TabTip.exe")

    def test_extract_any_frst_path_returns_path(self):
        line = (
            r"Path: file:_C:\Program Files\CELSYS\CLIP STUDIO 1.5"
            r"\CLIP STUDIO PAINT\CLIPStudioPaint.exe"
        )
        path = extract_any_frst_path(line)
        self.assertIsNotNone(path)
        self.assertTrue(path.endswith("CLIPStudioPaint.exe"))
        self.assertNotIn("file:_", path)
