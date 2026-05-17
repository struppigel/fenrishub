from django.test import TestCase

from ..frst_extractors import extract_onemonth, get_frst_entry


class ExtractOneMonthTests(TestCase):

    def test_captures_modified_timestamp_with_minutes(self):
        line = (
            r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 ____D "
            r"C:\Program Files\Proton\VPN\v4.3.13"
        )
        entry = extract_onemonth(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "onemonth")
        self.assertEqual(entry.date, "2026-03-18 13:45")
        self.assertTrue(entry.filepath.endswith(r"VPN\v4.3.13"))

    def test_captures_modified_timestamp_with_seconds(self):
        line = (
            r"2026-04-18 14:32:18 - 2026-04-15 09:00:00 - 0001234 _____ "
            r"(Microsoft Corporation) C:\Windows\System32\foo.exe"
        )
        entry = extract_onemonth(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.date, "2026-04-18 14:32:18")
        self.assertEqual(entry.company, "Microsoft Corporation")
        self.assertTrue(entry.filepath.endswith(r"System32\foo.exe"))

    def test_get_frst_entry_routes_to_onemonth(self):
        line = (
            r"2026-01-01 12:00 - 2026-01-01 12:00 - 0001234 _____ "
            r"(Acme) C:\path\to\file.exe"
        )
        entry = get_frst_entry(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "onemonth")
        self.assertEqual(entry.date, "2026-01-01 12:00")

    def test_non_onemonth_line_returns_none(self):
        self.assertIsNone(extract_onemonth("Startup: C:\\foo.lnk [2026-04-18]"))

    def test_captures_directory_attributes(self):
        line = (
            r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 ____D "
            r"C:\Program Files\Proton\VPN\v4.3.13"
        )
        entry = extract_onemonth(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.attributes, "____D")

    def test_captures_file_attributes(self):
        line = (
            r"2026-04-18 14:32:18 - 2026-04-15 09:00:00 - 0001234 _____ "
            r"(Microsoft Corporation) C:\Windows\System32\foo.exe"
        )
        entry = extract_onemonth(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.attributes, "_____")

    def test_captures_compound_attributes(self):
        line = (
            r"2026-05-16 17:49 - 2026-05-16 17:49 - 000000000 __RHD "
            r"C:\Users\Public\AccountPictures"
        )
        entry = extract_onemonth(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.attributes, "__RHD")

    def test_entries_differ_when_only_attributes_differ(self):
        dir_line = r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 ____D C:\foo\bar"
        file_line = r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 _____ C:\foo\bar"
        dir_entry = extract_onemonth(dir_line)
        file_entry = extract_onemonth(file_line)
        self.assertIsNotNone(dir_entry)
        self.assertIsNotNone(file_entry)
        self.assertNotEqual(dir_entry, file_entry)
