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
