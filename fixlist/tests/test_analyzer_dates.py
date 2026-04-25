from django.test import TestCase

from ..analyzer import analyze_log_text, invalidate_rule_buckets_cache


class AnalyzerDatesFieldTests(TestCase):

    def setUp(self):
        invalidate_rule_buckets_cache()

    def _dates_for(self, line):
        result = analyze_log_text(line)
        self.assertEqual(len(result["lines"]), 1)
        return result["lines"][0]["dates"]

    def test_runkey_line_with_size_date_brackets_yields_normalized_date(self):
        line = (
            r"HKLM\...\Run: [Virtual Pet] => "
            r"C:\Program Files\ASUS\Virtual Pet\Virtual Pet.exe "
            r"[33712544 2026-01-17] (ASUSTeK COMPUTER INC. -> ASUSTeK Computer Inc.)"
        )
        self.assertEqual(self._dates_for(line), ["2026-01-17"])

    def test_service_line_with_size_date_brackets_yields_normalized_date(self):
        line = (
            r"R2 ArmouryCrateService; "
            r"C:\Program Files\ASUS\Armoury Crate Service\ArmouryCrate.Service.exe "
            r"[451176 2026-01-23] (ASUSTeK COMPUTER INC. -> ASUSTeK COMPUTER INC.)"
        )
        self.assertEqual(self._dates_for(line), ["2026-01-23"])

    def test_startup_line_yields_single_date(self):
        line = (
            r"Startup: C:\Users\bob\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\foo.lnk [2026-04-17]"
        )
        self.assertEqual(self._dates_for(line), ["2026-04-17"])

    def test_onemonth_line_yields_both_timestamps(self):
        line = (
            r"2026-04-18 14:32:18 - 2026-04-15 09:00:00 - 0001234 _____ "
            r"(Microsoft Corporation) C:\Windows\System32\foo.exe"
        )
        self.assertEqual(
            self._dates_for(line),
            ["2026-04-18 14:32:18", "2026-04-15 09:00:00"],
        )

    def test_onemonth_line_dedupes_identical_timestamps(self):
        line = (
            r"2026-03-18 13:45 - 2026-03-18 13:45 - 000000000 ____D "
            r"C:\Program Files\Proton\VPN\v4.3.13"
        )
        self.assertEqual(self._dates_for(line), ["2026-03-18 13:45"])

    def test_unparseable_line_yields_empty_dates(self):
        line = "this is not a frst entry of any recognised shape"
        self.assertEqual(self._dates_for(line), [])

    def test_line_without_date_yields_empty_dates(self):
        line = (
            r"Startup: C:\Users\bob\AppData\Roaming\Microsoft\Windows"
            r"\Start Menu\Programs\Startup\foo.lnk"
        )
        self.assertEqual(self._dates_for(line), [])
