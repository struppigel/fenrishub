import json

from django.urls import reverse

from ..models import ClassificationRule
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase


class LogAnalyzerApiWarningTests(LogAnalyzerApiBaseTestCase):

    def test_analyze_api_returns_incomplete_log_warning(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Scan result of Farbar Recovery Scan Tool\n"
                    "Some FRST content without end markers"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warning_codes = {warning["code"] for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("incomplete_logs", warning_codes)
        self.assertEqual(payload["summary"]["warning_count"], len(payload["warnings"]))

    def test_analyze_api_returns_low_memory_warning(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Percentage of memory in use: 91%\n"
                    "Total physical RAM: 2048 MB\n"
                    "Drive C: (Windows) (Free:50 GB)\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("low_memory", warnings_by_code)
        self.assertIn("RAM usage above 80%", warnings_by_code["low_memory"]["message"])

    def test_analyze_api_does_not_warn_for_disk_space_at_50_gb_when_other_memory_signals_are_healthy(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Percentage of memory in use: 48%\n"
                    "Total physical RAM: 16384 MB\n"
                    "Drive C: (Windows) (Free:50 GB)\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("low_memory", warnings_by_code)

    def test_analyze_api_warns_for_disk_space_below_50_gb_when_other_memory_signals_are_healthy(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Percentage of memory in use: 48%\n"
                    "Total physical RAM: 16384 MB\n"
                    "Drive C: (Windows) (Free:49 GB)\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("low_memory", warnings_by_code)
        self.assertIn("below 50 GB", warnings_by_code["low_memory"]["message"])

    def test_analyze_api_returns_alert_warning_from_matched_alert_rule_description(self):
        self.client.login(username="analyzer", password="password123")
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="ALERT-LINE",
            description="Investigate this suspicious pattern",
        )

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": "ALERT-LINE\nOTHER-LINE"}),
            content_type="application/json",
        )

        payload = response.json()
        warnings = payload["warnings"]
        alert_warnings = [w for w in warnings if w.get("title") == "Alert rule matched"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(alert_warnings), 1)
        self.assertEqual(alert_warnings[0]["message"], "Investigate this suspicious pattern")

    def test_analyze_api_deduplicates_alert_warnings_for_same_description(self):
        self.client.login(username="analyzer", password="password123")
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="ALERT-LINE-1",
            description="Shared alert description",
        )
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="ALERT-LINE-2",
            description="Shared alert description",
        )

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps({"log": "ALERT-LINE-1\nALERT-LINE-2"}),
            content_type="application/json",
        )

        payload = response.json()
        warnings = payload["warnings"]
        alert_warnings = [w for w in warnings if w.get("title") == "Alert rule matched"]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(alert_warnings), 1)
        self.assertEqual(alert_warnings[0]["message"], "Shared alert description")

    def test_analyze_api_accepts_windows_ssd_drive_line_for_memory_check(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "BIOS: LENOVO KZCN40WW 10/18/2023\n"
                    "Motherboard: LENOVO LNVNB161216\n"
                    "Processor: 13th Gen Intel(R) Core(TM) i5-13500H\n"
                    "Percentage of memory in use: 67%\n"
                    "Total physical RAM: 16123.87 MB\n"
                    "Available physical RAM: 5196.51 MB\n"
                    "Total Virtual: 30459.87 MB\n"
                    "Available Virtual: 13730.64 MB\n"
                    "Drive c: (Windows-SSD) (Fixed) (Total:951.65 GB) (Free:260.94 GB) (Model: SAMSUNG MZAL41T0HBLB-00BL2) (Protected) NTFS\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("low_memory", warnings_by_code)

    def test_analyze_api_accepts_drive_c_without_windows_label_for_memory_check(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Percentage of memory in use: 48%\n"
                    "Total physical RAM: 16107.87 MB\n"
                    "Available physical RAM: 8322.04 MB\n"
                    "Drive c: () (Fixed) (Total:952.91 GB) (Free:901.65 GB) (Model: SAMSUNG MZVL21T0HCLR-00BL2) NTFS\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("low_memory", warnings_by_code)

    def test_analyze_api_warns_when_multiple_enabled_av_entries_found(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "AV: Malwarebytes (Enabled - Up to date) {A537353A-1D6A-F6B5-9153-CE1CF80FBE66}\n"
                    "AV: Windows Defender (Enabled - Up to date) {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}\n"
                    "AV: ESET Security (Enabled - Up to date) {26E0861C-6FB9-CEF9-E4F0-531986211ACE}\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("multiple_enabled_av", warnings_by_code)
        self.assertIn("Multiple AV products are enabled", warnings_by_code["multiple_enabled_av"]["message"])

    def test_analyze_api_does_not_warn_for_same_av_product_multiple_entries(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "AV: Kaspersky (Enabled - Up to date) {DABD1ABC-6D70-BB0E-89E6-BFA3FC920FD1}\n"
                    "AV: Kaspersky (Enabled - Up to date) {70E35457-C7D9-669C-FEA5-55382EABDC78}\n"
                    "AV: Windows Defender (Disabled - Up to date) {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}\n"
                    "AV: Kaspersky (Enabled - Up to date) {4F76F112-43EB-40E8-11D8-F7BD1853EA23}\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warning_codes = {warning["code"] for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("multiple_enabled_av", warning_codes)

    def test_analyze_api_does_not_warn_for_single_enabled_av_entry(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "AV: Windows Defender (Enabled - Up to date) {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}\n"
                    "AV: ESET Security (Disabled - Out of date) {26E0861C-6FB9-CEF9-E4F0-531986211ACE}\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warning_codes = {warning["code"] for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("multiple_enabled_av", warning_codes)

    def test_analyze_api_flags_memory_incomplete_when_drive_info_missing(self):
        self.client.login(username="analyzer", password="password123")

        response = self.client.post(
            reverse("analyze_log_api"),
            data=json.dumps(
                {
                    "log": "Percentage of memory in use: 67%\n"
                    "Total physical RAM: 16123.87 MB\n"
                    "Available physical RAM: 5196.51 MB\n"
                }
            ),
            content_type="application/json",
        )

        payload = response.json()
        warnings_by_code = {warning["code"]: warning for warning in payload["warnings"]}

        self.assertEqual(response.status_code, 200)
        self.assertIn("low_memory", warnings_by_code)
        self.assertIn("Memory information incomplete", warnings_by_code["low_memory"]["message"])
