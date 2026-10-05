from django.test import TestCase

from ..frst_extractors import (
    extract_frst_service,
    extract_installed_software,
    installed_software_uninstall_key,
)


GUID_LINE = (
    r"Adobe AIR (HKLM-x32\...\{10E33ABF-D7FB-4F47-900A-7973854AB45A}) "
    r"(Version: 32.0.0.144 - Adobe) Hidden"
)
NAMED_LINE = (
    r"Adobe AIR (HKLM-x32\...\Adobe AIR) (Version: 32.0.0.144 - Adobe)"
)


class ExtractInstalledSoftwareTests(TestCase):

    def test_msi_product_code_not_captured_into_clsid(self):
        """MSI Product Code GUIDs are intentionally NOT captured because third-
        party / PUP installers often generate per-install GUIDs that would
        break cross-system matching. Differentiation relies on is_hidden,
        name, and company instead."""
        entry = extract_installed_software(GUID_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "installed_software")
        self.assertEqual(entry.name, "Adobe AIR")
        self.assertEqual(entry.clsid, "")
        self.assertEqual(entry.company, "Adobe")

    def test_hidden_suffix_sets_is_hidden_true(self):
        entry = extract_installed_software(GUID_LINE)
        self.assertTrue(entry.is_hidden)

    def test_non_guid_uninstall_key_leaves_clsid_empty(self):
        entry = extract_installed_software(NAMED_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.clsid, "")
        self.assertEqual(entry.name, "Adobe AIR")

    def test_no_hidden_suffix_sets_is_hidden_false(self):
        entry = extract_installed_software(NAMED_LINE)
        self.assertFalse(entry.is_hidden)

    def test_guid_and_named_lines_are_not_equal(self):
        """The user's exact case: two Adobe AIR rows that should NOT collapse."""
        a = extract_installed_software(GUID_LINE)
        b = extract_installed_software(NAMED_LINE)
        self.assertIsNotNone(a)
        self.assertIsNotNone(b)
        self.assertNotEqual(a, b)

    def test_is_hidden_does_not_trigger_for_unrelated_lines(self):
        """A line that ends with ') Hidden' but isn't from the Installed
        Programs section must NOT have is_hidden set — the flag is scoped to
        entry_type == 'installed_software' only."""
        # Construct a service-style line that (artificially) ends with
        # ") Hidden". It parses as a service, so is_hidden must remain False.
        service_line = (
            r"R2 FakeSvc; C:\Windows\foo.exe [1234 2024-01-01] (Acme) Hidden"
        )
        entry = extract_frst_service(service_line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "service")
        self.assertFalse(entry.is_hidden)

    def test_is_hidden_false_for_non_hidden_installed_software(self):
        not_hidden = (
            r"Adobe AIR (HKLM-x32\...\{10E33ABF-D7FB-4F47-900A-7973854AB45A}) "
            r"(Version: 32.0.0.144 - Adobe)"
        )
        entry = extract_installed_software(not_hidden)
        self.assertFalse(entry.is_hidden)


class InstalledSoftwareUninstallKeyTests(TestCase):
    r"""FRST shortens the uninstall key to `HIVE\...\KEY`; the copy menu offers
    the key name and the full key rebuilt from the hive."""

    UNINSTALL = r"Microsoft\Windows\CurrentVersion\Uninstall"

    def test_hklm_x32_expands_to_wow6432node(self):
        line = (
            r"Wireless Utility (HKLM-x32\...\{81FBE49E-CFE9-44C3-BD74-9EAF39953649}) "
            r"(Version: 6.5 - Broadcom Inc.)"
        )
        self.assertEqual(
            installed_software_uninstall_key(line),
            (
                "{81FBE49E-CFE9-44C3-BD74-9EAF39953649}",
                rf"HKLM\SOFTWARE\WOW6432Node\{self.UNINSTALL}\{{81FBE49E-CFE9-44C3-BD74-9EAF39953649}}",
            ),
        )

    def test_hklm_expands_to_software(self):
        line = (
            r"Windows PC Health Check (HKLM\...\{6798C408-2636-448C-8AC6-F4E341102D27}) "
            r"(Version: 3.6.2204.08001 - Microsoft Corporation)"
        )
        self.assertEqual(
            installed_software_uninstall_key(line),
            (
                "{6798C408-2636-448C-8AC6-F4E341102D27}",
                rf"HKLM\SOFTWARE\{self.UNINSTALL}\{{6798C408-2636-448C-8AC6-F4E341102D27}}",
            ),
        )

    def test_hidden_suffix_does_not_end_up_in_key(self):
        line = (
            r"UsbRepairTool (HKLM-x32\...\{F8762A81-32B5-4144-9F3C-9274F515A651}) "
            r"(Version: 1.4.0.0 - Brother Industries, Ltd.) Hidden"
        )
        key, path = installed_software_uninstall_key(line)
        self.assertEqual(key, "{F8762A81-32B5-4144-9F3C-9274F515A651}")
        self.assertTrue(path.endswith(r"\Uninstall\{F8762A81-32B5-4144-9F3C-9274F515A651}"))

    def test_hku_keeps_sid_and_named_key(self):
        sid = "S-1-5-21-2331057209-136270744-4161921719-1001"
        line = (
            rf"Zoom Workplace (HKU\{sid}\...\ZoomUMX) "
            r"(Version: 7.1.9 (48550) - Zoom Communications, Inc.)"
        )
        self.assertEqual(
            installed_software_uninstall_key(line),
            ("ZoomUMX", rf"HKU\{sid}\Software\{self.UNINSTALL}\ZoomUMX"),
        )

    def test_key_with_parens_is_kept_whole(self):
        line = (
            r"Mozilla Firefox (x64 en-US) (HKLM\...\Mozilla Firefox 128.0 (x64 en-US)) "
            r"(Version: 128.0 - Mozilla)"
        )
        key, path = installed_software_uninstall_key(line)
        self.assertEqual(key, "Mozilla Firefox 128.0 (x64 en-US)")
        self.assertEqual(path, rf"HKLM\SOFTWARE\{self.UNINSTALL}\Mozilla Firefox 128.0 (x64 en-US)")

    def test_description_suffix_is_ignored(self):
        line = NAMED_LINE + "|||Description: (Version: 1 - Foo)"
        self.assertEqual(installed_software_uninstall_key(line)[0], "Adobe AIR")

    def test_line_without_uninstall_key_returns_none(self):
        self.assertIsNone(installed_software_uninstall_key(
            r"R2 FakeSvc; C:\Windows\foo.exe [1234 2024-01-01] (Acme)"
        ))
