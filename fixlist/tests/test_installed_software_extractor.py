from django.test import TestCase

from ..frst_extractors import extract_frst_service, extract_installed_software


GUID_LINE = (
    r"Adobe AIR (HKLM-x32\...\{10E33ABF-D7FB-4F47-900A-7973854AB45A}) "
    r"(Version: 32.0.0.144 - Adobe) Hidden"
)
NAMED_LINE = (
    r"Adobe AIR (HKLM-x32\...\Adobe AIR) (Version: 32.0.0.144 - Adobe)"
)


class ExtractInstalledSoftwareTests(TestCase):

    def test_msi_product_code_captured_into_clsid(self):
        entry = extract_installed_software(GUID_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "installed_software")
        self.assertEqual(entry.name, "Adobe AIR")
        self.assertEqual(entry.clsid, "10E33ABF-D7FB-4F47-900A-7973854AB45A")
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
