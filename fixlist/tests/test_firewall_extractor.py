from django.test import TestCase

from ..frst_extractors import extract_firewall_rule, get_frst_entry, normalize_path


class ExtractFirewallRuleTests(TestCase):
    """Tests for the firewall rule FRST entry extractor."""

    # -- GUID-only format --

    def test_guid_allow_with_company(self):
        line = (
            r"FirewallRules: [{854C03D7-A445-4A50-AA06-CA6E5F44A529}] => (Allow) "
            r"C:\Program Files\WindowsApps\MicrosoftTeams_24215.1105.3082.1600_x64__8wekyb3d8bbwe\msteams.exe "
            r"(Microsoft Corporation -> Microsoft Corporation)"
        )
        entry = extract_firewall_rule(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "firewall")
        self.assertEqual(entry.clsid, "854C03D7-A445-4A50-AA06-CA6E5F44A529")
        self.assertEqual(entry.name, "Allow")
        self.assertEqual(entry.filename, "msteams.exe")
        self.assertEqual(entry.company, "Microsoft Corporation")
        self.assertIn("msteams.exe", entry.filepath)

    def test_guid_no_file_returns_none(self):
        line = (
            r"FirewallRules: [{7CE56DB8-8DEC-4536-AD1E-CAF9CC8A3AE6}] => (Allow) "
            r"C:\Program Files (x86)\Brother\DriverTemp\Package\BSQ16A-2025-06-26-11-42-25-578\start.exe => No File"
        )
        self.assertIsNone(extract_firewall_rule(line))

    def test_guid_block_no_file_returns_none(self):
        line = (
            r"FirewallRules: [{D060F973-9882-47FF-B2D3-BBC30BDEBEFD}] => (Allow) "
            r"C:\Windows\System32\DriverStore\FileRepository\asussci2.inf_amd64_4fc38a913e0f2ea5"
            r"\ASUSLinkRemote\AsusLinkRemoteAgent.exe => No File"
        )
        self.assertIsNone(extract_firewall_rule(line))

    # -- TCP/UDP Query User format --

    def test_tcp_query_user_block_with_company(self):
        line = (
            r"FirewallRules: [TCP Query User{97B5CCE5-DCDD-48AB-B8B4-BBA31F8BB830}"
            r"C:\users\rbpon\appdata\local\thinkorswim\jxbrowser\v29\bin\chromium.exe] => (Block) "
            r"C:\users\rbpon\appdata\local\thinkorswim\jxbrowser\v29\bin\chromium.exe "
            r"(TeamDev Management OU -> The Chromium Authors)"
        )
        entry = extract_firewall_rule(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "firewall")
        self.assertEqual(entry.clsid, "97B5CCE5-DCDD-48AB-B8B4-BBA31F8BB830")
        self.assertEqual(entry.name, "Block")
        self.assertEqual(entry.filename, "chromium.exe")
        self.assertEqual(entry.company, "The Chromium Authors")

    def test_udp_query_user_allow_with_company(self):
        line = (
            r"FirewallRules: [UDP Query User{5B92B9E4-D93D-423F-83D1-BDFE276EC4B6}"
            r"C:\users\rbpon\appdata\local\programs\trezor suite\trezor suite.exe] => (Allow) "
            r"C:\users\rbpon\appdata\local\programs\trezor suite\trezor suite.exe "
            r"(Trezor Company s.r.o. -> SatoshiLabs)"
        )
        entry = extract_firewall_rule(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "firewall")
        self.assertEqual(entry.clsid, "5B92B9E4-D93D-423F-83D1-BDFE276EC4B6")
        self.assertEqual(entry.name, "Allow")
        self.assertEqual(entry.company, "SatoshiLabs")
        self.assertEqual(entry.filename, "trezor suite.exe")

    def test_udp_query_user_block_without_company(self):
        """Query User line without company or No File should still parse."""
        line = (
            r"FirewallRules: [UDP Query User{E5B05654-6E4F-4B66-8974-20DE9BF68DDE}"
            r"C:\users\rbpon\appdata\local\thinkorswim\jxbrowser\v28\bin\chromium.exe] => (Block) "
            r"C:\users\rbpon\appdata\local\thinkorswim\jxbrowser\v28\bin\chromium.exe"
        )
        entry = extract_firewall_rule(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.clsid, "E5B05654-6E4F-4B66-8974-20DE9BF68DDE")
        self.assertEqual(entry.name, "Block")
        self.assertEqual(entry.filename, "chromium.exe")
        self.assertEqual(entry.company, "")

    def test_tcp_query_user_no_file_returns_none(self):
        line = (
            r"FirewallRules: [TCP Query User{BA93DFFC-6E67-47B9-AA60-99563FE6FF0B}"
            r"C:\users\rbpon\appdata\local\thinkorswim\jxbrowser\v28\bin\chromium.exe] => (Block) "
            r"C:\users\rbpon\appdata\local\thinkorswim\jxbrowser\v28\bin\chromium.exe => No File"
        )
        self.assertIsNone(extract_firewall_rule(line))

    # -- Allow vs Block distinction --

    def test_allow_and_block_are_different_entries(self):
        """Two rules for the same file but different actions should not be equal."""
        allow_line = (
            r"FirewallRules: [{AAAA0000-0000-0000-0000-000000000000}] => (Allow) "
            r"C:\Program Files\app.exe (Corp -> Corp)"
        )
        block_line = (
            r"FirewallRules: [{AAAA0000-0000-0000-0000-000000000000}] => (Block) "
            r"C:\Program Files\app.exe (Corp -> Corp)"
        )
        allow_entry = extract_firewall_rule(allow_line)
        block_entry = extract_firewall_rule(block_line)
        self.assertIsNotNone(allow_entry)
        self.assertIsNotNone(block_entry)
        self.assertEqual(allow_entry.name, "Allow")
        self.assertEqual(block_entry.name, "Block")
        self.assertEqual(allow_entry.clsid, block_entry.clsid)
        self.assertNotEqual(allow_entry, block_entry)

    # -- Non-firewall lines --

    def test_non_firewall_line_returns_none(self):
        self.assertIsNone(extract_firewall_rule(r"HKLM\...\Run: [TestApp] => C:\test.exe"))

    def test_empty_line_returns_none(self):
        self.assertIsNone(extract_firewall_rule(""))

    # -- Path normalization --

    def test_filepath_normalized(self):
        """User paths should be normalized (username replaced)."""
        line = (
            r"FirewallRules: [{4C69B492-A29C-4BF5-99BF-78F820386083}] => (Allow) "
            r"C:\Users\RBpon\AppData\Local\Programs\app.exe "
            r"(Some Corp -> Some Corp)"
        )
        entry = extract_firewall_rule(line)
        self.assertIsNotNone(entry)
        self.assertIn("username", entry.filepath)
        self.assertNotIn("RBpon", entry.filepath)

    def test_firefox_profile_segment_normalized(self):
        path = (
            r"C:\Users\blake\AppData\Roaming\Mozilla\Firefox\Profiles"
            r"\kpxj5wcs.default-release-1694654727183\Extensions"
            r"\mozilla_cc3@internetdownloadmanager.com.xpi"
        )

        normalized = normalize_path(path)

        self.assertEqual(
            normalized,
            r"C:\Users\username\AppData\Roaming\Mozilla\Firefox\Profiles"
            r"\profile\Extensions\mozilla_cc3@internetdownloadmanager.com.xpi",
        )

    # -- Integration with get_frst_entry --

    def test_get_frst_entry_finds_firewall(self):
        line = (
            r"FirewallRules: [{5D364138-B5DA-4CEA-813D-837A47C26DF5}] => (Allow) "
            r"C:\Program Files\Google\Chrome\Application\chrome.exe "
            r"(Google LLC -> Google LLC)"
        )
        entry = get_frst_entry(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "firewall")
        self.assertEqual(entry.filename, "chrome.exe")
        self.assertEqual(entry.clsid, "5D364138-B5DA-4CEA-813D-837A47C26DF5")
        self.assertEqual(entry.name, "Allow")

    def test_get_frst_entry_skips_no_file(self):
        line = (
            r"FirewallRules: [{B65FBAB4-7110-47F2-8079-723C32F79125}] => (Allow) "
            r"C:\Users\RBpon\AppData\Roaming\Zoom\bin\airhost.exe => No File"
        )
        entry = get_frst_entry(line)
        self.assertIsNone(entry)
