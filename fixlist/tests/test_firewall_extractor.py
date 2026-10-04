from django.test import TestCase

from ..analyzer import inspect_line_matches, invalidate_rule_buckets_cache
from ..frst_extractors import extract_firewall_rule, get_frst_entry, normalize_path, path_search_start
from ..models import ClassificationRule
from .factories import make_rule

# Real lines from badlog2.txt. FRST ends a firewall rule's target with
# `(Signer -> Company)` when the file is signed and `(Company) [File not signed]`
# when it isn't; either name can be empty.
SIGNED_LINE = (
    r"FirewallRules: [{EEE78C2B-BF0C-42A2-A005-83DDAB47249E}] => (Allow) "
    r"C:\Program Files (x86)\Steam\bin\cef\cef.win64\steamwebhelper.exe (Valve Corp. -> Valve Corporation)"
)
SIGNED_NO_COMPANY_LINE = (
    r"FirewallRules: [{8E48BC75-A166-42A4-B40D-85F29F2F4A50}] => (Allow) "
    r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe (Cloudflare, Inc. -> )"
)
UNSIGNED_LINE = (
    r"FirewallRules: [{C4252B8B-11D7-42A9-A9EA-3663F73FDE47}] => (Allow) "
    r"F:\SteamLibrary\steamapps\common\Dead as Disco\Pagoda.exe (Epic Games, Inc.) [File not signed]"
)
UNSIGNED_NO_COMPANY_LINE = (
    r"FirewallRules: [{CEB7DAAC-72E9-499E-97B3-C0198FE0C7FD}] => (Allow) "
    r"A:\SteamLibrary\steamapps\common\Library Of Ruina\LibraryOfRuina.exe () [File not signed]"
)
QUERY_USER_LINE = (
    r"FirewallRules: [TCP Query User{CB374BDA-2B92-42F7-8D0A-728CF9725B43}"
    r"C:\program files\gigabyte\control center\gcc.exe] => (Allow) "
    r"C:\program files\gigabyte\control center\gcc.exe (GIGA-BYTE TECHNOLOGY CO., LTD. -> )"
)


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
        # Firewall rule GUIDs are per-system random — intentionally not captured.
        self.assertEqual(entry.clsid, "")
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
        self.assertEqual(entry.clsid, "")
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
        self.assertEqual(entry.clsid, "")
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
        self.assertEqual(entry.clsid, "")
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

    # -- Paths containing parentheses (e.g. Program Files (x86)) --

    def test_parenthesized_path_with_company(self):
        """A path with parentheses must parse; the trailing company suffix is
        still peeled off at the end."""
        line = (
            r"FirewallRules: [{AAAA0000-0000-0000-0000-000000000001}] => (Block) "
            r"C:\Program Files (x86)\Foo\evil.exe (Acme Inc -> Acme Signer)"
        )
        entry = extract_firewall_rule(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "firewall")
        self.assertEqual(entry.name, "Block")
        self.assertEqual(entry.company, "Acme Signer")
        self.assertEqual(entry.filename, "evil.exe")
        self.assertIn(r"Program Files (x86)", entry.filepath)

    def test_parenthesized_path_without_company(self):
        line = (
            r"FirewallRules: [{AAAA0000-0000-0000-0000-000000000002}] => (Allow) "
            r"C:\Program Files (x86)\Foo Bar\app.exe"
        )
        entry = extract_firewall_rule(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "Allow")
        self.assertEqual(entry.company, "")
        self.assertEqual(entry.filename, "app.exe")
        self.assertIn(r"Program Files (x86)", entry.filepath)

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
        self.assertEqual(entry.clsid, "")
        self.assertEqual(entry.name, "Allow")

    def test_get_frst_entry_skips_no_file(self):
        line = (
            r"FirewallRules: [{B65FBAB4-7110-47F2-8079-723C32F79125}] => (Allow) "
            r"C:\Users\RBpon\AppData\Roaming\Zoom\bin\airhost.exe => No File"
        )
        entry = get_frst_entry(line)
        self.assertIsNone(entry)

    def test_equality_ignores_stored_clsid_for_firewall(self):
        """A pre-existing rule still carrying a stored CLSID (from before this
        change) must still match a freshly-parsed firewall entry whose CLSID is
        now empty — otherwise the rescan-all step would become mandatory."""
        from ..frst_extractors import FrstEntry

        legacy_rule_entry = FrstEntry(
            clsid="854C03D7-A445-4A50-AA06-CA6E5F44A529",
            name="Allow",
            filepath=r"C:\Program Files\foo.exe",
            filename="foo.exe",
            company="Corp",
            entry_type="firewall",
        )
        freshly_parsed = FrstEntry(
            clsid="",  # new extractor leaves this empty
            name="Allow",
            filepath=r"C:\Program Files\foo.exe",
            filename="foo.exe",
            company="Corp",
            entry_type="firewall",
        )
        self.assertEqual(legacy_rule_entry, freshly_parsed)


class FirewallTargetSuffixTests(TestCase):
    """What follows the target ends the path and fills the company -- it must
    never be left in the path or the arguments."""

    def test_signed_target(self):
        entry = extract_firewall_rule(SIGNED_LINE)
        self.assertEqual(entry.filepath, r"C:\Program Files (x86)\Steam\bin\cef\cef.win64\steamwebhelper.exe")
        self.assertEqual(entry.company, "Valve Corporation")
        self.assertEqual(entry.arguments, "")
        self.assertFalse(entry.file_not_signed)

    def test_signed_target_without_company(self):
        entry = extract_firewall_rule(SIGNED_NO_COMPANY_LINE)
        self.assertEqual(entry.filepath, r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe")
        self.assertEqual(entry.company, "")
        self.assertEqual(entry.arguments, "")

    def test_unsigned_target_keeps_its_company(self):
        entry = extract_firewall_rule(UNSIGNED_LINE)
        self.assertEqual(entry.filepath, r"C:\SteamLibrary\steamapps\common\Dead as Disco\Pagoda.exe")
        self.assertEqual(entry.company, "Epic Games, Inc.")
        self.assertEqual(entry.arguments, "")
        self.assertTrue(entry.file_not_signed)

    def test_unsigned_target_without_company(self):
        entry = extract_firewall_rule(UNSIGNED_NO_COMPANY_LINE)
        self.assertEqual(entry.filepath, r"C:\SteamLibrary\steamapps\common\Library Of Ruina\LibraryOfRuina.exe")
        self.assertEqual(entry.company, "")
        self.assertEqual(entry.arguments, "")
        self.assertTrue(entry.file_not_signed)

    def test_unsigned_target_that_is_not_a_program(self):
        # Without a program extension to split at, only the suffix ends the path.
        entry = extract_firewall_rule(UNSIGNED_LINE.replace("Pagoda.exe", "Pagoda.pak"))
        self.assertEqual(entry.filepath, r"C:\SteamLibrary\steamapps\common\Dead as Disco\Pagoda.pak")
        self.assertEqual(entry.company, "Epic Games, Inc.")

    def test_attention_marker_after_the_suffix(self):
        entry = extract_firewall_rule(SIGNED_NO_COMPANY_LINE + " <==== ATTENTION")
        self.assertEqual(entry.filepath, r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-svc.exe")
        self.assertEqual(entry.company, "")
        self.assertEqual(entry.arguments, "")

    def test_query_user_target(self):
        entry = extract_firewall_rule(QUERY_USER_LINE)
        self.assertEqual(entry.filepath, r"C:\program files\gigabyte\control center\gcc.exe")
        self.assertEqual(entry.company, "")
        self.assertEqual(entry.arguments, "")


class PathSearchStartTests(TestCase):

    def test_query_user_rule_is_searched_from_its_target(self):
        # The rule's name repeats the path; only the copy after the action counts.
        target = QUERY_USER_LINE.index("(Allow) ") + len("(Allow) ")
        self.assertEqual(path_search_start(QUERY_USER_LINE), target)

    def test_other_lines_are_searched_from_the_start(self):
        self.assertEqual(path_search_start(r"HKLM\...\Run: [TestApp] => C:\test.exe"), 0)


class FirewallFilepathMatchingTests(TestCase):
    """A filepath rule should match firewall entries, including paths that
    contain parentheses (which previously failed to parse entirely)."""

    PATH = r"C:\Program Files (x86)\Foo\evil.exe"

    def setUp(self):
        invalidate_rule_buckets_cache()
        make_rule(
            self.PATH,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_FILEPATH,
            normalized_filepath=self.PATH,
        )
        invalidate_rule_buckets_cache()

    def test_allow_firewall_with_parenthesized_path_matches_filepath_rule(self):
        line = (
            r"FirewallRules: [{AAAA0000-0000-0000-0000-000000000003}] => (Allow) "
            + self.PATH
            + r" (Acme Inc -> Acme Signer)"
        )
        self.assertEqual(
            inspect_line_matches(line)["dominant_status"],
            ClassificationRule.STATUS_MALWARE,
        )

    def test_block_firewall_with_parenthesized_path_also_matches(self):
        # Behavior is unchanged by this fix: Block entries keep matching too.
        line = (
            r"FirewallRules: [{AAAA0000-0000-0000-0000-000000000004}] => (Block) "
            + self.PATH
            + r" (Acme Inc -> Acme Signer)"
        )
        self.assertEqual(
            inspect_line_matches(line)["dominant_status"],
            ClassificationRule.STATUS_MALWARE,
        )


class FirewallUnsignedFilepathMatchingTests(TestCase):
    """The `(Company) [File not signed]` suffix used to stay in the path when
    the target has no program extension, so no filepath rule could match it."""

    PATH = r"C:\SteamLibrary\steamapps\common\Dead as Disco\Pagoda.pak"

    def setUp(self):
        invalidate_rule_buckets_cache()
        make_rule(
            self.PATH,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_FILEPATH,
            normalized_filepath=self.PATH.lower(),
        )
        invalidate_rule_buckets_cache()

    def test_filepath_rule_matches_unsigned_target(self):
        line = UNSIGNED_LINE.replace("Pagoda.exe", "Pagoda.pak")
        self.assertEqual(
            inspect_line_matches(line)["dominant_status"],
            ClassificationRule.STATUS_MALWARE,
        )
