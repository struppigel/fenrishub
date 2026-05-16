"""Regression tests for company captures with nested parens.

Before this fix, runkey, service, and activesetup extractors used
`\\(([^\\)]*)\\)` for company, which stopped at the first nested `)` and
truncated companies like `Intel(R)` to `Intel(R` (61+ such cases in the live DB).
"""

from django.test import TestCase

from ..frst_extractors import (
    extract_frst_activesetup,
    extract_frst_runkey,
    extract_frst_service,
)


class ServiceExtractorNestedParensTests(TestCase):
    def test_lenovo_beijing(self):
        line = (
            r"R1 hotfixplatform; C:\Windows\system32\drivers\hotfixplatform.sys "
            r"[46168 2024-09-24] (Lenovo (Beijing) Limited -> )"
        )
        entry = extract_frst_service(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.company, "Lenovo (Beijing) Limited ->")

    def test_realix_tm(self):
        line = (
            r"R1 HWiNFO32; C:\Windows\SysWOW64\drivers\HWiNFO64A.SYS "
            r"[27552 2017-12-19] (Martin Malik - REALiX -> REALiX(tm))"
        )
        entry = extract_frst_service(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.company, "Martin Malik - REALiX -> REALiX(tm)")

    def test_netease_hangzhou(self):
        line = (
            r"R1 MuMuVMMDrv; C:\Program Files\MuMuVMMVbox\LoadedDrivers\MuMuVMMDrv.sys "
            r"[366808 2025-09-10] (NetEase (Hangzhou) Network Co., Ltd -> NetEase Corporation)"
        )
        entry = extract_frst_service(line)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.company, "NetEase (Hangzhou) Network Co., Ltd -> NetEase Corporation"
        )

    def test_microsoft_with_inner_parens(self):
        line = (
            r"R1 netfilter2; C:\WINDOWS\System32\drivers\netfilter2.sys "
            r"[79504 2017-03-13] "
            r"(Microsoft Windows Hardware Compatibility Publisher -> Windows (R) Win 7 DDK provider)"
        )
        entry = extract_frst_service(line)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.company,
            "Microsoft Windows Hardware Compatibility Publisher -> Windows (R) Win 7 DDK provider",
        )

    def test_qualcomm_test_only_marker(self):
        line = (
            r"R1 QcSOCPartition; "
            r"C:\WINDOWS\System32\DriverStore\FileRepository\qcsocpartition.inf_arm64_ab0ef651cc2c31ea\QcSOCPartition.sys "
            r"[278912 2021-08-27] "
            r"(Windows OEM Test Cert 2017 (TEST ONLY) -> Qualcomm Technologies, Inc.)"
        )
        entry = extract_frst_service(line)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.company,
            "Windows OEM Test Cert 2017 (TEST ONLY) -> Qualcomm Technologies, Inc.",
        )

    def test_company_capture_unchanged_for_simple_case(self):
        line = (
            r"R2 OneApp.IGCC.WinService; "
            r"C:\Program Files (x86)\Intel\OneApp\IGCC.WinService.exe "
            r"[123456 2024-01-01] (Intel Corporation -> Intel Corporation)"
        )
        entry = extract_frst_service(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.company, "Intel Corporation -> Intel Corporation")


class RunkeyExtractorNestedParensTests(TestCase):
    def test_intel_r_rapid_storage(self):
        line = (
            r"HKLM\...\Run: [IAStorIcon] => "
            r"C:\Program Files\Intel\Intel(R) Rapid Storage Technology\IAStorIcon.exe "
            r"[321096 2017-07-26] (Intel(R) Rapid Storage Technology -> Intel Corporation)"
        )
        entry = extract_frst_runkey(line)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.company, "Intel(R) Rapid Storage Technology -> Intel Corporation"
        )

    def test_steam_concatenated_with_trailing_paren_group(self):
        # Real-world concatenated runkey line where the company is followed by
        # another `(...)` group (process-style continuation). The company must
        # still be `Valve Corp. -> Valve Corporation`, not empty.
        line = (
            r"HKU\S-1-5-21-452909219-3126049660-382430182-1000\...\Run: [Steam] => "
            r"C:\Program Files (x86)\Steam\steam.exe [4698720 2025-06-28] "
            r"(Valve Corp. -> Valve Corporation)"
            r"(C:\Program Files\GIGABYTE\Control Center\GCC.exe ->) "
            r"(GIGA-BYTE TECHNOLOGY CO., LTD. -> GBT_DL_LIB) "
            r"C:\Program Files\WindowsApps\foo.exe"
        )
        entry = extract_frst_runkey(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filepath, r"C:\Program Files (x86)\Steam\steam.exe")
        self.assertEqual(entry.date, "4698720 2025-06-28")
        self.assertEqual(entry.company, "Valve Corp. -> Valve Corporation")


class RunkeyArgumentsSplitTests(TestCase):
    """When a runkey value embeds a binary + args, the filepath must hold only
    the binary and `arguments` must capture the rest. Pre-fix, lines without a
    `[date]` block dumped everything into filepath."""

    def test_conhost_powershell_command_splits(self):
        line = (
            r"HKU\S-1-5-21-1004897451-227671751-2029699546-1001\...\Run: "
            r"[WindowsPowerShell_v1.0 CL_NCL] => "
            r'conhost.exe --headless powershell.exe -NoP -ExecutionPolicy Bypass '
            r'-WindowStyle Hidden -Command "" (No File)'
        )
        entry = extract_frst_runkey(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filepath, "conhost.exe")
        self.assertIn("--headless", entry.arguments)
        self.assertIn("powershell.exe", entry.arguments)
        self.assertNotIn("(No File)", entry.arguments)

    def test_quoted_path_with_arg_splits(self):
        line = (
            r"HKLM\...\Run: [Foo] => "
            r'"C:\Program Files\App\app.exe" -arg [123 2024-01-01] (Co)'
        )
        entry = extract_frst_runkey(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filepath, r"C:\Program Files\App\app.exe")
        self.assertEqual(entry.arguments, "-arg")

    def test_no_args_leaves_arguments_empty(self):
        line = (
            r"HKLM\...\Run: [Foo] => "
            r"C:\Program Files\App\app.exe [123 2024-01-01] (Co)"
        )
        entry = extract_frst_runkey(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filepath, r"C:\Program Files\App\app.exe")
        self.assertEqual(entry.arguments, "")


class ActivesetupExtractorNestedParensTests(TestCase):
    def test_lenovo_beijing(self):
        line = (
            r"HKLM\Software\Microsoft\Active Setup\Installed Components: "
            r"[{7D2B3E1D-D096-4594-9D8F-A6667F12E0AC}] -> "
            r"C:\Program Files (x86)\Lenovo\SLBrowser\9.0.7.12231\Installer\chrmstp.exe "
            r"[2025-12-23] (Lenovo (Beijing) Limited -> Lenovo)"
        )
        entry = extract_frst_activesetup(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.company, "Lenovo (Beijing) Limited -> Lenovo")
