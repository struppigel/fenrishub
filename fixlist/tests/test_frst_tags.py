"""FRST's bracket tags after a file's company (`[File not signed]`, `[File is in
use]`, `[symlink -> ...]`) come in the language of the scanned system. The
extractors build their patterns from the lists in frst_tags.py, so a tag in any
listed language must be recognized as a tag -- never end up in the path, the
company, the date or the arguments -- and lines that differ only in the tag's
language must give equal entries.

The lines are real shapes from FRST logs, with user names replaced."""

import re
from importlib import import_module

from django.test import TestCase

from .. import frst_tags
from ..frst_extractors import (
    _FILE_TAG,
    extract_firewall_rule,
    extract_frst_runkey,
    extract_frst_scheduled_task,
    extract_frst_service,
    extract_frst_startup,
    extract_onemonth,
    extract_process,
)

SERVICE = r"R2 qcmtusvc; C:\Program Files (x86)\QUALCOMM\qcmtusvc.exe [148480 2019-11-25] (QUALCOMM, Inc.) [{tag}]"


class TagListTests(TestCase):

    def test_pattern_accepts_every_listed_tag(self):
        for text in frst_tags.ALL_FIXED:
            self.assertRegex(f"[{text}]", "^" + _FILE_TAG + "$")
        for prefix in frst_tags.PREFIXED:
            self.assertRegex(f"[{prefix}C:\\target.dll]", "^" + _FILE_TAG + "$")

    def test_pattern_rejects_other_brackets(self):
        for text in ("1080p", "174080 2022-10-04", "MS Ad"):
            self.assertIsNone(re.fullmatch(_FILE_TAG, f"[{text}]"))

    def test_every_not_signed_language_sets_the_flag(self):
        english = extract_frst_service(SERVICE.format(tag="File not signed"))
        for text in frst_tags.NOT_SIGNED:
            entry = extract_frst_service(SERVICE.format(tag=text))
            self.assertTrue(entry.file_not_signed, text)
            self.assertEqual(entry.company, "QUALCOMM, Inc.", text)
            self.assertEqual(entry, english, text)

    def test_signature_unknown_and_in_use_do_not_set_the_flag(self):
        for text in frst_tags.SIGNATURE_UNKNOWN + frst_tags.IN_USE:
            entry = extract_frst_service(SERVICE.format(tag=text))
            self.assertFalse(entry.file_not_signed, text)
            self.assertEqual(entry.company, "QUALCOMM, Inc.", text)


class ExtractorTagTests(TestCase):

    def test_firewall_translated_tag(self):
        polish = (
            r"FirewallRules: [{08ACA863-8D5C-42EC-9353-9BABCF4464C1}] => (Allow) "
            r"C:\Program Files (x86)\Steam\steamapps\common\MECCHA CHAMELEON\PenguinHotel.exe "
            r"(Epic Games, Inc.) [Brak podpisu cyfrowego]"
        )
        entry = extract_firewall_rule(polish)
        self.assertEqual(entry.company, "Epic Games, Inc.")
        self.assertEqual(entry.arguments, "")
        self.assertTrue(entry.file_not_signed)
        self.assertEqual(entry, extract_firewall_rule(polish.replace("Brak podpisu cyfrowego", "File not signed")))

    def test_firewall_symlink_and_signature_unknown(self):
        symlink = extract_firewall_rule(
            r"FirewallRules: [{05EAEF63-9F3B-4750-B723-D2180071BE13}] => (Allow) "
            r"D:\Oculus\Support\oculus-client\OculusClient.exe () [symlink -> D:\Oculus\Support\oculus-client\Client.exe]"
        )
        self.assertEqual(symlink.filename, "OculusClient.exe")
        self.assertEqual(symlink.arguments, "")

        unknown = extract_firewall_rule(
            r"FirewallRules: [TCP Query User{1737D3A2-C9C3-4198-92E6-419260EFE931}C:\xboxgames\minecraft.windows.exe] "
            r"=> (Block) C:\xboxgames\minecraft.windows.exe (Access Denied)  [File not signed?]"
        )
        self.assertEqual(unknown.company, "Access Denied")
        self.assertEqual(unknown.arguments, "")
        self.assertFalse(unknown.file_not_signed)

    def test_firewall_tag_after_a_path_without_executable_extension(self):
        entry = extract_firewall_rule(
            r"FirewallRules: [TCP Query User{B6F9B17B-9A9D-4C66-9FEB-AFEE8ED079FA}D:\tools\proxy.cli] "
            r"=> (Allow) D:\tools\proxy.cli () [文件未签名]"
        )
        self.assertEqual(entry.filepath, r"C:\tools\proxy.cli")

    def test_scheduled_task_translated_tag_after_company(self):
        entry = extract_frst_scheduled_task(
            r"Task: {0E938B6E-B146-46AB-AC11-39FD5206D71F} - System32\Tasks\WU_2484136b => "
            r"C:\ProgramData\Microsoft\Windows\y6rs7.exe [1190400 2026-10-01] (Microsoft Corporation) "
            r"[Файл не подписан] <==== ВНИМАНИЕ"
        )
        self.assertEqual(entry.filepath, r"C:\ProgramData\Microsoft\Windows\y6rs7.exe")
        self.assertEqual(entry.company, "Microsoft Corporation")
        self.assertEqual(entry.date, "1190400 2026-10-01")
        self.assertEqual(entry.arguments, "")
        self.assertTrue(entry.file_not_signed)

    def test_scheduled_task_tag_before_arguments(self):
        entry = extract_frst_scheduled_task(
            r"Task: {3A318E3A-7D87-44C0-BF63-51D018561DC4} - System32\Tasks\EqualizerAPOUpdateChecker => "
            r"C:\Program Files\EqualizerAPO\UpdateChecker.exe [440832 2025-03-21] () [File not signed] "
            r"-> C:\Program Files\EqualizerAPO\-a"
        )
        self.assertEqual(entry.filepath, r"C:\Program Files\EqualizerAPO\UpdateChecker.exe")
        self.assertEqual(entry.arguments, r"C:\Program Files\EqualizerAPO\-a")

    def test_scheduled_task_two_tags_and_marker(self):
        entry = extract_frst_scheduled_task(
            r"Task: {10EA860D-F9F9-4C8F-8385-D66F2D6A5EBD} - System32\Tasks\msprompt_net7 => "
            r"C:\ProgramData\int_oracle_terminal\CelSu16.exe [192672 0] (Error1: CreateFileW function failed -> ) "
            r"[Archivo no firmado] [El archivo está en uso] <==== ATENCIÓN"
        )
        self.assertEqual(entry.filepath, r"C:\ProgramData\int_oracle_terminal\CelSu16.exe")
        self.assertEqual(entry.arguments, "")
        self.assertTrue(entry.file_not_signed)

    def test_startup_size_date_company_and_tag(self):
        portuguese = extract_frst_startup(
            r"Startup: C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\libcairo-2.dll "
            r"[367616 2025-02-27] () [Arquivo não assinado]"
        )
        self.assertEqual(portuguese.filename, "libcairo-2.dll")
        self.assertEqual(portuguese.date, "367616 2025-02-27")
        self.assertEqual(portuguese.arguments, "")
        self.assertTrue(portuguese.file_not_signed)

        english = extract_frst_startup(
            r"Startup: C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\TaskbarX.exe "
            r"[174080 2022-10-04] (Chris Andriessen) [File not signed]"
        )
        self.assertEqual(english.company, "Chris Andriessen")
        self.assertEqual(english.date, "174080 2022-10-04")
        self.assertEqual(english.arguments, "")

    def test_startup_no_file_marker_is_not_a_company(self):
        entry = extract_frst_startup(r"Startup: C:\Program Files\Foo\foo.lnk (No File)")
        self.assertEqual(entry.company, "")
        self.assertEqual(entry.filename, "foo.lnk")

    def test_startup_file_without_extension_and_marker(self):
        entry = extract_frst_startup(
            r"Startup: C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\settings "
            r"[331 2023-11-27] () [File not signed] <==== ATTENTION"
        )
        self.assertEqual(entry.filename, "settings")
        self.assertEqual(entry.date, "331 2023-11-27")

    def test_runkey_translated_tag_and_marker(self):
        entry = extract_frst_runkey(
            r"HKU\S-1-5-21-2199805677-1116787976-1980509921-1001\...\Run: [WinSysCache] => "
            r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Caches\80673708\RuntimeHost.exe "
            r"[1191968 2026-10-01] (Adobe Systems -> Microsoft Corporation) [Файл не подписан] <==== ВНИМАНИЕ"
        )
        self.assertEqual(entry.company, "Adobe Systems -> Microsoft Corporation")
        self.assertEqual(entry.date, "1191968 2026-10-01")

    def test_onemonth_with_tags(self):
        english = extract_onemonth(
            r"2025-05-14 13:45 - 2025-05-14 13:45 - 000035840 _____ (The Qt Company Ltd.) [File not signed] "
            r"C:\Program Files\AMD\CNext\CNext\plugins\imageformats\qgif.dll"
        )
        self.assertIsNotNone(english)
        self.assertEqual(english.company, "The Qt Company Ltd.")
        self.assertEqual(english.filename, "qgif.dll")
        self.assertTrue(english.file_not_signed)

        french = extract_onemonth(
            r"2026-04-20 16:22 - 2026-04-22 09:27 - 000004608 _____ () [Fichier non signé] "
            r"[Fichier en cours d'utilisation] C:\Program Files (x86)\FanControl\FanControl.Plugins.dll"
        )
        self.assertIsNotNone(french)
        self.assertEqual(french.filename, "FanControl.Plugins.dll")
        self.assertTrue(french.file_not_signed)

    def test_process_in_use_tag(self):
        entry = extract_process(
            r"(services.exe ->) (Node.js) [Archivo no firmado] [El archivo está en uso] "
            r"C:\Users\alice\AppData\Roaming\HotSpot\plugin.exe"
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filename, "plugin.exe")
        self.assertTrue(entry.file_not_signed)


class TagListMigrationTests(TestCase):

    def test_only_one_month_lines_the_old_pattern_could_not_read_are_converted(self):
        newly_parseable = import_module("fixlist.migrations.0076_reparse_after_tag_list")._newly_parseable

        self.assertTrue(newly_parseable(
            r"2025-05-14 13:45 - 2025-05-14 13:45 - 000035840 _____ (The Qt Company Ltd.) [File not signed] "
            r"C:\Program Files\AMD\CNext\CNext\plugins\imageformats\qgif.dll"
        ))
        self.assertFalse(newly_parseable(
            r"2026-05-13 02:29 - 2023-05-22 18:29 - 000000000 ____D C:\Users\alice\AppData\Roaming\RenPy"
        ))
        self.assertFalse(newly_parseable(SERVICE.format(tag="File not signed")))
