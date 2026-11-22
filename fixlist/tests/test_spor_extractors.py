"""Spor parsed types (spor_extractors): each Spor 0.7.0+ block read into one
entry of what stays the same across PCs, and the one path of each line."""

import re
from pathlib import Path

from django.test import SimpleTestCase

from .. import frst_extractors as ex
from .. import log_layout
from .. import spor_extractors as se
from . import spor7_sample as sample


def _entries(text, log_type='Spor'):
    walked = log_layout.analyzed_lines(text)
    structure = log_layout.layout(text, log_type)
    found = se.analyze_lines(walked, structure)
    first = {}
    for index, block in enumerate(structure.block_of):
        first.setdefault(block, index)
    return {walked[first[block]].text: entries[0] for block, entries in found.entries_by_block.items()}, found, walked


def _block(lines):
    return se.parse_block([line.strip() for line in lines])


class SporEntryTypesListTests(SimpleTestCase):
    def test_every_type_the_module_produces_is_listed(self):
        source = Path(se.__file__).read_text(encoding='utf-8')
        produced = set(re.findall(r"_entry\(\s*'(spor_[a-z_]+)'", source))
        self.assertTrue(produced)
        self.assertEqual(produced, set(se.SPOR_ENTRY_TYPES))

    def test_all_types_are_frsts_then_spors(self):
        self.assertEqual(se.ALL_ENTRY_TYPES, ex.ENTRY_TYPES + se.SPOR_ENTRY_TYPES)


class SporBlockEntryTests(SimpleTestCase):
    def test_run_value_with_its_program_and_arguments(self):
        entry = _block(sample.RUN_BLOCK)
        self.assertEqual(entry.entry_type, 'spor_run')
        self.assertEqual(entry.name, 'Updater')
        self.assertEqual(entry.attributes, 'run')
        self.assertEqual(entry.filepath, ex.normalize_path(sample.PROGRAM))
        self.assertEqual(entry.filename, 'upd.exe')
        self.assertEqual(entry.arguments, '--silent')
        self.assertTrue(entry.file_not_signed)

    def test_the_same_entry_on_another_pc(self):
        other = [
            '2025-01-02 03:04:05 [run] HKU\\anna\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
            '    program: D:\\Users\\anna\\AppData\\Roaming\\Upd\\UPD.EXE [unsigned]',
            '    arguments: --silent',
        ]
        self.assertEqual(_block(other), _block(sample.RUN_BLOCK))
        self.assertEqual(hash(_block(other)), hash(_block(sample.RUN_BLOCK)))

    def test_a_value_name_with_a_backslash_comes_from_its_value_line(self):
        entry = _block([
            '2026-11-15 16:35:36 [run] HKU\\Bob\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Back\\Slash',
            '    program: C:\\Program Files\\A\\a.exe',
            '    value: Back\\Slash',
        ])
        self.assertEqual((entry.name, entry.file_not_signed), ('Back\\Slash', False))

    def test_task_with_program_and_arguments(self):
        entry = _block(sample.TASK_BLOCK)
        self.assertEqual(
            (entry.entry_type, entry.name, entry.filepath, entry.arguments),
            ('spor_task', '\\Evil\\UpdateCheck', ex.normalize_path(sample.TASK_PROGRAM), '/run'),
        )

    def test_services_of_the_registry_and_of_event_7045_agree(self):
        registry = _block([
            f'2026-11-01 10:00:00 [service] EvilSvc => {sample.SVC_DLL} (svchost DLL) [unsigned], start auto',
            f'    dll: {sample.SVC_DLL} [unsigned]',
        ])
        event = _block([
            '2026-11-01 09:59:00 [service] EvilSvc => C:\\Windows\\System32\\svchost.exe, account LocalSystem',
            f'    dll: {sample.SVC_DLL} [unsigned]',
        ])
        self.assertEqual(registry.entry_type, 'spor_service')
        self.assertEqual((registry.name, registry.filepath, registry.file_not_signed), ('EvilSvc', sample.SVC_DLL, True))
        self.assertEqual(registry, event)

    def test_startup_item_and_its_target(self):
        entry = _block([
            '2026-09-05 04:53:50 [startup] C:\\Users\\Bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Evil.lnk',
            f'    target: {sample.PROGRAM}',
        ])
        self.assertEqual(entry.entry_type, 'spor_startup')
        self.assertTrue(entry.filepath.endswith('\\Startup\\Evil.lnk'))
        self.assertEqual(entry.name, ex.normalize_path(sample.PROGRAM).lower())

    def test_the_same_threat_from_every_section(self):
        defender = _block(['2026-11-21 08:18:43 [1116] Defender detected: Trojan:JS/Fake.A!ams', '    file: C:\\x.js'])
        timeline = _block(['2026-11-21 08:18:43 [DEF] Defender detected: Trojan:JS/Fake.A!ams'])
        summary = _block(['2026-11-21 08:18:43 [Defender] Defender detected: Trojan:JS/Fake.A!ams', '    file: C:\\y.js'])
        action = _block(['2026-11-21 08:22:08 [1117] Defender action taken: Trojan:JS/Fake.A!ams => action Quarantine'])
        self.assertEqual(defender.entry_type, 'spor_defender')
        self.assertEqual(defender.name, 'Trojan:JS/Fake.A!ams')
        self.assertEqual({defender, timeline, summary, action}, {defender})

    def test_defender_exclusions(self):
        path = _block(['2026-11-17 16:12:59 [Paths] C:\\Users\\Bob\\Downloads\\'])
        extension = _block(['2026-11-17 16:13:00 [Extensions] .xyz'])
        self.assertEqual((path.entry_type, path.attributes, path.filepath),
                         ('spor_defender_exclusion', 'Paths', 'C:\\Users\\username\\Downloads'))
        self.assertEqual((extension.attributes, extension.name, extension.filepath), ('Extensions', '.xyz', ''))

    def test_software_uninstall_entries(self):
        entry = _block([
            '2026-11-09 11:25:19 [machine 32-bit] Evil Tool => C:\\Program Files (x86)\\Evil\\uninstall.exe [unsigned], version 1.0; publisher Evil Ltd; hidden yes',
            '    key: HKLM-x32\\...\\Evil Tool',
        ])
        self.assertEqual(
            (entry.entry_type, entry.name, entry.company, entry.attributes, entry.is_hidden, entry.file_not_signed),
            ('spor_software', 'Evil Tool', 'Evil Ltd', 'machine 32-bit', True, True),
        )
        self.assertTrue(entry.filepath.endswith('\\uninstall.exe'))
        msi = _block(['2026-11-09 12:09:52 [user Bob] Some App => Windows Installer (msiexec), version 2.0; publisher Some Inc'])
        self.assertEqual((msi.filepath, msi.attributes, msi.company), ('', 'user', 'Some Inc'))

    def test_windows_installer_event(self):
        entry = _block([
            f'2026-10-27 14:37:02 [1033] installed: Some App 2.0 (Some Inc) => SYSTEM; name Some App; product code {{{sample.PRODUCT_CODE}}}',
        ])
        self.assertEqual((entry.entry_type, entry.name, entry.clsid, entry.attributes),
                         ('spor_installer', 'Some App', sample.PRODUCT_CODE, 'installed'))

    def test_store_package_family_and_signer(self):
        entry = _block([
            '2026-11-21 07:40:21 [Add] Evil.App_1.0.0.0_x64__abcdefghjk123 => Evil App; times 1',
            '    signer: Evil Ltd (package) (newer version)',
        ])
        newer = _block(['2026-11-22 07:40:21 [Register] Evil.App_2.0.0.0_x64__abcdefghjk123', '    signer: Evil Ltd (package)'])
        self.assertEqual((entry.entry_type, entry.name, entry.company), ('spor_package', 'Evil.App_abcdefghjk123', 'Evil Ltd'))
        self.assertEqual(entry, newer)

    def test_running_process_parents(self):
        cases = {
            'parent Explorer.EXE (15464) < pid 15400 (exited); arguments --silent': 'explorer.exe',
            'parent pid 4200 (exited, was Loader.exe); arguments -x': 'loader.exe',
            'parent pid 4200 (exited)': '',
            'parent unknown': '',
            'parent none': '',
        }
        for rest, parent in cases.items():
            with self.subTest(rest=rest):
                entry = _block([f'2026-11-21 08:36:59 [21536] {sample.PROGRAM} [unsigned] => {rest}'])
                self.assertEqual((entry.entry_type, entry.name, entry.file_not_signed), ('spor_process', parent, True))

    def test_files_line(self):
        entry = _block([
            f'{sample.PROGRAM} => {sample.SHA.upper()}, signature unsigned',
            f'    file: md5 {sample.MD5.upper()}; size 1234',
        ])
        signed = _block([f'C:\\Program Files\\Ok\\ok.exe => {sample.SHA.upper()}, signature valid; signer Ok Inc.'])
        self.assertEqual((entry.entry_type, entry.attributes, entry.file_not_signed), ('spor_file', 'unsigned', True))
        self.assertEqual((signed.company, signed.attributes, signed.file_not_signed), ('Ok Inc.', 'valid', False))

    def test_lines_that_are_no_entry(self):
        for lines in (
            ['2026-11-04 08:00:00 [task] [141] \\Evil\\Gone => deleted; by Bob'],
            ['C:\\Users\\Bob\\Desktop\\old.exe => ' + 'f0' * 20],
            ['2026-10-24 04:42:52 [machine] 2 entries from Learning Machines LLC', '    key: HKLM\\...\\{A}; name PhotoCraft'],
            ['2026-11-21 08:20:00 [INS] installed or updated: Evil Tool 1.0 (Evil), per user'],
            ['2026-11-21 08:08:57 [RUN] Run dialog: joy.cpl'],
            ['2026-11-18 08:00:00 [run] HKU\\Bob\\...\\Run\\a => [gone] x <==== !log-syntax-in-name'],
            ['(line: time [kind] entry <==== flags)'],
            ['==================== PERSISTENCE - Run keys ===================='],
        ):
            with self.subTest(lines=lines[0]):
                self.assertIsNone(_block(lines))


class SporLogTests(SimpleTestCase):
    def test_every_type_in_a_log(self):
        entries, _found, _walked = _entries(sample.SPOR7)
        self.assertEqual({entry.entry_type for entry in entries.values()}, set(se.SPOR_ENTRY_TYPES))

    def test_logs_of_older_spor_versions_get_none(self):
        old = sample.SPOR7.replace('Spor 0.7.1', 'Spor 0.6.1', 1)
        entries, found, _walked = _entries(old)
        self.assertEqual(entries, {})
        self.assertFalse(any(found.path_by_index))

    def test_paths_of_items_targets_and_sub_lines(self):
        _entries_found, found, walked = _entries(sample.SPOR7)
        path_of = {item.text: found.path_by_index[item.index] for item in walked}
        self.assertEqual(path_of['loaded: C:\\Users\\Bob\\AppData\\Roaming\\TELEGRAM DESKTOP\\TELEGRAM.EXE [gone]'],
                         'C:\\Users\\Bob\\AppData\\Roaming\\TELEGRAM DESKTOP\\TELEGRAM.EXE')
        self.assertEqual(path_of[f'program: {sample.PROGRAM} [unsigned]'], sample.PROGRAM)
        self.assertEqual(path_of[sample.RUN_BLOCK[0]], '')                       # a registry entry
        self.assertEqual(path_of['2026-11-01 10:00:00 [service] EvilSvc => C:\\ProgramData\\Evil\\evilsvc.dll'
                                 ' (svchost DLL) [unsigned], start auto'], sample.SVC_DLL)  # the target
        self.assertEqual(path_of['folder: C:\\Program Files (x86)\\Evil\\'], 'C:\\Program Files (x86)\\Evil')
        self.assertEqual(path_of['arguments: --silent'], '')

    def test_line_path_on_its_own(self):
        self.assertEqual(se.line_path('file: C:\\a.zip->inner.exe'), 'C:\\a.zip')
        self.assertEqual(se.line_path('2026-11-21 08:36:59 [21536] C:\\x.exe [unsigned] => parent none'), 'C:\\x.exe')
        self.assertEqual(se.line_path('key: HKLM\\...\\Evil Tool'), '')
