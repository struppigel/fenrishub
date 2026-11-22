"""Correlations beyond the line's own file (fixlist/case_correlations.py):
host programs, detected siblings, folder contents, registry values and
browser settings, files of the same name, copies with the same SHA256, and
lines / Spor events at the same time. Modelled on a case with fake MSI
installers that dropped wscript tasks. Nothing here may call centralbox."""

from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from .. import centralbox
from .. import frst_extractors as ex
from .. import spor_log
from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..case_correlations import INFO_MATCHES, correlations_for_upload, entry_status
from ..correlation_keys import browser_key, line_keys, name_key, regval_key, target_keys
from ..models import HashVerdict, InfectionCase, InfectionCaseLog, UploadedLogAnalysis, UploadedLogFileHash
from ..tool_log_facts import mau_facts
from .factories import make_uploaded_log, make_user

WSCRIPT_SHA = 'a1' * 32
COPY_SHA = 'c3' * 32
EVIL_MD5 = 'd4' * 16

TASK_LINE = (r'Task: {AE622AC8-DBB2-417A-B514-DE0B4F79EB95} - System32\Tasks\DataAgent => '
             r'C:\Windows\System32\wscript.exe [184320 2026-10-14] (Microsoft Windows -> Microsoft Corporation) '
             r'-> //B //NoLogo "C:\Users\Bob\AppData\Local\Hidden\ToolsNet\ToolsNet.wsf"')
TASK_FILE_LINE = r'2026-11-18 15:26 - 2026-11-18 15:26 - 000003396 _____ C:\WINDOWS\system32\Tasks\DataAgent'
FOLDER_LINE = r'2026-11-18 15:25 - 2026-11-18 15:25 - 000000000 ____D C:\Users\Bob\AppData\Local\FakeVendor'
LATER_LINE = r'2026-11-18 18:40 - 2026-11-18 18:40 - 000000000 ____D C:\Users\Bob\AppData\Local\Unrelated'
COPY_LINE = r'2026-11-01 10:00 - 2026-11-01 10:00 - 000012345 _____ C:\Users\Bob\Downloads\copy.exe'
DEFENDER_LINE = r'HKLM\SOFTWARE\Microsoft\Windows Defender: [DisableAntiSpyware] Restriction <==== ATTENTION'
HOMEPAGE_LINE = r'CHR HomePage: Default -> hxxp://%66%65%65%64.example/?p=1'
RUN_LINE = r'HKU\S-1-5-21-1-2-3-1001\...\Run: [evil] => C:\Users\Bob\AppData\Roaming\evil\evil.exe'

FIXLOG = '\n'.join([
    'Fix result of Farbar Recovery Scan Tool (x64) Version: 17-11-2026',
    'fixlist content:',
    '*****************',
    DEFENDER_LINE,
    HOMEPAGE_LINE,
    '*****************',
    r'HKLM\SOFTWARE\Microsoft\Windows Defender\\"DisableAntiSpyware"="0" => value restored successfully',
    '"Chrome HomePage" => removed successfully',
    r'C:\Users\Bob\AppData\Local\FakeVendor\Fake Runtime\a.props => moved successfully',
    r'C:\Users\Bob\AppData\Local\FakeVendor\Fake Runtime\b.props => moved successfully',
    r'C:\Users\Bob\AppData\Local\FakeVendor\Fake Runtime\c.props => moved successfully',
])
ESET = '\n'.join([
    '05-11-2026 11:16:09',
    r'C:\Users\Bob\AppData\Local\Hidden\ToolsNet\MSBuild.exe' '\ta variant of Win64/Kryptik.GHM trojan\tcleaned by deleting',
    r'C:\Users\Bob\AppData\Local\FakeVendor\Fake Runtime\loader.exe' '\ta variant of Win64/Kryptik.GHM trojan\tcleaned by deleting',
    r'C:\Users\Bob\AppData\Local\Temp\one.exe' '\ta variant of Win64/Kryptik.GHM trojan\tcleaned by deleting',
])
DASHES = '-' * 94
MAU = '\n'.join([
    '======================== MAU Log ========================',
    '',
    'Analyzing {6D2F9E45-4F17-4AAF-BA5F-2940D41378CC}...',
    DASHES,
    '                                       UNINSTALL / ARP',
    DASHES,
    '',
    '  DisplayName=Fake Runtime',
    '  Publisher=Fake Inc.',
    DASHES,
    '                                      REGISTRY KEY PATHS',
    DASHES,
    '',
    r'  C:\Users\Bob\AppData\Local\FakeVendor\Fake Runtime\ToolsNet.wsf',
    r'  C:\Users\Bob\AppData\Local\FakeVendor\Fake Runtime\app.config',
    DASHES,
    '                                            FILES',
    DASHES,
    '',
    '  <none>',
])
SPOR = '\n'.join([
    '==================== Spor 0.1.0 - forensic triage log ==============================================',
    'Created:   2026-11-19 11:26:17 UTC (local time 19:26, UTC+08:00)',
    'Computer:  PC-BOB, Windows 11 Pro 26H2, build 26300.9974, 64-bit',
    'Times:     UTC',
    '',
    '==================== TIMELINE - last 5 days, newest first ==========================================',
    '',
    r'2026-11-18 10:40:00 [EXE] C:\Users\Bob\AppData\Local\Other\late.exe',
    r'2026-11-18 07:26:37 [TSK] C:\Windows\System32\wscript.exe => task \DataAgent created <==== !lolbin',
    '2026-11-18 07:25:18 [INS] Windows Installer installed: Fake Runtime 6.7 (Fake Inc.) => product code '
    '{6D2F9E45-4F17-4AAF-BA5F-2940D41378CC}',
    '',
    '==================== LEGEND ========================================================================',
])


def folder_listing(rows):
    """A Fixlog Folder: block with a SHA256 per path."""
    return '\n'.join([
        r'========================= Folder: C:\Users\Bob ========================',
        *(f'  [{sha}] 03/08/2026 - 03/08/2026 - 1 MB - Signer: - {path}' for sha, path in rows),
    ])


def cache_parsed(upload, statuses):
    """A fresh analysis of {line: rule status}, components parsed like the analyzer's."""
    lines = []
    for text, status in statuses.items():
        entry = ex.get_frst_entry(text)
        components = {'arguments': entry.arguments} if entry is not None and entry.arguments else {}
        lines.append({'line': text, 'dominant_status': status, 'components': components,
                      'parsed_entry_type': entry.entry_type if entry is not None else ''})
    UploadedLogAnalysis.objects.create(
        upload=upload, rule_set_key='shared', source_content_hash=upload.content_hash,
        payload={'format': ANALYSIS_PAYLOAD_FORMAT, 'lines': lines, 'summary': {}, 'warnings': []},
    )


class MoreCorrelationTests(TestCase):
    STATUSES = {
        TASK_LINE: 'B', TASK_FILE_LINE: 'B', FOLDER_LINE: '?', LATER_LINE: '?', COPY_LINE: '?',
        DEFENDER_LINE: '!', HOMEPAGE_LINE: '?', RUN_LINE: '?',
    }

    def setUp(self):
        self.user = make_user()
        self.case = InfectionCase.objects.create(owner=self.user, username='bob')
        self.frst = self.make_frst('frst-log', self.STATUSES)

    def make_frst(self, upload_id, statuses):
        """An FRST log of the case with these {line: rule status}."""
        content = '\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)', *statuses])
        upload = make_uploaded_log(upload_id, log_type='FRST', content=content, forum_username='nobody')
        cache_parsed(upload, statuses)
        self.link(upload)
        return upload

    def link(self, upload):
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=upload, added_by=self.user)

    def add_log(self, upload_id, log_type, content):
        upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(upload)
        self.link(upload)
        return upload

    def answer(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            result = correlations_for_upload(self.frst, self.user)
        http.assert_not_called()
        request.assert_not_called()
        return result

    def matched(self, answer, line, match):
        return [entry for entry in answer['lines'].get(line, ()) if entry.get('match') == match]

    def test_a_clean_host_program_does_not_rate_the_task_line(self):
        now = timezone.now()
        HashVerdict.objects.create(sha256=WSCRIPT_SHA, state='known', verdict='clean', checked_at=now,
                                   next_check_at=now + timedelta(days=7))
        self.add_log('folder-log', 'Fixlog', folder_listing([(WSCRIPT_SHA, r'C:\Windows\System32\wscript.exe')]))
        answer = self.answer()
        (host,) = self.matched(answer, TASK_LINE, 'host')
        self.assertEqual((host['kind'], host['sha256']), ('hash', WSCRIPT_SHA))
        self.assertEqual(answer['statuses'][TASK_LINE], '')

    def test_a_host_name_outside_windows_is_the_lines_own_file(self):
        line = r'HKU\S-1-5-21-1-2-3-1001\...\Run: [svc] => C:\Users\Bob\AppData\Roaming\svchost.exe "C:\Users\Bob\x.dat"'
        self.frst = self.make_frst('frst-fake-host', {line: '?'})
        self.add_log('eset-log', 'ESET', '\n'.join([
            '05-11-2026 11:16:09',
            r'C:\Users\Bob\AppData\Roaming\svchost.exe' '\ta variant of Win64/Kryptik.GHM trojan\tcleaned by deleting',
        ]))
        answer = self.answer()
        (detection,) = answer['lines'][line]
        self.assertNotIn('match', detection)
        self.assertEqual(answer['statuses'][line], 'B')

    def test_the_reverse_view_is_not_coloured_by_informational_matches(self):
        from ..case_correlations import reverse_correlations, reverse_status
        now = timezone.now()
        HashVerdict.objects.create(sha256=WSCRIPT_SHA, state='known', verdict='clean', checked_at=now,
                                   next_check_at=now + timedelta(days=7))
        listing = self.add_log('folder-log', 'Fixlog', folder_listing([(WSCRIPT_SHA, r'C:\Windows\System32\wscript.exe')]))
        self.answer()
        with mock.patch.object(centralbox, '_http_get'), mock.patch.object(centralbox, '_request'):
            reverse = reverse_correlations(listing, self.user)
        (entries,) = reverse['lines'].values()
        self.assertEqual([(entry['line_status'], entry['match']) for entry in entries], [('B', 'host')])
        self.assertEqual(reverse_status(entries), '')

    def test_a_detected_file_in_the_same_folder_informs_without_a_status(self):
        self.add_log('eset-log', 'ESET', ESET)
        answer = self.answer()
        (sibling,) = self.matched(answer, TASK_LINE, 'sibling')
        self.assertEqual(sibling['detection'], 'a variant of Win64/Kryptik.GHM trojan')
        self.assertTrue(sibling['other_path'].endswith(r'\hidden\toolsnet\msbuild.exe'))
        self.assertEqual(answer['statuses'][TASK_LINE], '')

    def test_temp_is_too_broad_for_siblings(self):
        line = r'2026-11-01 10:00 - 2026-11-01 10:00 - 000000100 _____ C:\Users\Bob\AppData\Local\Temp\two.exe'
        self.frst = self.make_frst('frst-temp', {line: '?'})
        self.add_log('eset-log', 'ESET', ESET)
        self.assertEqual(self.matched(self.answer(), line, 'sibling'), [])

    def test_a_folder_line_gets_what_is_said_about_the_files_inside(self):
        self.add_log('eset-log', 'ESET', ESET)
        self.add_log('fix-log', 'Fixlog', FIXLOG)
        answer = self.answer()
        inside = self.matched(answer, FOLDER_LINE, 'inside')
        detection = next(entry for entry in inside if entry['kind'] == 'detection')
        self.assertTrue(detection['other_path'].endswith(r'\fake runtime\loader.exe'))
        summary = next(entry for entry in inside if entry.get('role') == 'files inside')
        self.assertEqual(summary['text'], '3 Fixlog results: a.props, b.props, c.props')
        self.assertEqual(answer['statuses'][FOLDER_LINE], entry_status(detection))
        self.assertNotEqual(answer['statuses'][FOLDER_LINE], '')
        # A file line is no folder: nothing inside it.
        self.assertEqual(self.matched(answer, COPY_LINE, 'inside'), [])

    def test_a_flagged_file_inside_is_listed_but_does_not_colour_the_folder(self):
        self.add_log('spor-log', 'Spor', SPOR.replace(
            '2026-11-18 10:40:00 [EXE] C:\\Users\\Bob\\AppData\\Local\\Other\\late.exe',
            '2026-11-18 10:40:00 [EXE] C:\\Users\\Bob\\AppData\\Local\\FakeVendor\\x\\invoice.pdf.exe '
            '<==== !double-extension',
        ))
        answer = self.answer()
        (flagged,) = [entry for entry in self.matched(answer, FOLDER_LINE, 'inside') if entry['kind'] == 'evidence']
        self.assertEqual((flagged['file'], flagged['severity']), ('invoice.pdf.exe', 'w'))
        self.assertEqual(answer['statuses'][FOLDER_LINE], '')

    def test_registry_values_and_browser_settings_find_the_fixlog_results(self):
        self.add_log('fix-log', 'Fixlog', FIXLOG)
        answer = self.answer()
        (value,) = answer['lines'][DEFENDER_LINE]
        self.assertEqual((value['kind'], value['match'], value['result']),
                         ('fixlog', 'registry', 'value restored successfully'))
        (setting,) = answer['lines'][HOMEPAGE_LINE]
        self.assertEqual((setting['match'], setting['result']), ('browser', 'removed successfully'))

    def test_a_file_of_the_same_name_ties_the_task_to_the_product_that_installed_it(self):
        self.add_log('mau-log', 'MAU', MAU)
        answer = self.answer()
        (named,) = self.matched(answer, TASK_LINE, 'name')
        self.assertEqual((named['upload_id'], named['role']), ('mau-log', 'installed by product (MAU)'))
        self.assertTrue(named['other_path'].endswith(r'\fakevendor\fake runtime\toolsnet.wsf'))
        self.assertEqual(answer['statuses'][TASK_LINE], '')

    def test_a_copy_with_the_same_sha256_carries_the_detection(self):
        self.add_log('mb-log', 'Malwarebytes', (
            r'Trojan.AsyncRAT, C:\USERS\BOB\APPDATA\ROAMING\EVIL\evil.exe, Quarantined, 8322, 1457763, '
            f'1.0.116571, , ame, , {EVIL_MD5.upper()}, {COPY_SHA.upper()}'
        ))
        self.add_log('folder-log', 'Fixlog', folder_listing([(COPY_SHA, r'C:\Users\Bob\Downloads\copy.exe')]))
        answer = self.answer()
        (copy,) = [entry for entry in self.matched(answer, COPY_LINE, 'same_hash') if entry['upload_id'] == 'mb-log']
        self.assertEqual(copy['detection'], 'Trojan.AsyncRAT')
        self.assertTrue(copy['other_path'].endswith(r'\roaming\evil\evil.exe'))
        self.assertEqual(answer['statuses'][COPY_LINE], 'B')

    def test_lines_and_spor_events_at_the_same_time(self):
        self.add_log('spor-log', 'Spor', SPOR)
        answer = self.answer()
        own = [entry for entry in self.matched(answer, FOLDER_LINE, 'timing') if entry['upload_id'] == 'frst-log']
        self.assertEqual([entry['text'] for entry in own], [TASK_FILE_LINE])
        self.assertEqual(own[0]['line_no'], 3)
        spor = [entry for entry in self.matched(answer, FOLDER_LINE, 'timing') if entry['upload_id'] == 'spor-log']
        # 07:25:18 UTC is 15:25:18 at UTC+08:00, the folder's minute; 07:26:37 is within two minutes.
        self.assertEqual([entry['time'] for entry in spor], ['2026-11-18 15:25:18', '2026-11-18 15:26:37'])
        self.assertEqual(spor[0]['extra'], [['time in log', '2026-11-18 07:25:18']])
        self.assertEqual(answer['statuses'].get(FOLDER_LINE, ''), '')
        # Hours later, and nothing flagged near it.
        self.assertEqual(self.matched(answer, LATER_LINE, 'timing'), [])

    def test_a_crowded_minute_ties_nothing_together(self):
        crowd = [rf'2026-11-18 15:26 - 2026-11-18 15:26 - 000000100 _____ C:\Users\Bob\Update\f{n}.dat'
                 for n in range(30)]
        self.frst = self.make_frst('frst-crowd', {TASK_FILE_LINE: 'B', **{line: '?' for line in crowd}})
        answer = self.answer()
        self.assertFalse(any(self.matched(answer, line, 'timing') for line in [TASK_FILE_LINE, *crowd]))


class KeyTests(SimpleTestCase):
    def test_registry_value_keys(self):
        self.assertEqual(regval_key(r'HKLM\SOFTWARE\Microsoft\Windows Defender', '"DisableAntiSpyware"'),
                         'regval:windows defender|disableantispyware')
        self.assertEqual(regval_key(r'HKLM\...\Run', 'evil'), '')
        self.assertEqual(target_keys(r'HKLM\SOFTWARE\Microsoft\Windows Defender\\"DisableAntiSpyware"="0"'),
                         {'regval:windows defender|disableantispyware'})
        self.assertEqual(target_keys(r'"HKCU\Environment\\P1"'), {'regval:environment|p1'})
        self.assertEqual(target_keys(r'HKU\S-1-5-21-1\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|DisableTaskMgr'),
                         {'regval:system|disabletaskmgr'})
        # A Run value keeps its own key.
        self.assertEqual(target_keys(r'"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\\launcher"'),
                         {'run:launcher'})
        self.assertEqual(dict(line_keys({'line': DEFENDER_LINE})),
                         {'regval:windows defender|disableantispyware': 'registry'})
        self.assertNotIn('regval', ' '.join(key for key, _match in line_keys({'line': RUN_LINE})))

    def test_browser_setting_keys(self):
        self.assertEqual(browser_key('CHR', 'HomePage'), 'browser:chrome:homepage')
        self.assertEqual(browser_key('CHR', 'Extension'), '')
        self.assertEqual(target_keys('"Chrome StartupUrls"'), {'browser:chrome:startupurls'})
        self.assertEqual(target_keys('"Firefox newtab"'), {'browser:firefox:newtab'})
        # EmptyTemp's "Chrome => 6629743437 B" names no setting.
        self.assertEqual(target_keys('Chrome'), set())
        self.assertEqual(dict(line_keys({'line': HOMEPAGE_LINE})), {'browser:chrome:homepage': 'browser'})

    def test_name_keys_leave_out_common_names(self):
        self.assertEqual(name_key(r'c:\users\username\appdata\local\hidden\toolsnet\toolsnet.wsf'), 'name:toolsnet.wsf')
        for key in (r'c:\x\app.config', r'c:\x\msbuild.exe', r'c:\x\readme.txt', r'c:\windows\x\rare.dll',
                    r'c:\x\shortcut.lnk', r'c:\x\noextension'):
            self.assertEqual(name_key(key), '', key)

    def test_informational_matches_never_give_a_status(self):
        for match in INFO_MATCHES:
            self.assertEqual(entry_status({'match': match, 'severity': 'b', 'kind': 'detection'}), '')
        self.assertEqual(entry_status({'match': 'same_hash', 'severity': 'b', 'kind': 'detection'}), 'B')
        # Inside a folder: only malware and PUPs speak for the folder.
        self.assertEqual(entry_status({'match': 'inside', 'severity': 'p', 'kind': 'detection'}), 'P')
        self.assertEqual(entry_status({'match': 'inside', 'severity': 'w', 'kind': 'evidence'}), '')
        self.assertEqual(entry_status({'match': 'inside', 'kind': 'hash', 'centralbox': {'verdict': 'clean'}}), '')


class ParserTests(SimpleTestCase):
    def test_mau_key_paths(self):
        (product,), _items = mau_facts(MAU)
        self.assertEqual(product.name, 'Fake Runtime')
        self.assertEqual([path for _no, path in product.key_paths], [
            r'C:\Users\Bob\AppData\Local\FakeVendor\Fake Runtime\ToolsNet.wsf',
            r'C:\Users\Bob\AppData\Local\FakeVendor\Fake Runtime\app.config',
        ])
        self.assertEqual(product.key_paths[0][0], 14)

    def test_an_upper_case_key_path_is_no_section_title(self):
        upper = MAU.replace(r'  C:\Users\Bob\AppData\Local\FakeVendor\Fake Runtime\ToolsNet.wsf',
                            r'  C:\PROGRAM FILES (X86)\FAKE\LOADER.EXE')
        (product,), _items = mau_facts(upper)
        self.assertEqual([path for _no, path in product.key_paths][0], r'C:\PROGRAM FILES (X86)\FAKE\LOADER.EXE')

    def test_spor_local_offset(self):
        lines = SPOR.split('\n')
        self.assertEqual(spor_log.local_offset_minutes(lines), 480)
        self.assertEqual(spor_log.local_offset_minutes([lines[1].replace('+08:00', '-03:30'), 'Times:     UTC']), -210)
        self.assertEqual(spor_log.local_offset_minutes([lines[1], 'Times:     local']), 0)
        # Spor 0.7.2+ names the exception (FILES' created / modified are local time): still UTC
        self.assertEqual(spor_log.local_offset_minutes([lines[1], 'Times:     UTC, except created and modified in FILES '
                                                                  '(local time of this PC, as FRST shows them)']), 480)
        self.assertIsNone(spor_log.local_offset_minutes([lines[1]]))
        times = [(no, item.time) for no, item in spor_log.iter_timeline_items(lines)]
        self.assertEqual(times, [(8, '2026-11-18 10:40:00'), (9, '2026-11-18 07:26:37'), (10, '2026-11-18 07:25:18')])
