"""Correlations beyond the line's own file (fixlist/correlation_keys.py):
files in a command line, registry Run values, services, tasks, browser
extensions, CLSIDs and firewall rules named by scanners and Fixlogs; and
Windows Defender events of Addition logs. Nothing here calls centralbox."""

from unittest import mock

from django.test import TestCase

from .. import centralbox
from ..analyzer import analyze_log_text
from ..case_correlations import correlations_for_upload, iter_addition_defender_detections
from ..correlation_keys import argument_paths, line_keys, line_path_keys, target_keys
from ..models import InfectionCase, InfectionCaseLog, UploadedLogAnalysis, UploadedLogFileHash
from .factories import make_uploaded_log, make_user

HEADER = 'Scan result of Farbar Recovery Scan Tool (FRST) (x64) Version: 10-11-2026 01'
RUN_LINE = (r'HKU\S-1-5-21-1-2-3-1001\...\Run: [Updater] => "C:\Program Files\Up\up.exe" --quiet '
            r'[3520440 2026-01-01] (Up Inc. -> Up Inc.)')
SERVICE_LINE = r'R2 EvilSvc; C:\Windows\evilsvc.sys [123 2026-01-01] () [File not signed]'
TASK_LINE = (r'Task: {5F2EAF8F-4827-4B10-A79A-83A72769A412} - System32\Tasks\Evil Updater => '
             r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass -f '
             r'"C:\Users\Bob\AppData\Roaming\x y\a.ps1" <==== ATTENTION')
EXTENSION_LINE = (r'CHR Extension: (Bad) - C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Default'
                  r'\Extensions\pbdpajcdgknpendpmecafmopknefafha [2026-05-30]')
FIREWALL_LINE = r'FirewallRules: [{1834C62C-1AC6-4753-BF2A-03ACE49B2DE2}] => (Allow) C:\p\x.exe () [File not signed]'
CLSID_LINE = (r'CustomCLSID: HKU\S-1-5-21-1-2-3-1001_Classes\CLSID\{2F81B25E-7507-4844-BFF2-77D2CC24CED4}'
              r'\InprocServer32 -> C:\Users\Bob\AppData\Local\x.dll (No File)')
WINDOWS_SERVICE_LINE = r'R2 Spooler; C:\Windows\System32\spoolsv.exe [123 2026-01-01] (Microsoft Windows -> Microsoft Corporation)'
FRST_LINES = [RUN_LINE, SERVICE_LINE, TASK_LINE, EXTENSION_LINE, FIREWALL_LINE, CLSID_LINE, WINDOWS_SERVICE_LINE]

MB_REGISTRY = '\n'.join([
    'Malwarebytes',
    'www.malwarebytes.com',
    r'PUP.Optional.Updater, HKU\S-1-5-21-1-2-3-1001\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN|UPDATER, '
    'Quarantined, 1, 1, 1.0.1, , ame, ',
    r'PUP.Optional.BadExt, HKU\S-1-5-21-1-2-3-1001\SOFTWARE\GOOGLE\CHROME\PREFERENCEMACS\Default'
    r'\extensions.settings|pbdpajcdgknpendpmecafmopknefafha, Quarantined, 1, 1, 1.0.1, , ame, ',
])
FIXLOG = '\n'.join([
    'Fix result of Farbar Recovery Scan Tool (x64) Version: 01-11-2026',
    r'"HKLM\System\CurrentControlSet\Services\EvilSvc" => removed successfully',
    r'EvilSvc => service removed successfully',
    r'"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Evil Updater" => removed successfully',
    r'"HKLM\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    r'\\{1834C62C-1AC6-4753-BF2A-03ACE49B2DE2}" => removed successfully',
    r'"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID\{2F81B25E-7507-4844-BFF2-77D2CC24CED4}" => removed successfully',
])
ESET_SCRIPT = ('05-11-2026 11:16:09\n'
               'C:\\Users\\Bob\\AppData\\Roaming\\x y\\a.ps1\tPowerShell/Agent.A trojan\tcleaned by deleting')

ADDITION = '\n'.join([
    'Additional scan result of Farbar Recovery Scan Tool (x64) Version: 10-11-2026 01',
    'Ran by Bob (13-11-2026 11:11:39)',
    '==================== Event log errors: ========================',
    '',
    'Windows Defender:',
    '================',
    '',
    'TimeCreated : 11/4/2026 4:07:39 AM',
    'Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.',
    'Name: Trojan:Win32/Posilod.EB!cl',
    'ID: 2147735503',
    'Severity: Severe',
    'Category: Trojan',
    r'Path: file:_C:\Users\Bob\AppData\Roaming\x y\a.p',
    r's1; file:_C:\Windows\Installer\1284762.msi',
    'Detection Origin: Local machine',
    '',
    'TimeCreated : 11/4/2026 4:07:40 AM',
    'Message     : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.',
    'Name: Trojan:Win32/Commandrob.A!ml',
    r'Path: CmdLine:_C:\Users\Bob\AppData\Local\Microsoft\WinShellHost32.exe --algo x --url stratum://pool.example:9000',
    'Detection Origin: Unknown',
    '',
    'TimeCreated : 11/3/2026 1:00:00 AM',
    'Message     : Microsoft Defender Antivirus scan has been stopped before completion.',
    'User: PC\\Bob',
    '',
    'CodeIntegrity:',
    '===============',
    'Date: 2026-11-13 11:18:31',
    r'Path: file:_C:\Never\counted.exe',
])


class TargetKeyTests(TestCase):
    def test_registry_service_task_extension_clsid_and_firewall_targets(self):
        self.assertEqual(target_keys(r'HKU\S-1\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN|EVIL'), {'run:evil'})
        self.assertEqual(target_keys('"HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\\\Evil One"',
                                     'removed successfully'), {'run:evil one'})
        self.assertEqual(target_keys(r'"HKLM\System\CurrentControlSet\Services\EvilSvc"'), {'svc:evilsvc'})
        self.assertEqual(target_keys('EvilSvc', 'service removed successfully'), {'svc:evilsvc'})
        self.assertEqual(target_keys('Chrome', '6190706292 B'), set())
        self.assertEqual(
            target_keys(r'HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\TASKS'
                        r'\{E86D5947-58AD-4A3E-8003-5E81BD306422}'),
            {'taskid:e86d5947-58ad-4a3e-8003-5e81bd306422'},
        )
        self.assertEqual(target_keys(r'C:\Windows\System32\Tasks\Evil Updater'),
                         {r'c:\windows\system32\tasks\evil updater', 'task:evil updater'})
        self.assertEqual(target_keys('agibagflppafhfonkefpklndlohkclcb'), {'ext:agibagflppafhfonkefpklndlohkclcb'})
        self.assertEqual(target_keys(r'"HKLM\SOFTWARE\Google\Chrome\Extensions\fheoggkfdfchfphceeifdbepaooicaho"'),
                         {'ext:fheoggkfdfchfphceeifdbepaooicaho'})
        self.assertEqual(
            target_keys(r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
                        r'\{761497BB-D6F0-462C-B6EB-D4DAF1D92D43}'),
            {'clsid:761497bb-d6f0-462c-b6eb-d4daf1d92d43'},
        )
        self.assertEqual(
            target_keys(r'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
                        r'\FirewallRules|{1834C62C-1AC6-4753-BF2A-03ACE49B2DE2}'),
            {'fw:{1834c62c-1ac6-4753-bf2a-03ace49b2de2}'},
        )

    def test_files_inside_an_extension_folder_do_not_name_the_extension(self):
        base = r'C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Default\Extensions\fheoggkfdfchfphceeifdbepaooicaho'
        self.assertIn('ext:fheoggkfdfchfphceeifdbepaooicaho', target_keys(base))
        self.assertFalse(any(key.startswith('ext:') for key in target_keys(base + r'\8.2.0_0\about.js')))


class LineKeyTests(TestCase):
    def payload_lines(self):
        payload = analyze_log_text('\n'.join([HEADER, *FRST_LINES]) + '\n', 'shared')
        return {line['line'].strip(): line for line in payload['lines'] if isinstance(line, dict)}

    def test_typed_keys_of_analyzed_lines(self):
        lines = self.payload_lines()
        keys = {text: dict(line_keys(lines[text])) for text in FRST_LINES}
        self.assertEqual(keys[RUN_LINE]['run:updater'], 'registry')
        self.assertEqual(keys[SERVICE_LINE]['svc:evilsvc'], 'service')
        self.assertEqual(keys[TASK_LINE]['task:evil updater'], 'task')
        self.assertEqual(keys[TASK_LINE]['taskid:5f2eaf8f-4827-4b10-a79a-83a72769a412'], 'task')
        self.assertEqual(keys[TASK_LINE][r'c:\users\username\appdata\roaming\x y\a.ps1'], 'argument')
        self.assertEqual(keys[TASK_LINE][r'c:\windows\system32\windowspowershell\v1.0\powershell.exe'], 'path')
        self.assertEqual(keys[EXTENSION_LINE]['ext:pbdpajcdgknpendpmecafmopknefafha'], 'extension')
        self.assertEqual(keys[FIREWALL_LINE]['fw:{1834c62c-1ac6-4753-bf2a-03ace49b2de2}'], 'firewall')
        self.assertEqual(keys[CLSID_LINE]['clsid:2f81b25e-7507-4844-bff2-77d2cc24ced4'], 'clsid')

    def test_argument_paths(self):
        self.assertEqual(
            argument_paths(r'-f "C:\Users\Bob\x y\a.ps1" %APPDATA%\b.vbs C:\ProgramData\q\z.dll,Run --dir=C:\Temp'),
            [r'c:\users\username\x y\a.ps1', r'c:\users\username\appdata\roaming\b.vbs', r'c:\programdata\q\z.dll'],
        )
        self.assertEqual(argument_paths('%UNKNOWNVAR%\\x.exe /q'), [])
        self.assertEqual(line_path_keys(TASK_LINE),
                         [r'c:\windows\system32\windowspowershell\v1.0\powershell.exe',
                          r'c:\users\username\appdata\roaming\x y\a.ps1'])


class AdditionDefenderTests(TestCase):
    def test_events_with_wrapped_paths_and_command_lines(self):
        found = {(path.lower(), threat): line_no for line_no, threat, _action, path in
                 iter_addition_defender_detections(ADDITION)}
        lines = ADDITION.split('\n')
        self.assertEqual(set(found), {
            (r'c:\users\bob\appdata\roaming\x y\a.ps1', 'Trojan:Win32/Posilod.EB!cl'),
            (r'c:\windows\installer\1284762.msi', 'Trojan:Win32/Posilod.EB!cl'),
            (r'c:\users\username\appdata\local\microsoft\winshellhost32.exe', 'Trojan:Win32/Commandrob.A!ml'),
        })
        line_no = found[(r'c:\windows\installer\1284762.msi', 'Trojan:Win32/Posilod.EB!cl')]
        self.assertEqual(lines[line_no - 1], 'Name: Trojan:Win32/Posilod.EB!cl')

    def test_no_section_no_detections(self):
        self.assertEqual(iter_addition_defender_detections('Additional scan result\nName: x\nPath: file:_C:\\x.exe'), [])


class KeyCorrelationTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.case = InfectionCase.objects.create(owner=self.user, username='bob')
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content='\n'.join([HEADER, *FRST_LINES]),
                                      forum_username='nobody')
        payload = analyze_log_text(self.frst.content, 'shared')
        UploadedLogAnalysis.objects.create(upload=self.frst, rule_set_key='shared', payload=payload,
                                           source_content_hash=self.frst.content_hash)
        self.link(self.frst)

    def link(self, upload):
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=upload, added_by=self.user)

    def add_log(self, upload_id, log_type, content):
        upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(upload)
        self.link(upload)
        return upload

    def correlations(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            result = correlations_for_upload(self.frst, self.user)
        http.assert_not_called()
        request.assert_not_called()
        return result

    def matches(self, result, line):
        return {(entry['upload_id'], entry.get('match', 'path')) for entry in result['lines'].get(line, [])}

    def test_registry_and_extension_detections_reach_their_lines(self):
        self.add_log('mb-log', 'Malwarebytes', MB_REGISTRY)
        result = self.correlations()
        self.assertEqual(self.matches(result, RUN_LINE), {('mb-log', 'registry')})
        self.assertEqual(self.matches(result, EXTENSION_LINE), {('mb-log', 'extension')})
        self.assertEqual(result['statuses'][RUN_LINE], 'P')
        self.assertIn('same registry value', result['notes'][RUN_LINE])

    def test_fixlog_results_reach_service_task_firewall_and_clsid_lines(self):
        self.add_log('fix-log', 'Fixlog', FIXLOG)
        result = self.correlations()
        service = result['lines'][SERVICE_LINE]
        self.assertEqual({(entry['line_no'], entry['match']) for entry in service}, {(2, 'service'), (3, 'service')})
        self.assertEqual(self.matches(result, TASK_LINE), {('fix-log', 'task')})
        self.assertEqual(self.matches(result, FIREWALL_LINE), {('fix-log', 'firewall')})
        self.assertEqual(self.matches(result, CLSID_LINE), {('fix-log', 'clsid')})
        # A Windows service only correlates when a log names it.
        self.assertNotIn(WINDOWS_SERVICE_LINE, result['lines'])

    def test_a_detected_script_reaches_the_task_that_runs_it(self):
        self.add_log('eset-log', 'ESET', ESET_SCRIPT)
        result = self.correlations()
        self.assertEqual(self.matches(result, TASK_LINE), {('eset-log', 'argument')})
        self.assertEqual(result['statuses'][TASK_LINE], 'B')
        self.assertIn('file in command line', result['notes'][TASK_LINE])

    def test_defender_events_of_a_related_addition_log(self):
        self.add_log('add-log', 'Addition', ADDITION)
        result = self.correlations()
        entry = result['lines'][TASK_LINE][0]
        self.assertEqual((entry['upload_id'], entry['source'], entry['match'], entry['log_type']),
                         ('add-log', 'defender', 'argument', 'Addition'))
        self.assertEqual(entry['detection'], 'Trojan:Win32/Posilod.EB!cl')

    def test_defender_events_of_the_logs_own_addition_part(self):
        merged = make_uploaded_log('merged-log', log_type='FRST&Addition',
                                   content='\n'.join([ADDITION, HEADER, *FRST_LINES]), forum_username='nobody')
        payload = analyze_log_text(merged.content, 'shared')
        UploadedLogAnalysis.objects.create(upload=merged, rule_set_key='shared', payload=payload,
                                           source_content_hash=merged.content_hash)
        self.link(merged)
        result = correlations_for_upload(merged, self.user)
        own = [entry for entry in result['lines'][TASK_LINE] if entry['upload_id'] == 'merged-log']
        self.assertEqual([(entry['source'], entry['match']) for entry in own], [('defender', 'argument')])
