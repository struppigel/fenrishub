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
        # powershell.exe only runs a.ps1: listed, but as the host program.
        self.assertEqual(keys[TASK_LINE][r'c:\windows\system32\windowspowershell\v1.0\powershell.exe'], 'host')
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

    def test_a_command_line_detection_is_about_what_the_host_program_runs(self):
        def detections(command_line):
            text = '\n'.join(['Windows Defender:', '================', '', 'TimeCreated : 1/1/2026 1:00:00 AM',
                              'Name: Trojan:PowerShell/X', 'Path: CmdLine:_' + command_line, 'User: x'])
            return [path for _no, _threat, _action, path in iter_addition_defender_detections(text)]

        self.assertEqual(detections(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep bypass '
                                    r'-f "C:\Users\Bob\AppData\Roaming\x.ps1"'),
                         [r'c:\users\username\appdata\roaming\x.ps1'])
        self.assertEqual(detections(r'C:\Windows\System32\cmd.exe /c C:\Windows\System32\rundll32.exe '
                                    r'C:\ProgramData\q\z.dll,Run'), [r'c:\programdata\q\z.dll'])
        # Only Windows' own programs: no file to blame.
        self.assertEqual(detections(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc AAAA'), [])

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
        # The line names powershell.exe and the script: the entry says which file it is about.
        self.assertEqual(result['lines'][TASK_LINE][0]['file'], 'a.ps1')
        self.assertIn('file in command line: a.ps1', result['notes'][TASK_LINE])

    def test_a_merged_log_without_related_logs_uses_its_own_addition_part(self):
        merged = make_uploaded_log('alone-log', log_type='FRST&Addition',
                                   content='\n'.join([ADDITION, HEADER, *FRST_LINES]), forum_username='alone')
        payload = analyze_log_text(merged.content, 'shared')
        UploadedLogAnalysis.objects.create(upload=merged, rule_set_key='shared', payload=payload,
                                           source_content_hash=merged.content_hash)
        result = correlations_for_upload(merged, self.user)
        self.assertEqual(result['scope'], 'user')
        entry = result['lines'][TASK_LINE][0]
        self.assertEqual((entry['upload_id'], entry['source'], entry['file']), ('alone-log', 'defender', 'a.ps1'))
        self.assertEqual(result['statuses'][TASK_LINE], 'B')
        # Not "another Addition log": the log's own part.
        self.assertIn("this log's Addition part", result['notes'][TASK_LINE])
        self.assertNotIn('· Addition', result['notes'][TASK_LINE])
        # A plain FRST log without related logs still has nothing.
        self.assertEqual(correlations_for_upload(
            make_uploaded_log('plain-log', log_type='FRST', content=HEADER, forum_username='alone2'), self.user,
        )['lines'], {})

    def test_hash_entries_name_their_file(self):
        bat = r'C:\Program Files (x86)\Google\Cloud SDK\cloud_env.bat'
        shortcut = (r'ShortcutWithArgument: C:\Users\Public\Desktop\Google Cloud SDK Shell.lnk -> '
                    r'C:\Windows\System32\cmd.exe (Microsoft Corporation) -> /k ""' + bat + '""')
        frst = make_uploaded_log('lnk-log', log_type='FRST', content='\n'.join([HEADER, shortcut]),
                                 forum_username='nobody')
        payload = analyze_log_text(frst.content, 'shared')
        UploadedLogAnalysis.objects.create(upload=frst, rule_set_key='shared', payload=payload,
                                           source_content_hash=frst.content_hash)
        self.link(frst)
        self.add_log('fix-log', 'Fixlog', '\n'.join([
            'Fix result of Farbar Recovery Scan Tool (x64) Version: 01-11-2026',
            f'  [{"96" * 32}] 23-11-2023 01:32:45 - 23-11-2023 01:32:45 -      251 B - Signer: N/A (not PE) - {bat}',
        ]))
        entry = correlations_for_upload(frst, self.user)['lines'][shortcut][0]
        self.assertEqual((entry['kind'], entry['match'], entry['file']), ('hash', 'argument', 'cloud_env.bat'))

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
        # The analyzer finds the row of the log's own entry by its text.
        self.assertEqual(own[0]['line_text'], 'Name: Trojan:Win32/Posilod.EB!cl')


class SoftwareKeyTests(TestCase):
    """Installed programs: Addition's Installed Programs lines, Spor's
    "key" detail and registry targets of scanners / Fixlogs share one key."""

    def test_short_forms_of_frst_and_spor(self):
        from ..correlation_keys import software_keys

        self.assertEqual(software_keys(r'7-Zip 24.09 (x64) (HKLM\...\7-Zip) (Version: 24.09 - Igor Pavlov)'),
                         {'uninstall:7-zip'})
        # A subkey name with parens of its own.
        self.assertEqual(
            software_keys(r'Firefox (HKLM\...\Mozilla Firefox 128.0 (x64 en-US)) (Version: 128.0 - Mozilla)'),
            {'uninstall:mozilla firefox 128.0 (x64 en-us)'},
        )
        self.assertEqual(software_keys(r'HKLM-x32\...\Google Chrome'), {'uninstall:google chrome'})
        self.assertEqual(software_keys(r'HKU\S-1-5-21-1-2-3-1001\...\Discord'), {'uninstall:discord'})
        # An MSI product code is also the msi key.
        self.assertEqual(
            software_keys(r'App (HKLM\...\{599B5A52-33FD-0EA6-D7F2-E62F2058A21C}) (Version: 1.0 - X) Hidden'),
            {'uninstall:{599b5a52-33fd-0ea6-d7f2-e62f2058a21c}', 'msi:599b5a52-33fd-0ea6-d7f2-e62f2058a21c'},
        )

    def test_full_registry_forms(self):
        from ..correlation_keys import software_keys

        self.assertEqual(software_keys(
            r'HKU\S-1-5-21-1-2-3-1002\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\uTorrent'),
            {'uninstall:utorrent'})
        self.assertEqual(software_keys(
            r'HKLM\SOFTWARE\WOW6432NODE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\Crack.exe_is1'),
            {'uninstall:crack.exe_is1'})
        self.assertEqual(software_keys(
            r'"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Evil" => removed successfully'),
            {'uninstall:evil'})
        self.assertEqual(software_keys(r'[HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Evil]'),
                         {'uninstall:evil'})
        # PowerShell's wildcard names no program; a file path no key.
        self.assertEqual(software_keys(r"'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',"), set())
        self.assertEqual(software_keys(r'C:\Program Files\Evil\evil.exe'), set())

    def test_line_and_target_keys(self):
        from ..correlation_keys import msi_key

        line = {'line': r'TeamViewer (HKLM\...\TeamViewer) (Version: 15.83.7 - TeamViewer)', 'components': {}}
        self.assertIn(('uninstall:teamviewer', 'uninstall'), line_keys(line))
        self.assertIn('uninstall:utorrent', target_keys(
            r'HKU\S-1-5-21-1-2-3-1002\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\UNINSTALL\uTorrent'))
        self.assertEqual(msi_key('{795F9101-3A31-5313-82FC-13CFC9E0FE17}'), 'msi:795f9101-3a31-5313-82fc-13cfc9e0fe17')
        self.assertEqual(msi_key('Tailscale'), '')
