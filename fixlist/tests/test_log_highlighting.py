from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from ..log_highlighting import (
    HIGHLIGHTERS, HighlightResult, Stat, _inline, apply_analysis_statuses, compute_tool_stats, highlight_log, iter_lines,
    render_highlighted_html, threat_severity,
)
from ..templatetags.rule_tags import stat_class
from ..models import LogTypeDetectionRule, UploadedLog, count_fixlog_results
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin

# Sanitized excerpts of real logs (usernames, machine names and SIDs replaced).

MAU_REPORT = """======================== MAU Log ========================

Analyzing {3B086246-E935-41F8-BE45-676EF3138112}...
----------------------------------------------------------------------------------------------
                                       UNINSTALL / ARP
----------------------------------------------------------------------------------------------

  DisplayName=PhysX Runtime
  InstallLocation=
  InstallSource=C:\\Users\\User\\AppData\\Local\\Temp\\bib04rPIGTlJO0pi\\
  Publisher=NVIDIA Corporation
RESOLVED: DisplayName=PhysX Runtime
RESOLVED: Publisher=NVIDIA Corporation
RESOLVED: LocalPackage=<none>
----------------------------------------------------------------------------------------------
                                         MSI DATABASE
----------------------------------------------------------------------------------------------

<cached MSI unavailable>
----------------------------------------------------------------------------------------------
                                         DIRECTORIES
----------------------------------------------------------------------------------------------

  EXISTS c:\\windows\\installer
Analysis complete in 1,4s.
Found 57 traces.

----------------------------------------------------------------------------------------------
                                           REMOVAL
----------------------------------------------------------------------------------------------

Selected: 2

Deleted items:
  [RegValue] HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{3B086246-E935-41F8-BE45-676EF3138112}\\UninstallString
  [RegKey] HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{3B086246-E935-41F8-BE45-676EF3138112}
Failed to delete: C:\\Users\\User\\AppData\\Local\\NVIDIA\\locked.dll

Removal summary: Deleted=2 Scheduled=0 Failed=1
"""

MAU_CONSOLE = """[06:05:30] Malicious App Uninstaller Portable
[06:05:30] Loaded 371 installed applications.
[06:06:45] Analyzing {AB23F34D-D8B5-4354-B7BB-256FADCF8A1B}...
[06:06:45] 1. UNINSTALL / ARP
[06:06:45]    Resolved: NetLink Helper
[06:06:45]    Publisher: Broadcom Inc.
[06:06:49] 6. LIVE COM REGISTRATION
[06:06:49]    Skipped
[06:06:49] Found 68 traces.
[06:07:51] Deleted file: c:\\users\\user\\appdata\\local\\netlink\\license
[06:07:51] Removal summary: Deleted=47 Scheduled=1 Failed=0"""

ESET = """05-11-2026 11:16:09
Scanned files: 501243
Detected files: 3
Cleaned files: 2
Total scan time 01:52:18
Scan status: Finished
C:\\Users\\User\\AppData\\Local\\Nox\\fusion_tool\\INSTALLERFUSION.dll\ta variant of MSIL/DotSetupIo.B potentially unwanted application\tcleaned by deleting

C:\\Users\\User\\Downloads\\Fix.7z\ta variant of Win64/GameHack.PV potentially unsafe application\tunable to clean

C:\\Users\\User\\Downloads\\CRICFy.apk\ta variant of Android/Agent.FNM trojan\tcleaned by deleting
"""

MALWAREBYTES = """Malwarebytes
www.malwarebytes.com

-Scan Summary-
Scan Type: Threat Scan
Threats Detected: 2
Threats Quarantined: 2

-Scan Details-
Process: 0
(No malicious items detected)

Registry Key: 1
Trojan.PavinLoader.E, HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\SCHEDULE\\TASKCACHE\\TREE\\ConfigHost, Quarantined, 8322, 1457441, 1.0.116571, , ame, , ,

File: 1
PUP.Optional.TLauncher, C:\\USERS\\USER\\APPDATA\\ROAMING\\.TLAUNCHER\\tlauncher.exe, Sin acciones por parte del usuario, 8322, 1457763, 1.0.116571, , ame, , DB731DE38A5471A744FB09C633CD557F, 033BB9EEF12E0E23ADB36C9788EDAA342704362512A8113D6AAEEC3E01BF83AD

(end)"""

HITMANPRO = """[code]
HitmanPro 3.8.50.346
www.hitmanpro.com

   Computer name . . . . : DESKTOP-TEST
   Threats . . . . . . . : 1
   Traces  . . . . . . . : 2

Malware _____________________________________________________________________

   C:\\Users\\User\\Desktop\\Love Town.exe
      Size . . . . . . . : 4 110 654 bytes
      SHA-256  . . . . . : 5B6E95D043F853FC39E96E57925151CAD01A4239CC96CF37274FF5A7705C6A79
    > SurfRight  . . . . : Mal/Generic-S
      Authenticode . . . : Invalid
         Program is altered or corrupted since it was code signed by its author.
      Forensic Cluster
         -55.9s C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Store\\528ECE41

Cookies _____________________________________________________________________

   C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies:doubleclick.net

[/code]"""

ADWCLEANER_SCAN = """# -------------------------------
# Malwarebytes AdwCleaner 8.7.1.626
# -------------------------------
# Mode: Scan
# Detected: 2


***** [ Services ] *****

No malicious services found.

***** [ Folders ] *****

PUP.Optional.Legacy             C:\\Users\\User\\AppData\\Local\\Tencent

***** [ Registry ] *****

Adware.Ghokswa                  HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules|{1834C62C-1AC6-4753-BF2A-03ACE49B2DE2}

########## EOF - C:\\AdwCleaner\\Logs\\AdwCleaner[S00].txt ##########"""

ADWCLEANER_CLEAN = """# Malwarebytes AdwCleaner 8.8.1.639
# Mode: Clean
# Cleaned:  1
# Failed:   1

***** [ Folders ] *****

Deleted       C:\\Users\\User\\AppData\\Roaming\\Tencent

***** [ Chromium (and derivatives) ] *****

Not Deleted   agibagflppafhfonkefpklndlohkclcb

*************************

[+] Reset Winsock
"""

EMSISOFT = """Emsisoft Emergency Kit - Version 2025.7
Last update: 10/29/2026 11:43:00 AM

Scan settings:

Scan start:\t10/29/2026 11:45:24 AM
C:\\Program Files (x86)\\DeltaFix \tdetected: Application.InstallFix (A) [230134]
K:\\downloads\\Unconfirmed 900225.crdownload -> GAME_CRACK.exe \tdetected: Trojan.GenericKD.36942578 (B) [krnl.xmd]

Scanned\t12404966
Found\t2
Scanning memory...
Scan end:\t10/30/2026 5:27:09 PM"""

FIXLOG = """Fix result of Farbar Recovery Scan Tool (x64) Version: 01-11-2026
Ran by USER (05-11-2026 14:29:00) Run:1
Boot Mode: Normal
==============================================

fixlist content:
*****************
CloseProcesses:
HKU\\S-1-5-21-1-2-3-1002\\Software\\Classes\\.reg:  =>  <==== ATTENTION
FirewallRules: [{0F78B7BA-0DF6-4130-8A07-2F1328EBB77E}] => (Block) D:\\AutoCAD 2027\\acad.exe => No File
Powershell: Format-Hex -InputObject 1
*****************

Processes closed successfully.
C:\\ProgramData\\Nahimic\\AmindPDFCore.dat => moved successfully
"C:\\ProgramData\\Nahimic\\AmindPDFCore.dll" => not found
C:\\ProgramData\\Nahimic\\AmindPDFCore.exe => No running process found
Could not move "C:\\Windows\\System32\\locked.dll" => Access Denied

========= Format-Hex -InputObject 1 =========

Exception calling "ReadAllBytes" with "1" argument(s): "The process cannot access the file"
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException

========= End of Powershell: =========

==== End of Fixlog 14:33:32 ===="""

SHORTCUT = """Users shortcut scan result (x64) Version: 18-10-2026 01
Ran by USER (19-10-2026 00:48:51)
Boot Mode: Normal

==================== Shortcuts =============================

(The entries could be listed to be restored or removed.)

Shortcut: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Excel.lnk -> C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE (Microsoft Corporation)
Shortcut: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\PDF Architect 9.lnk -> C:\\Program Files\\PDF Architect 9\\architect-launcher.exe (No File)
Shortcut: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\WinRAR\\Console RAR manual.lnk -> C:\\Program Files\\WinRAR\\Rar.txt ()
"""

KPRM = """======================================================
# KpRm v3.3.1 \u2014 Report \u2014 20261101080809
# https://github.com/KernelPan1k/KpRm
User               : User
Computer           : DESKTOP-TEST
Run count          : 0
======================================================

Summary
------------------------------------------------------
  Removed                          : 3
  Scheduled for removal on reboot  : 0
  Failed                           : 1

ESET Online Scanner
------------------------------------------------------
  [OK]    C:\\Users\\User\\Desktop\\New folder (2)\\esetonlinescanner.exe (desktop)
  [OK]    HKLM64\\SOFTWARE\\ESET\\ESET Online Scanner           (registry_key)
  [FAILED] C:\\Users\\User\\AppData\\Local\\ESET\\ESETOnlineScanner (folder)

FRST
------------------------------------------------------
  [OK]    C:\\FRST                                            (home_drive)

======================================================
End of report."""

SECURITYCHECK = """SecurityCheck by glax24 & Severnyj v.1.4.0.58 [15.08.24]
WebSite: www.safezone.cc
Log directory: C:\\SecurityCheck\\
___________________________________________________________________________

Windows 10 Core (x64) Release: 22H2 (10.0.19045.6456) Lang: English(0409)
SystemDrive: C: FS: [NTFS] Capacity: [476.1 Gb] Used: [365.8 Gb] Free: [110.3 Gb]
------------------------------- [ Windows ] -------------------------------
User Account Control [b]enabled[/b] (Level 3)
[color=red][b]Never check for updates[/b][/color]
Remote Registry (RemoteRegistry) - The service has stopped
------------------------------- [ HotFix ] --------------------------------
HotFix KB5126657 [color=red][b]Warning! [url=https://www.catalog.update.microsoft.com/Search.aspx?q=KB5126657]Download Update[/url][/b][/color]
--------------------------- [ OtherUtilities ] ----------------------------
Steam v.2.10.91.91"""

FRST_SEARCH = """Farbar Recovery Scan Tool (x64) Version: 22-10-2026
Ran by User (25-10-2026 22:04:53)
Running from C:\\Users\\User\\Downloads
Boot Mode: Normal

================== Search Files: "SearchAll: ChurnDashboard" =============

File:
========
C:\\FRST\\Quarantine\\C\\Users\\User\\AppData\\Roaming\\Microsoft\\Protect\\ChurnDashboard\\ChurnDashboard.sln.xBAD
[2026-10-21 17:21][2026-10-21 17:21] 000000997 ____H () 389700D32DB7ECC74AF1DCF801F05A05 [File not signed]

Folder:
========
2026-10-25 03:08 - 2026-10-25 03:08 _____ C:\\FRST\\Quarantine\\C\\Users\\User\\AppData\\Roaming\\Microsoft\\Protect\\ChurnDashboard

Registry:
========

===================== Search result for "ChurnDashboard" ==========

[HKEY_USERS\\S-1-5-21-1-2-3-1003\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths]
"url5"="C:\\Users\\User\\AppData\\Local\\Microsoft\\Windows\\WebCache\\ChurnDashboard"

====== End of Search ======"""

FRST = """Scan result of Farbar Recovery Scan Tool (FRST) (x64) Version: 01-11-2026
Ran by User (administrator) on DESKTOP-TEST (05-11-2026 12:37:58)
Boot Mode: Normal

==================== Processes (Whitelisted) =================

(If an entry is included in the fixlist, the process will be closed. The file will not be moved.)

(Adobe Inc. -> Adobe Inc.) C:\\Program Files\\Adobe\\Adobe Creative Cloud\\ACC\\Creative Cloud.exe <5>
(PostgreSQL Global Development Group) [File not signed] C:\\Users\\User\\PostgreSQL\\bin\\postgres.exe
(services.exe ->) (Bad Corp -> ) C:\\Users\\User\\AppData\\Local\\Evil\\evil.exe

==================== Registry (Whitelisted) ===================

HKLM\\...\\Run: [SteelSeriesGG] => C:\\Program Files\\SteelSeries\\GG\\SteelSeriesGGEZ.exe [195640 2026-10-19] (GN Hearing A/S -> SteelSeries A/S)
HKLM\\Software\\Policies\\...\\system: [EnableSmartScreen] 0 <==== ATTENTION
2026-10-21 17:21 - 2026-10-21 17:21 - 000005912 ____H C:\\Users\\User\\AppData\\Roaming\\New folder (2)\\x.dat

==================== End of FRST.txt ========================"""

# What the analyzer would cache for FRST: one entry per non-blank line.
FRST_VERDICTS = {
    'Creative Cloud.exe <5>': ('C', 'status-c'),
    'postgres.exe': ('P', 'status-p'),
    'evil.exe': ('B', 'status-b'),
    'EnableSmartScreen': ('!', 'status-w'),
}


def _frst_payload(content, verdicts=FRST_VERDICTS):
    from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
    lines = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        status, css = next(((s, c) for needle, (s, c) in verdicts.items() if needle in line),
                           ('?', 'status-unknown'))
        lines.append({'line': line, 'dominant_status': status, 'css_class': css})
    return {'format': ANALYSIS_PAYLOAD_FORMAT, 'lines': lines, 'summary': {}, 'warnings': []}


FIXTURES = {
    'FRST': [FRST],
    'Addition': [FRST.replace('Scan result', 'Additional scan result')],
    'FRST&Addition': [FRST],
    'FRST Search': [FRST_SEARCH],
    'KpRm': [KPRM],
    'SecurityCheck': [SECURITYCHECK],
    'MAU': [MAU_REPORT, MAU_CONSOLE],
    'ESET': [ESET],
    'Malwarebytes': [MALWAREBYTES],
    'HitmanPro': [HITMANPRO],
    'AdwCleaner': [ADWCLEANER_SCAN, ADWCLEANER_CLEAN],
    'Emsisoft': [EMSISOFT],
    'Fixlog': [FIXLOG],
    'Shortcut': [SHORTCUT],
}


def _no(content, needle):
    """1-based number of the first fixture line containing `needle`."""
    for index, line in enumerate(content.split('\n')):
        if needle in line:
            return index + 1
    raise AssertionError(f'{needle!r} not in fixture')


def _line(result, content, needle):
    return _lines(result)[_no(content, needle)]


def _lines(result):
    return {line.no: line for line in iter_lines(result)}


def _classes(line):
    return {cls: text for cls, text in line.tokens if cls}


def _headers(result):
    return [section.header.text.strip() for section in result.sections if section.header is not None]


class HighlightRoundTripTests(SimpleTestCase):

    def test_every_fixture_round_trips_to_the_original_text(self):
        for log_type, samples in FIXTURES.items():
            for content in samples:
                for variant in (content, content.replace('\n', '\r\n')):
                    with self.subTest(log_type=log_type, crlf='\r' in variant):
                        result = highlight_log(log_type, variant)
                        self.assertIsNotNone(result)
                        lines = list(iter_lines(result))
                        self.assertEqual([line.no for line in lines], list(range(1, len(lines) + 1)))
                        self.assertEqual('\n'.join(line.text for line in lines), variant)

    def test_every_highlighter_has_a_fixture(self):
        self.assertEqual(set(HIGHLIGHTERS), set(FIXTURES))

    def test_unsupported_types_return_none(self):
        for log_type in ('Unknown', 'SomeNewTool', ''):
            with self.subTest(log_type=log_type):
                self.assertIsNone(highlight_log(log_type, 'Scan result of Farbar'))

    def test_empty_content_returns_none(self):
        self.assertIsNone(highlight_log('ESET', ''))

    def test_oversized_log_falls_back_to_plain_view(self):
        with mock.patch('fixlist.log_highlighting.MAX_HIGHLIGHT_CHARS', len(ESET) - 1):
            self.assertIsNone(highlight_log('ESET', ESET))
        self.assertIsNotNone(highlight_log('ESET', ESET))

    def test_highlighter_exception_falls_back_to_none(self):
        with mock.patch.dict(HIGHLIGHTERS, {'ESET': mock.Mock(side_effect=ValueError('boom'))}):
            with self.assertLogs('fixlist.log_highlighting', level='ERROR'):
                self.assertIsNone(highlight_log('ESET', ESET))

    def test_unbounded_line_is_handled_quickly(self):
        # Long path-like lines must not trigger pathological regex behaviour.
        line = 'C:\\' + 'a (b ' * 20000
        for log_type in HIGHLIGHTERS:
            with self.subTest(log_type=log_type):
                result = highlight_log(log_type, line)
                self.assertEqual(next(iter_lines(result)).text, line)


class ThreatSeverityTests(SimpleTestCase):

    def test_severity_mapping(self):
        cases = {
            'Trojan.PavinLoader.E': 'b',
            'a variant of Win32/Packed.VMProtect.ACV trojan': 'b',
            'Mal/Generic-S': 'b',
            'PUP.Optional.Legacy': 'p',
            'Adware.Ghokswa': 'p',
            'a variant of Win64/MiniTool.A potentially unwanted application': 'p',
            'Application.ProcessHacker.1': 'p',
            'Gen:Variant.Application.Deceptor.Uniblue.2': 'p',
            'PUM.Optional.DisabledSecurityCenter': 'g',
            'RiskWare.AutoKMS': 'g',
            'Win64/HackTool.Crack.FG potentially unsafe application': 'g',
            'a variant of Win64/Packed.Themida.Q suspicious application': 'g',
            'Generic.Malware/Suspicious': 'g',
            'SomethingNew': 'b',
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(threat_severity(name), expected)


class PerToolHighlightTests(SimpleTestCase):

    def test_mau_report_sections_products_and_counts(self):
        result = highlight_log('MAU', MAU_REPORT)
        self.assertIn('Analyzing {3B086246-E935-41F8-BE45-676EF3138112}...', _headers(result))
        self.assertIn('UNINSTALL / ARP', _headers(result))
        self.assertIn('REMOVAL', _headers(result))
        product = result.summary[0]
        self.assertEqual((product.line_no, product.severity), (_no(MAU_REPORT, 'Analyzing'), 'i'))
        self.assertEqual(product.name, 'PhysX Runtime')
        self.assertEqual(product.action, 'NVIDIA Corporation')
        failed = [item for item in result.summary if item.severity == 'b']
        self.assertEqual([item.line_no for item in failed], [_no(MAU_REPORT, 'Failed to delete')])
        stats = {stat.label: (stat.value, stat.severity) for stat in result.stats}
        self.assertEqual(stats['Traces found'], ('57', 'w'))
        self.assertEqual(stats['Deleted'], ('2', 'c'))
        self.assertEqual(stats['Failed'], ('1', 'b'))
        self.assertEqual(_classes(_line(result, MAU_REPORT, 'LocalPackage=<none>'))['hl-dim'], '<none>')
        self.assertEqual(_classes(_line(result, MAU_REPORT, 'Removal summary'))['hl-sev-b'], 'Failed=1')

    def test_mau_console_format(self):
        result = highlight_log('MAU', MAU_CONSOLE)
        lines = _lines(result)
        self.assertEqual(lines[1].tokens[0], ('hl-dim', '[06:05:30] '))
        self.assertIn('1. UNINSTALL / ARP', [h.split('] ', 1)[1] for h in _headers(result)])
        product = result.summary[0]
        self.assertEqual((product.name, product.action), ('NetLink Helper', 'Broadcom Inc.'))
        self.assertEqual(_classes(lines[10])['hl-sev-c'], 'Deleted file:')
        stats = {stat.label: (stat.value, stat.severity) for stat in result.stats}
        self.assertEqual(stats['Scheduled'], ('1', 'w'))

    def test_eset_detections_and_actions(self):
        result = highlight_log('ESET', ESET)
        self.assertEqual(
            [(item.line_no, item.severity) for item in result.summary],
            [(7, 'p'), (9, 'g'), (11, 'b')],
        )
        lines = _lines(result)
        self.assertEqual(_classes(lines[9])['hl-sev-w'], 'unable to clean')
        self.assertEqual(_classes(lines[11])['hl-sev-b'], 'a variant of Android/Agent.FNM trojan')
        self.assertEqual(_classes(lines[11])['hl-sev-c'], 'cleaned by deleting')
        self.assertEqual(_classes(lines[7])['hl-path'], 'C:\\Users\\User\\AppData\\Local\\Nox\\fusion_tool\\INSTALLERFUSION.dll')
        self.assertEqual([(s.label, s.value, s.severity) for s in result.stats], [('Detected files', '3', 'b')])

    def test_malwarebytes_detections_and_categories(self):
        result = highlight_log('Malwarebytes', MALWAREBYTES)
        self.assertEqual(_headers(result), ['-Scan Summary-', '-Scan Details-'])
        trojan_no = _no(MALWAREBYTES, 'Trojan.PavinLoader.E,')
        pup_no = _no(MALWAREBYTES, 'PUP.Optional.TLauncher,')
        self.assertEqual([(i.line_no, i.severity, i.action) for i in result.summary],
                         [(trojan_no, 'b', 'Quarantined'), (pup_no, 'p', 'Sin acciones por parte del usuario')])
        lines = _lines(result)
        self.assertEqual(_classes(_line(result, MALWAREBYTES, 'Process: 0'))['hl-sev-j'], '0')
        self.assertEqual(_classes(_line(result, MALWAREBYTES, '(No malicious'))['hl-dim'],
                         '(No malicious items detected)')
        self.assertEqual(_classes(lines[trojan_no])['hl-sev-c'], 'Quarantined')
        self.assertEqual(_classes(lines[pup_no])['hl-sev-w'], 'Sin acciones por parte del usuario')
        self.assertTrue(_classes(lines[trojan_no])['hl-reg'].startswith('HKLM\\SOFTWARE'))
        # MD5 and SHA-256 at the end of a file detection are separate, copyable tokens.
        hashes = [text for cls, text in lines[pup_no].tokens if cls == 'hl-hash']
        self.assertEqual(hashes, ['DB731DE38A5471A744FB09C633CD557F',
                                  '033BB9EEF12E0E23ADB36C9788EDAA342704362512A8113D6AAEEC3E01BF83AD'])
        self.assertTrue(result.has_sections)
        self.assertFalse(highlight_log('ESET', ESET).has_sections)

    def test_hitmanpro_sections_and_vendor_names(self):
        result = highlight_log('HitmanPro', HITMANPRO)
        self.assertEqual(_headers(result), ['Malware _____________________________________________________________________',
                                            'Cookies _____________________________________________________________________'])
        malware, cookie = result.summary
        self.assertEqual((malware.line_no, malware.severity, malware.name, malware.action),
                         (11, 'b', 'Mal/Generic-S', 'SurfRight'))
        self.assertEqual((cookie.severity, cookie.name), ('j', 'Cookies'))
        lines = _lines(result)
        self.assertEqual(_classes(lines[6])['hl-sev-b'], ' 1')
        self.assertIn('hl-hash', _classes(lines[13]))
        self.assertEqual(_classes(lines[15])['hl-sev-w'], ' Invalid')

    def test_adwcleaner_scan_and_clean_modes(self):
        scan = highlight_log('AdwCleaner', ADWCLEANER_SCAN)
        self.assertEqual(_headers(scan), ['***** [ Services ] *****', '***** [ Folders ] *****', '***** [ Registry ] *****'])
        self.assertEqual([(i.severity, i.name) for i in scan.summary],
                         [('p', 'PUP.Optional.Legacy'), ('p', 'Adware.Ghokswa')])
        clean = highlight_log('AdwCleaner', ADWCLEANER_CLEAN)
        self.assertEqual(clean.summary_title, 'AdwCleaner failures')
        self.assertEqual([(i.severity, i.name, i.target) for i in clean.summary],
                         [('w', 'Not Deleted', 'agibagflppafhfonkefpklndlohkclcb')])
        self.assertEqual(_classes(_line(clean, ADWCLEANER_CLEAN, 'Deleted       '))['hl-sev-c'], 'Deleted')

    def test_emsisoft_detections(self):
        result = highlight_log('Emsisoft', EMSISOFT)
        self.assertEqual([(i.line_no, i.severity, i.name) for i in result.summary],
                         [(7, 'p', 'Application.InstallFix'), (8, 'b', 'Trojan.GenericKD.36942578')])
        self.assertEqual([(s.label, s.value, s.severity) for s in result.stats], [('Found', '2', 'b')])

    def test_fixlog_results_and_failures(self):
        result = highlight_log('Fixlog', FIXLOG)
        self.assertIn('fixlist content:', _headers(result))
        # Echoed fixlist lines are not results, even with " => " in them.
        self.assertEqual(_classes(_line(result, FIXLOG, 'ATTENTION'))['hl-sev-w'], '<==== ATTENTION')
        firewall = _classes(_line(result, FIXLOG, 'FirewallRules:'))
        self.assertNotIn('hl-sev-w', firewall)
        self.assertEqual(firewall['hl-accent'], 'FirewallRules:')
        self.assertEqual(_classes(_line(result, FIXLOG, 'AmindPDFCore.dat'))['hl-sev-c'], 'moved successfully')
        self.assertEqual(_classes(_line(result, FIXLOG, 'AmindPDFCore.dll'))['hl-sev-w'], 'not found')
        self.assertEqual(_classes(_line(result, FIXLOG, 'AmindPDFCore.exe'))['hl-sev-j'], 'No running process found')
        self.assertEqual(
            [(i.line_no, i.severity, i.name) for i in result.summary],
            [(_no(FIXLOG, 'AmindPDFCore.dll'), 'w', 'not found'),
             (_no(FIXLOG, 'Could not move'), 'b', 'Access Denied'),
             (_no(FIXLOG, 'Exception calling'), 'b', 'PowerShell error')],
        )

    def test_kprm_sections_counts_and_items(self):
        result = highlight_log('KpRm', KPRM)
        self.assertEqual(_headers(result), ['Summary', 'ESET Online Scanner', 'FRST'])
        stats = {stat.label: (stat.value, stat.severity) for stat in result.stats}
        self.assertEqual(stats['Removed'], ('3', 'c'))
        self.assertEqual(stats['Scheduled for removal on reboot'], ('0', 'j'))
        self.assertEqual(stats['Failed'], ('1', 'b'))
        ok_line = _classes(_line(result, KPRM, 'esetonlinescanner.exe'))
        self.assertEqual(ok_line['hl-sev-c'], '[OK]')
        self.assertEqual(ok_line['hl-path'], 'C:\\Users\\User\\Desktop\\New folder (2)\\esetonlinescanner.exe')
        self.assertEqual(ok_line['hl-dim'], ' (desktop)')
        self.assertEqual(_classes(_line(result, KPRM, 'HKLM64'))['hl-reg'],
                         'HKLM64\\SOFTWARE\\ESET\\ESET Online Scanner')
        self.assertEqual(
            [(i.line_no, i.severity, i.name, i.action) for i in result.summary],
            [(_no(KPRM, '[FAILED]'), 'b', '[FAILED]', 'ESET Online Scanner')],
        )

    def test_securitycheck_bbcode_is_hidden_and_styled(self):
        result = highlight_log('SecurityCheck', SECURITYCHECK)
        self.assertEqual(_headers(result)[:2], [
            '------------------------------- [ Windows ] -------------------------------',
            '------------------------------- [ HotFix ] --------------------------------',
        ])
        self.assertFalse(result.has_summary)
        hotfix = _line(result, SECURITYCHECK, 'HotFix KB')
        tags = [text for cls, text in hotfix.tokens if cls == 'hl-bbtag']
        self.assertEqual(tags[:3], ['[color=red]', '[b]',
                                    '[url=https://www.catalog.update.microsoft.com/Search.aspx?q=KB5126657]'])
        self.assertIn(('hl-sev-b hl-bold', 'Warning! '), hotfix.tokens)
        self.assertIn(('hl-url hl-bold', 'Download Update'), hotfix.tokens)
        # Square brackets that are not BBCode stay visible text.
        drive = _line(result, SECURITYCHECK, 'SystemDrive')
        self.assertNotIn('hl-bbtag', _classes(drive))
        self.assertIn('[NTFS]', drive.text)
        self.assertIn(('hl-sev-b hl-bold', 'Never check for updates'),
                      _line(result, SECURITYCHECK, 'Never check').tokens)
        self.assertEqual(_classes(_line(result, SECURITYCHECK, 'RemoteRegistry'))['hl-dim'],
                         'The service has stopped')
        self.assertIn('hl-bbtag', render_highlighted_html(result))

    def test_frst_syntax(self):
        result = highlight_log('FRST', FRST)
        self.assertEqual(_headers(result), [
            '==================== Processes (Whitelisted) =================',
            '==================== Registry (Whitelisted) ===================',
        ])
        self.assertEqual(_classes(_line(result, FRST, '(If an entry'))['hl-dim'][:6], '(If an')
        adobe = _line(result, FRST, 'Creative Cloud.exe')
        self.assertIn(('hl-company', '(Adobe Inc. -> Adobe Inc.)'), adobe.tokens)
        self.assertIn(('hl-dim', ' <5>'), adobe.tokens)
        self.assertTrue(_classes(adobe)['hl-path'].endswith('Creative Cloud.exe'))
        self.assertIn(('hl-sev-w', '[File not signed]'), _line(result, FRST, 'postgres.exe').tokens)
        run = _line(result, FRST, 'SteelSeriesGG')
        self.assertIn(('hl-dim', '[195640 2026-10-19]'), run.tokens)
        self.assertIn(('hl-company', '(GN Hearing A/S -> SteelSeries A/S)'), run.tokens)
        self.assertIn(('hl-sev-w', '<==== ATTENTION'), _line(result, FRST, 'ATTENTION').tokens)
        dated = _line(result, FRST, '____H')
        self.assertEqual(dated.tokens[0], ('hl-dim', '2026-10-21 17:21 - 2026-10-21 17:21 - 000005912 ____H '))
        self.assertTrue(_classes(dated)['hl-path'].endswith('New folder (2)\\x.dat'))
        self.assertEqual(_classes(_line(result, FRST, 'Boot Mode'))['hl-key'], 'Boot Mode:')

    def test_frst_rule_statuses_paint_lines_and_fill_summary(self):
        result = highlight_log('FRST', FRST)
        self.assertTrue(apply_analysis_statuses(result, FRST, _frst_payload(FRST)))
        self.assertEqual(
            [(i.line_no, i.severity) for i in result.summary],
            [(_no(FRST, 'postgres.exe'), 'p'), (_no(FRST, 'evil.exe'), 'b'), (_no(FRST, 'EnableSmartScreen'), 'w')],
        )
        evil = _line(result, FRST, 'evil.exe')
        self.assertEqual((evil.status, evil.paint), ('B', 'b'))
        self.assertEqual(_line(result, FRST, 'Creative Cloud.exe').status, 'C')
        self.assertEqual(_line(result, FRST, 'Boot Mode').status, '')  # '?' lines stay unpainted
        html = render_highlighted_html(result)
        no = _no(FRST, 'evil.exe')
        self.assertIn(f'<span class="hl-line hl-st-b" id="L{no}" data-n="{no}" data-st="B">', html)
        self.assertEqual('\n'.join(line.text for line in iter_lines(result)), FRST)

    def test_frst_stale_or_mismatched_analysis_is_not_applied(self):
        result = highlight_log('FRST', FRST)
        payload = _frst_payload(FRST)
        payload['lines'][3]['line'] = 'something else'
        self.assertFalse(apply_analysis_statuses(result, FRST, payload))
        short = _frst_payload(FRST)
        short['lines'].pop()
        self.assertFalse(apply_analysis_statuses(result, FRST, short))
        self.assertFalse(apply_analysis_statuses(result, FRST, {'lines': None}))
        self.assertEqual(result.summary, [])
        self.assertFalse(any(line.status for line in iter_lines(result)))

    def test_frst_search_files_folders_and_registry(self):
        result = highlight_log('FRST Search', FRST_SEARCH)
        self.assertEqual(_headers(result), [
            '================== Search Files: "SearchAll: ChurnDashboard" =============',
            '===================== Search result for "ChurnDashboard" ==========',
        ])
        self.assertFalse(result.has_summary)
        file_line = _classes(_line(result, FRST_SEARCH, 'ChurnDashboard.sln.xBAD'))
        self.assertTrue(file_line['hl-path'].endswith('ChurnDashboard.sln.xBAD'))
        meta = _classes(_line(result, FRST_SEARCH, '[2026-10-21'))
        self.assertEqual(meta['hl-hash'], '389700D32DB7ECC74AF1DCF801F05A05')
        self.assertEqual(meta['hl-sev-w'], '[File not signed]')
        folder = _classes(_line(result, FRST_SEARCH, '_____ C:'))
        self.assertTrue(folder['hl-path'].endswith('Protect\\ChurnDashboard'))
        self.assertTrue(_classes(_line(result, FRST_SEARCH, '[HKEY_USERS'))['hl-reg'].endswith('TypedPaths'))
        value = _classes(_line(result, FRST_SEARCH, '"url5"'))
        self.assertEqual(value['hl-key'], '"url5"')
        self.assertTrue(value['hl-path'].endswith('WebCache\\ChurnDashboard'))
        self.assertEqual(_classes(_line(result, FRST_SEARCH, 'File:'))['hl-subheader'], 'File:')

    def test_paths_after_underscore_and_with_numbered_folders_are_whole(self):
        # Defender output in a Fixlog: "file:_C:\..." with a "(1)" folder.
        content = ('Path     : file:_C:\\Users\\USER\\Downloads\\_Getintopc.com_Nitro_Pro_13.70.2.40 (1)'
                   '\\Nitro_Pro_13.70.2.40\\Nitro Pro ')
        result = highlight_log('Fixlog', content)
        paths = [text for cls, text in next(iter_lines(result)).tokens if cls == 'hl-path']
        self.assertEqual(paths, ['C:\\Users\\USER\\Downloads\\_Getintopc.com_Nitro_Pro_13.70.2.40 (1)'
                                 '\\Nitro_Pro_13.70.2.40\\Nitro Pro'])
        # A company in parentheses after the path still ends it.
        tokens = _inline('C:\\Tools\\x.exe (Some Company)')
        self.assertEqual(tokens[0], ('hl-path', 'C:\\Tools\\x.exe'))
        # A letter directly before the drive is not a path start.
        self.assertNotIn('hl-path', {cls for cls, _ in _inline('ABC:\\foo')})

    def test_paths_end_at_separators_that_cannot_be_part_of_a_file_name(self):
        def first_path(text):
            return next(t for c, t in _inline(text) if c == 'hl-path')
        # Defender: resources separated by "; ", archive members after "->".
        self.assertEqual(first_path('Path: file:_C:\\Users\\pc\\MSBuild.exe; \r'), 'C:\\Users\\pc\\MSBuild.exe')
        self.assertEqual(first_path('containerfile:_C:\\Users\\pc\\Dopamine.ipa; file:_C:\\x'),
                         'C:\\Users\\pc\\Dopamine.ipa')
        self.assertEqual(first_path('file:_C:\\Users\\pc\\Downloads\\Dopamine.ipa->Payload/Dopamine.app/kfd'),
                         'C:\\Users\\pc\\Downloads\\Dopamine.ipa')
        # FRST parent process group "(C:\...\x.exe ->)".
        self.assertEqual(first_path('(C:\\Program Files (x86)\\Adobe\\ADS\\Adobe Desktop Service.exe ->) '),
                         'C:\\Program Files (x86)\\Adobe\\ADS\\Adobe Desktop Service.exe')
        self.assertEqual(first_path('C:\\x\\y.exe <==== ATTENTION'), 'C:\\x\\y.exe')
        # A semicolon inside a name stays.
        self.assertEqual(first_path('C:\\a;b\\c.txt'), 'C:\\a;b\\c.txt')

    def test_arrow_targets_are_split_into_separate_paths(self):
        # Each side of "->" must be its own token so a click copies one path.
        result = highlight_log('Emsisoft', EMSISOFT)
        line = _line(result, EMSISOFT, 'GAME_CRACK')
        paths = [text for cls, text in line.tokens if cls == 'hl-path']
        self.assertEqual(paths, ['K:\\downloads\\Unconfirmed 900225.crdownload'])

    def test_hitmanpro_entry_paths_are_copyable(self):
        result = highlight_log('HitmanPro', HITMANPRO)
        entry = _line(result, HITMANPRO, 'Love Town.exe')
        self.assertIn(('hl-entry hl-path hl-sev-b', 'C:\\Users\\User\\Desktop\\Love Town.exe'), entry.tokens)

    def test_shortcut_company_and_missing_targets(self):
        result = highlight_log('Shortcut', SHORTCUT)
        self.assertEqual(result.summary, [])
        self.assertFalse(result.has_summary)
        lines = _lines(result)
        self.assertEqual(_classes(lines[9])['hl-company'], 'Microsoft Corporation')
        self.assertEqual(_classes(lines[10])['hl-sev-w'], ' (No File)')
        self.assertEqual(_classes(lines[11])['hl-sev-w'], ' ()')


class ToolStatsChipTests(SimpleTestCase):
    """Chips for the uploads / cases lists, stored on UploadedLog.tool_stats."""

    def test_detection_tools_count_by_severity(self):
        self.assertEqual(compute_tool_stats('ESET', ESET), [['B', 1, 'b'], ['P', 1, 'p'], ['G', 1, 'g']])
        self.assertEqual(compute_tool_stats('Malwarebytes', MALWAREBYTES),
                         [['B', 1, 'b'], ['P', 1, 'p'], ['G', 0, 'j']])
        self.assertEqual(compute_tool_stats('Emsisoft', EMSISOFT), [['B', 1, 'b'], ['P', 1, 'p'], ['G', 0, 'j']])
        self.assertEqual(compute_tool_stats('HitmanPro', HITMANPRO),
                         [['B', 1, 'b'], ['P', 0, 'j'], ['G', 0, 'j'], ['traces', 1, 'j']])
        self.assertEqual(compute_tool_stats('AdwCleaner', ADWCLEANER_SCAN),
                         [['B', 0, 'j'], ['P', 2, 'p'], ['G', 0, 'j']])

    def test_removal_tools_show_removal_counts(self):
        self.assertEqual(compute_tool_stats('AdwCleaner', ADWCLEANER_CLEAN),
                         [['cleaned', 1, 'c'], ['failed', 1, 'w']])
        self.assertEqual(compute_tool_stats('MAU', MAU_REPORT),
                         [['deleted', 2, 'c'], ['sched', 0, 'j'], ['failed', 1, 'b']])
        self.assertEqual(compute_tool_stats('MAU', MAU_CONSOLE),
                         [['deleted', 47, 'c'], ['sched', 1, 'w'], ['failed', 0, 'j']])
        self.assertEqual(compute_tool_stats('KpRm', KPRM),
                         [['removed', 3, 'c'], ['sched', 0, 'j'], ['failed', 1, 'b']])

    def test_other_tools(self):
        self.assertEqual(compute_tool_stats('Shortcut', SHORTCUT),
                         [['shortcuts', 3, 'i'], ['no file', 1, 'w']])
        self.assertEqual(compute_tool_stats('FRST Search', FRST_SEARCH),
                         [['files', 1, 'i'], ['folders', 1, 'i'], ['reg', 1, 'i']])
        self.assertEqual(compute_tool_stats('SecurityCheck', SECURITYCHECK),
                         [['upd', 1, 'w'], ['eol', 0, 'j'], ['pup', 0, 'j'], ['rdp', 0, 'j'], ['set', 1, 'w']])

    def test_zero_counts_are_grey_everywhere(self):
        self.assertEqual(Stat('Deleted', '0', 'c').severity, 'j')
        self.assertEqual(Stat('Threats', ' 0', 'b').severity, 'j')
        self.assertEqual(Stat('Deleted', '3', 'c').severity, 'c')
        self.assertEqual(stat_class(0, 'b'), 'stat-j')
        self.assertEqual(stat_class(4, 'b'), 'stat-b')
        self.assertEqual(stat_class(None, 'b'), 'stat-j')
        clean_none = ADWCLEANER_CLEAN.replace('# Cleaned:  1', '# Cleaned:  0')
        stats = {s.label: s.severity for s in highlight_log('AdwCleaner', clean_none).stats}
        self.assertEqual(stats['Cleaned'], 'j')
        mau = highlight_log('MAU', MAU_CONSOLE.replace('Deleted=47', 'Deleted=0'))
        summary_line = _line(mau, MAU_CONSOLE, 'Removal summary')
        self.assertIn(('hl-sev-j', 'Deleted=0'), summary_line.tokens)

    def test_types_with_dedicated_fields_get_no_chips(self):
        for log_type in ('Fixlog', 'FRST', 'Addition', 'FRST&Addition', 'Unknown'):
            with self.subTest(log_type=log_type):
                self.assertEqual(compute_tool_stats(log_type, FIXLOG), [])


class FixlogCountTests(SimpleTestCase):

    def test_echoed_fixlist_lines_are_not_counted_as_results(self):
        # The fixture's echoed fixlist has two " => " lines (ATTENTION, FirewallRules).
        self.assertEqual(count_fixlog_results(FIXLOG),
                         {'total': 4, 'success': 1, 'not_found': 1, 'error': 0})

    def test_fixlog_without_fixlist_section_counts_every_result(self):
        content = 'a => moved successfully\nb => not found\nc => Error deleting\nplain line'
        self.assertEqual(count_fixlog_results(content),
                         {'total': 3, 'success': 1, 'not_found': 1, 'error': 1})


class ToolStatsPersistenceTests(UploadedLogSharedSetupMixin, TestCase):

    def test_recalculate_analysis_stats_stores_chips(self):
        upload = UploadedLog.objects.create(
            upload_id='chip-scanner', forum_username='forum_user', content=ESET, log_type='ESET',
        )
        upload.recalculate_analysis_stats()
        upload.refresh_from_db()
        self.assertEqual(upload.tool_stats, [['B', 1, 'b'], ['P', 1, 'p'], ['G', 1, 'g']])

    def test_uploads_list_shows_tool_chips(self):
        UploadedLog.objects.create(
            upload_id='listed-scanner', forum_username='forum_user', content=ESET, log_type='ESET',
            recipient_user=self.user, tool_stats=[['B', 1, 'b'], ['P', 0, 'j']],
        )
        self.client.login(username='alice', password='password123')
        response = self.client.get(reverse('uploaded_logs'))
        self.assertContains(response, '<span class="stat-b">B 1</span>')
        self.assertContains(response, '<span class="stat-j">P 0</span>')

    def test_frst_and_fixlog_list_chips_are_grey_when_zero(self):
        UploadedLog.objects.create(
            upload_id='zero-forest', forum_username='forum_user', content='x', log_type='FRST',
            recipient_user=self.user, count_malware=2, count_pup=0, count_unknown=0,
        )
        UploadedLog.objects.create(
            upload_id='zero-fix', forum_username='forum_user', content='x', log_type='Fixlog',
            recipient_user=self.user, fixlog_total=3, fixlog_success=3, fixlog_not_found=0, fixlog_error=0,
        )
        self.client.login(username='alice', password='password123')
        response = self.client.get(reverse('uploaded_logs'))
        self.assertContains(response, '<span class="stat-b">B 2</span>')
        self.assertContains(response, '<span class="stat-j">P 0</span>')
        self.assertContains(response, '<span class="stat-j">? 0</span>')
        self.assertContains(response, '<span class="stat-c">ok 3</span>')
        self.assertContains(response, '<span class="stat-j">n/f 0</span>')
        self.assertContains(response, '<span class="stat-j">err 0</span>')

    def test_oversized_fixlog_still_shows_stats_above_plain_view(self):
        upload = UploadedLog.objects.create(
            upload_id='huge-fix', forum_username='forum_user', content=FIXLOG, log_type='Fixlog',
            fixlog_total=5, fixlog_success=5,
        )
        self.client.login(username='alice', password='password123')
        with mock.patch('fixlist.log_highlighting.MAX_HIGHLIGHT_CHARS', 10):
            response = self.client.get(reverse('view_uploaded_log', args=[upload.upload_id]))
        self.assertContains(response, 'id="highlightSummary"')
        self.assertContains(response, '<span class="hl-stat-label">ok:</span> <span class="hl-sev-c">5</span>')
        self.assertContains(response, '<span class="hl-stat-label">err:</span> <span class="hl-sev-j">0</span>')
        self.assertContains(response, 'class="log-chunk"')
        self.assertNotContains(response, 'class="hl-line"')
        self.assertNotContains(response, 'nothing found')

    def test_fixlog_detail_summary_shows_list_chip_numbers(self):
        upload = UploadedLog.objects.create(
            upload_id='fixed-system', forum_username='forum_user', content=FIXLOG, log_type='Fixlog',
            fixlog_total=7, fixlog_success=4, fixlog_not_found=2, fixlog_error=1,
        )
        self.client.login(username='alice', password='password123')
        response = self.client.get(reverse('view_uploaded_log', args=[upload.upload_id]))
        self.assertContains(response, '<span class="hl-stat-label">ops:</span> <span class="hl-sev-">7</span>')
        self.assertContains(response, '<span class="hl-stat-label">ok:</span> <span class="hl-sev-c">4</span>')
        self.assertContains(response, '<span class="hl-stat-label">n/f:</span> <span class="hl-sev-u">2</span>')
        self.assertContains(response, '<span class="hl-stat-label">err:</span> <span class="hl-sev-b">1</span>')


class RenderHighlightedHtmlTests(SimpleTestCase):

    def test_render_escapes_markup_and_marks_lines(self):
        content = 'C:\\x\\<script>alert(1)</script>.exe\tBAT/Runner.QT trojan\tcleaned by deleting'
        html = render_highlighted_html(highlight_log('ESET', content))
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)
        self.assertIn('id="L1" data-n="1"', html)

    def test_render_keeps_carriage_returns_as_character_references(self):
        html = render_highlighted_html(highlight_log('ESET', 'Scan status: Finished\r\nnext'))
        self.assertIn('&#13;', html)
        self.assertNotIn('\r', html)

    def test_sections_render_as_open_details_with_line_count(self):
        html = render_highlighted_html(highlight_log('AdwCleaner', ADWCLEANER_SCAN))
        self.assertIn('<details open class="hl-section">', html)
        self.assertIn('<summary class="hl-line hl-section-header" id="L8" data-n="8" data-count="3">', html)

    def test_virustotal_urls_render_as_links_and_other_urls_do_not(self):
        vt = 'https://www.virustotal.com/gui/file/4231121502A23A485797C295B317280CE14ADEE1C9A81F5B3299DC0F7D432422'
        content = f'  VirusTotal Report: {vt}\n  Support: https://evil.example/payload.exe'
        result = highlight_log('MAU', content)
        html = render_highlighted_html(result)
        self.assertIn(f'href="{vt}" target="_blank" rel="noopener noreferrer"', html)
        self.assertNotIn('href="https://evil.example', html)
        self.assertIn('https://evil.example/payload.exe', html)
        self.assertEqual('\n'.join(line.text for line in iter_lines(result)), content)

    def test_gutter_is_only_as_wide_as_the_longest_line_number(self):
        eset = highlight_log('ESET', ESET)
        self.assertEqual(eset.gutter_ch, len(str(len(ESET.split('\n')))))
        self.assertFalse(eset.has_status)
        frst = highlight_log('FRST', FRST)
        apply_analysis_statuses(frst, FRST, _frst_payload(FRST))
        self.assertTrue(frst.has_status)
        # Room for the status letter on top of the line number digits.
        self.assertEqual(frst.gutter_ch, len(str(len(FRST.split('\n')))) + 2)

    def test_summary_line_labels_are_only_as_wide_as_the_longest(self):
        result = highlight_log('ESET', ESET)
        # Detections on lines 7, 9 and 11: "L11" is 3 characters.
        self.assertEqual(result.summary_line_ch, 3)
        self.assertEqual(HighlightResult([], []).summary_line_ch, 2)

    def test_render_none_is_empty(self):
        self.assertEqual(render_highlighted_html(None), '')


class HighlightedDetailViewTests(UploadedLogSharedSetupMixin, TestCase):

    def _get(self, upload):
        self.client.login(username='alice', password='password123')
        return self.client.get(reverse('view_uploaded_log', args=[upload.upload_id]))

    def test_malwarebytes_upload_renders_highlighted_lines_and_summary(self):
        upload = UploadedLog.objects.create(
            upload_id='bright-scanner', forum_username='forum_user', original_filename='mbam.txt',
            content=MALWAREBYTES, log_type='Malwarebytes',
        )
        response = self._get(upload)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'class="hl-line"')
        self.assertContains(response, 'id="highlightSummary"')
        line_no = _no(MALWAREBYTES, 'Trojan.PavinLoader.E,')
        self.assertContains(response, f'href="#L{line_no}" class="hl-jump" data-line="{line_no}"')
        self.assertContains(response, 'css/log_highlight.css')

    def test_mau_upload_is_highlighted_when_detected(self):
        LogTypeDetectionRule.objects.create(
            name='MAU', log_type='MAU', pattern=r'MAU Log|Malicious App Uninstaller',
            scope=LogTypeDetectionRule.SCOPE_START,
        )
        upload = UploadedLog.objects.create(
            upload_id='quiet-remover', forum_username='forum_user', original_filename='MAU.txt',
            content=MAU_REPORT, log_type='MAU',
        )
        response = self._get(upload)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'hl-section-header')
        self.assertContains(response, 'PhysX Runtime')
        self.assertContains(response, 'Removal summary')

    def test_highlighted_view_offers_click_to_copy_paths(self):
        upload = UploadedLog.objects.create(
            upload_id='copy-scanner', forum_username='forum_user', original_filename='mbam.txt',
            content=MALWAREBYTES, log_type='Malwarebytes',
        )
        response = self._get(upload)
        self.assertContains(response, 'class="hl-copy-hint"')
        self.assertContains(response, "closest('.hl-path, .hl-reg, .hl-guid, .hl-hash')")
        self.assertContains(response, 'id="toggleSectionsButton"')

    def test_summary_and_metadata_are_tabs_of_one_panel(self):
        upload = UploadedLog.objects.create(
            upload_id='tabbed-scanner', forum_username='forum_user', original_filename='mbam.txt',
            content=MALWAREBYTES, log_type='Malwarebytes', detected_encoding='utf-16-le',
        )
        response = self._get(upload)
        self.assertContains(response, 'data-info-tab="summary" role="tab" aria-selected="true"')
        self.assertContains(response, 'data-info-tab="metadata" role="tab" aria-selected="false"')
        # The metadata is still on the page (hidden until its tab is chosen).
        self.assertContains(response, 'id="logMetadata" data-info-pane="metadata" role="tabpanel" '
                                       'aria-labelledby="infoTabMetadata" hidden')
        self.assertContains(response, 'utf-16-le')
        self.assertContains(response, 'id="highlightSummary" data-info-pane="summary"')

    def test_upload_without_summary_shows_metadata_without_tabs(self):
        upload = UploadedLog.objects.create(
            upload_id='untabbed-notes', forum_username='forum_user', original_filename='notes.txt',
            content='some text nobody recognises', log_type='Unknown',
        )
        response = self._get(upload)
        self.assertNotContains(response, 'role="tablist"')
        self.assertContains(response, 'id="logMetadata" data-info-pane="metadata">')

    def test_log_without_sections_has_no_collapse_all_button(self):
        upload = UploadedLog.objects.create(
            upload_id='flat-scanner', forum_username='forum_user', original_filename='eset.txt',
            content=ESET, log_type='ESET',
        )
        response = self._get(upload)
        self.assertContains(response, 'class="hl-line"')
        self.assertNotContains(response, 'id="toggleSectionsButton"')

    def test_securitycheck_upload_is_highlighted_without_summary(self):
        LogTypeDetectionRule.objects.create(
            name='SecurityCheck', log_type='SecurityCheck', pattern=r'^SecurityCheck by',
            scope=LogTypeDetectionRule.SCOPE_START,
        )
        upload = UploadedLog.objects.create(
            upload_id='checked-safety', forum_username='forum_user', original_filename='SecurityCheck.txt',
            content=SECURITYCHECK, log_type='SecurityCheck',
        )
        response = self._get(upload)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'class="hl-line"')
        self.assertContains(response, 'hl-bbtag')
        self.assertNotContains(response, 'id="highlightSummary"')

    def test_frst_upload_uses_cached_rule_statuses(self):
        from ..models import UploadedLogAnalysis
        from ..rule_sets import SHARED_RULE_SET_KEY
        upload = UploadedLog.objects.create(
            upload_id='ruled-forest', forum_username='forum_user', original_filename='FRST.txt',
            content=FRST, log_type='FRST', count_malware=1, count_pup=1, count_warning=1, count_clean=1,
        )
        UploadedLogAnalysis.objects.update_or_create(
            upload=upload, rule_set_key=SHARED_RULE_SET_KEY,
            defaults={'payload': _frst_payload(FRST), 'source_content_hash': upload.content_hash},
        )
        response = self._get(upload)
        self.assertEqual(response.status_code, 200)
        no = _no(FRST, 'evil.exe')
        self.assertContains(response, f'data-n="{no}" data-st="B"')
        self.assertContains(response, f'href="#L{no}" class="hl-jump" data-line="{no}"')
        self.assertContains(response, '<span class="hl-summary-title">shared rules</span>')
        self.assertContains(response, '<span class="hl-stat-label">B:</span> <span class="hl-sev-b">1</span>')
        self.assertContains(response, '<span class="hl-stat-label">G:</span> <span class="hl-sev-j">0</span>')

    def test_frst_upload_without_cached_analysis_keeps_syntax_colours(self):
        upload = UploadedLog.objects.create(
            upload_id='uncached-forest', forum_username='forum_user', original_filename='FRST.txt',
            content=FRST, log_type='FRST',
        )
        from ..models import UploadedLogAnalysis
        UploadedLogAnalysis.objects.filter(upload=upload).delete()
        response = self._get(upload)
        self.assertContains(response, 'class="hl-line"')
        self.assertNotContains(response, 'data-st=')
        self.assertContains(response, 'shared rules (analysis is being refreshed, reload in a moment)')
        # The refresh (synchronous under the test runner) caches a fresh analysis
        # without touching the upload's list counts.
        from ..rule_sets import SHARED_RULE_SET_KEY
        from ..upload_utils import get_fresh_cached_analysis
        upload.refresh_from_db()
        self.assertIsNotNone(get_fresh_cached_analysis(upload, SHARED_RULE_SET_KEY))
        response = self._get(upload)
        self.assertContains(response, '<span class="hl-summary-title">shared rules</span>')

    def test_unknown_upload_keeps_plain_chunked_view(self):
        upload = UploadedLog.objects.create(
            upload_id='plain-forest', forum_username='forum_user', original_filename='notes.txt',
            content='some text nobody recognises\nline two',
            log_type='Unknown',
        )
        response = self._get(upload)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'class="log-chunk"')
        self.assertNotContains(response, 'class="hl-line"')
        self.assertNotContains(response, 'id="highlightSummary"')
        self.assertNotContains(response, 'css/log_highlight.css')
        self.assertNotContains(response, 'class="hl-copy-hint"')
        # Maximize works for every log type, plain view included.
        self.assertContains(response, 'id="maximizeLogToggle"')
        self.assertNotContains(response, '>maximize</button>')
