"""Installed programs found by name (correlation_keys.app_key): a Fixlog's
installed-app investigation and MAU logs (tool_log_facts), their install
folders and what MAU deleted, in the correlations of FRST / Addition lines.
Nothing here may call centralbox."""

from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from .. import centralbox
from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..correlation_keys import app_key, installed_program, line_keys, versions_differ
from ..models import InfectionCase, InfectionCaseLog, UploadedLogAnalysis, UploadedLogFileHash
from ..tool_log_facts import fixlog_app_facts, mau_facts
from .factories import make_uploaded_log, make_user
from .test_log_highlighting import MAU_CONSOLE, MAU_REPORT

GUID = '11111111-2222-3333-4444-555555555555'
SHA_A = 'a1' * 32
SHA_B = 'b2' * 32

INSTALLED = f'Tool Kit (HKLM\\...\\{{{GUID.upper()}}}) (Version: 2.4 - Acme Inc.)'
INSTALLED_OTHER_VERSION = 'Other App (HKLM-x32\\...\\Other App) (Version: 1.0 - Other Corp)'
INSTALLED_NO_VERSION = 'Game (HKLM\\...\\Game) (Version:  - Studio)'
INSTALLED_PARENS = ('Anaconda3 2024.06-1 (Python 3.12.4 64-bit) (HKU\\S-1-5-21-1-2-3-1001\\...\\'
                    'Anaconda3 2024.06-1 (Python 3.12.4 64-bit)) (Version: 2024.06-1 - Anaconda, Inc.)')
SERVICE = 'R2 ToolSvc; C:\\Program Files\\Tool Kit\\svc.exe [1000 2026-01-01] (Acme Inc. -> Acme) [File not signed]'
BROAD = 'R2 BroadSvc; C:\\Program Files (x86)\\Broad\\broad.exe [1000 2026-01-01] (Broad -> Broad)'
TEMP_FOLDER = ('2026-11-18 15:25 - 2026-11-18 15:25 - 000000000 ____D '
               'C:\\Users\\Bob\\AppData\\Local\\Temp\\abcDEF123')
HELPER_RUN = ('HKU\\S-1-5-21-1-2-3-1001\\...\\Run: [helper] => C:\\Users\\Bob\\AppData\\Local\\Helper\\helper.exe '
              '[100 2026-01-01] () [File not signed]')
HELPER_FILE = ('2026-11-18 15:25 - 2026-11-18 15:25 - 000001234 _____ '
               'C:\\Users\\Bob\\AppData\\Local\\Helper\\data.bin')
FRST_LINES = [INSTALLED, INSTALLED_OTHER_VERSION, INSTALLED_NO_VERSION, SERVICE, BROAD, TEMP_FOLDER,
              HELPER_RUN, HELPER_FILE]
FRST = '\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)'] + FRST_LINES)

FIXLOG_APPS = '\n'.join([
    'Fix result of Farbar Recovery Scan Tool (x64) Version: 17-11-2026',
    '========= Powershell: =========',
    '',
    '',
    '<=== Tool Kit [2.4] (Acme Inc.) ===>',
    '  Path: C:\\Program Files\\Tool Kit\\ | Created: 01/01/2026 10:00:00 | Modified: 01/01/2026 10:00:00'
    ' | Files: 2 | Folders: 0',
    f'  [{SHA_A.upper()}] 01/01/2026 10:00:00 - 01/01/2026 10:00:00 -    1.00 MB - Signer: Acme Inc.'
    ' [INVALID: HashMismatch] - C:\\Program Files\\Tool Kit\\svc.exe',
    f'  [{SHA_B.upper()}] 01/01/2026 10:00:00 - 01/01/2026 10:00:00 -   10.00 KB - Signer: Unsigned'
    ' - C:\\Program Files\\Tool Kit\\helper.dll',
    '',
    '<=== Other App [9.9] (Other Corp) ===>',
    '  Path: N/A',
    '',
    '<=== Game [?] (?) ===>',
    '  Path: C:\\Games\\Game\\',
    '  [NOT FOUND]',
    '',
    '<=== Broad [1.0] (Broad) ===>',
    '  Path: C:\\Program Files (x86)\\ | Created: 01/01/2026 10:00:00 | Modified: 01/01/2026 10:00:00'
    ' | Files: 0 | Folders: 9',
    '========= End of Powershell: =========',
    '',
    '<=== Not In PowerShell [1.0] (Nobody) ===>',
])

MAU = '\n'.join([
    '======================== MAU Log ========================',
    '',
    f'Analyzing {{{GUID.upper()}}}...',
    '  DisplayName=Tool Kit',
    '  DisplayVersion=2.4',
    '  InstallLocation=C:\\Program Files\\Tool Kit\\',
    '  InstallSource=C:\\Users\\Bob\\AppData\\Local\\Temp\\abcDEF123\\',
    'RESOLVED: DisplayName=Tool Kit',
    'RESOLVED: Publisher=Acme Inc.',
    '',
    'Deleted items:',
    '  [File] c:\\users\\bob\\appdata\\local\\helper\\helper.exe',
    '  [Dir] c:\\users\\bob\\appdata\\local\\helper',
    '  [RegValue] HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\helper',
    f'  [RegValue] HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{{{GUID.upper()}}}\\UninstallString',
    '  [RegKey] HKLM\\SYSTEM\\CurrentControlSet\\Services\\ToolSvc',
    f'  [RegKey] HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{{{GUID.upper()}}}',
    'Failed to delete: C:\\Users\\Bob\\AppData\\Local\\Helper\\locked.dll',
    '',
    'Removal summary: Deleted=6 Scheduled=0 Failed=1',
])


# The analyzer's parsed entry of the lines that need one for their typed keys.
PARSED = {
    SERVICE: ('service', 'ToolSvc'),
    HELPER_RUN: ('runkey', 'helper'),
}


def cache_analysis(upload, lines, statuses=None):
    """A stored analysis of these lines (rule status '?' unless given)."""
    rows = []
    for text in lines:
        entry_type, name = PARSED.get(text, ('', ''))
        rows.append({'line': text, 'dominant_status': (statuses or {}).get(text, '?'),
                     'parsed_entry_type': entry_type, 'components': {'name': name} if name else {}})
    UploadedLogAnalysis.objects.create(
        upload=upload, rule_set_key='shared', source_content_hash=upload.content_hash,
        payload={'format': ANALYSIS_PAYLOAD_FORMAT, 'lines': rows, 'summary': {}, 'warnings': []},
    )


class InstalledProgramKeyTests(SimpleTestCase):
    def test_name_and_version_of_installed_programs_lines(self):
        self.assertEqual(installed_program(INSTALLED), ('Tool Kit', '2.4'))
        self.assertEqual(installed_program(INSTALLED_NO_VERSION), ('Game', ''))
        self.assertEqual(installed_program(INSTALLED_PARENS), ('Anaconda3 2024.06-1 (Python 3.12.4 64-bit)', '2024.06-1'))
        self.assertEqual(installed_program(INSTALLED + ' Hidden'), ('Tool Kit', '2.4'))
        self.assertIsNone(installed_program(SERVICE))

    def test_line_keys_add_the_app_key(self):
        keys = dict(line_keys({'line': INSTALLED_PARENS}))
        self.assertEqual(keys[app_key('Anaconda3 2024.06-1 (Python 3.12.4 64-bit)')], 'app')
        self.assertEqual(app_key('  Tool   Kit '), 'app:tool kit')
        self.assertEqual(app_key(''), '')

    def test_versions_differ_only_when_both_are_known(self):
        self.assertTrue(versions_differ('1.0', '9.9'))
        self.assertFalse(versions_differ('2.4', '2.4 '))
        self.assertFalse(versions_differ('', '9.9'))
        self.assertFalse(versions_differ('1.0', '?'))


class ParserTests(SimpleTestCase):
    def test_fixlog_app_facts(self):
        apps = {app.name: app for app in fixlog_app_facts(FIXLOG_APPS)}
        self.assertEqual(sorted(apps), ['Broad', 'Game', 'Other App', 'Tool Kit'])
        tool = apps['Tool Kit']
        self.assertEqual((tool.line_no, tool.version, tool.publisher, tool.path, tool.is_folder, tool.files),
                         (5, '2.4', 'Acme Inc.', 'C:\\Program Files\\Tool Kit\\', True, 2))
        self.assertEqual(tool.unsigned, 1)
        self.assertEqual(tool.invalid, [['C:\\Program Files\\Tool Kit\\svc.exe', 'Acme Inc. [HashMismatch]']])
        self.assertEqual(tool.signers, ['Acme Inc.'])
        self.assertEqual((apps['Other App'].state, apps['Other App'].path), ('N/A', ''))
        self.assertEqual((apps['Game'].state, apps['Game'].version, apps['Game'].publisher), ('NOT FOUND', '', ''))

    def test_mau_facts_report(self):
        products, items = mau_facts(MAU)
        self.assertEqual(len(products), 1)
        product = products[0]
        self.assertEqual((product.name, product.version, product.publisher, product.install_location,
                          product.install_source),
                         ('Tool Kit', '2.4', 'Acme Inc.', 'C:\\Program Files\\Tool Kit\\',
                          'C:\\Users\\Bob\\AppData\\Local\\Temp\\abcDEF123\\'))
        self.assertEqual([(item.kind, item.failed) for item in items], [
            ('File', False), ('Dir', False), ('RegValue', False), ('RegValue', False), ('RegKey', False),
            ('RegKey', False), ('File', True),
        ])

    def test_mau_facts_of_the_sample_logs(self):
        products, items = mau_facts(MAU_REPORT)
        self.assertEqual((products[0].name, products[0].install_source),
                         ('PhysX Runtime', 'C:\\Users\\User\\AppData\\Local\\Temp\\bib04rPIGTlJO0pi\\'))
        self.assertEqual(items[-1].target, 'C:\\Users\\User\\AppData\\Local\\NVIDIA\\locked.dll')
        products, items = mau_facts(MAU_CONSOLE)
        self.assertEqual((products[0].name, products[0].publisher), ('NetLink Helper', 'Broadcom Inc.'))
        self.assertEqual([(item.kind, item.target) for item in items],
                         [('File', 'c:\\users\\user\\appdata\\local\\netlink\\license')])


class InstalledAppCorrelationTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.case = InfectionCase.objects.create(owner=self.user, username='bob')
        self.frst = make_uploaded_log('frst-log', log_type='FRST&Addition', content=FRST, forum_username='nobody')
        cache_analysis(self.frst, FRST_LINES)
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=self.frst, added_by=self.user)

    def add_log(self, upload_id, log_type, content):
        upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(upload)
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=upload, added_by=self.user)
        return upload

    def get(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            response = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-log'})
        http.assert_not_called()
        request.assert_not_called()
        return response.json()['correlations']

    def roles(self, found, line):
        return sorted((item['upload_id'], item.get('role', item['kind']), item.get('match', ''),
                       bool(item.get('in_folder'))) for item in found.get(line, []))

    def test_fixlog_app_investigation(self):
        self.add_log('fix-apps', 'Fixlog', FIXLOG_APPS)
        found = self.get()
        app = next(item for item in found[INSTALLED] if item.get('role') == 'installed app')
        self.assertEqual((app['match'], app['line_no'], app['text'], app['severity']),
                         ('app', 5, 'Tool Kit [2.4] (Acme Inc.)', 'w'))
        extra = dict(app['extra'])
        self.assertEqual(extra['invalid signature'], 'svc.exe: Acme Inc. [HashMismatch]')
        self.assertEqual(extra['unsigned PE files'], '1')
        # Another version of a program of that name: not the same program.
        self.assertNotIn(INSTALLED_OTHER_VERSION, found)
        # No version on one side: the name decides; a missing folder still links.
        game = found[INSTALLED_NO_VERSION][0]
        self.assertEqual((game['text'], game['file_status']), ('Game', 'NOT FOUND'))
        # The install folder speaks for the files inside it; the hash row of the file too.
        self.assertIn(('fix-apps', 'installed app', '', True), self.roles(found, SERVICE))
        self.assertIn(('fix-apps', 'hash', '', False), self.roles(found, SERVICE))
        # A broad folder (Program Files) never does.
        self.assertNotIn(BROAD, found)
        # The invalid signature colours the line orange.
        statuses = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-log'}).json()['statuses']
        self.assertEqual(statuses[INSTALLED], '!')

    def test_mau(self):
        self.add_log('mau-log', 'MAU', MAU)
        found = self.get()
        product = [item for item in found[INSTALLED] if item.get('role') == 'removed by MAU']
        # Found through the product code, the Uninstall key and the name: listed once.
        self.assertEqual(len(product), 1)
        self.assertEqual(product[0]['text'], 'Tool Kit (Acme Inc.)')
        self.assertIn(('mau-log', 'removed by MAU', '', True), self.roles(found, SERVICE))
        self.assertIn(('mau-log', 'MAU install source', '', False), self.roles(found, TEMP_FOLDER))
        helper = self.roles(found, HELPER_RUN)
        self.assertIn(('mau-log', 'deleted by MAU', '', False), helper)        # [File]
        self.assertIn(('mau-log', 'deleted by MAU', 'registry', False), helper)  # [RegValue] Run\helper
        self.assertIn(('mau-log', 'deleted by MAU', '', True), self.roles(found, HELPER_FILE))  # [Dir]
        self.assertIn(('mau-log', 'deleted by MAU', 'service', False), self.roles(found, SERVICE))
        # The Uninstall key's values add nothing to the product's own entries.
        texts = [item['text'] for item in found[INSTALLED]]
        self.assertFalse(any('UninstallString' in text for text in texts))

    def test_mau_name_with_another_version_is_not_linked(self):
        self.add_log('mau-other', 'MAU', MAU.replace(f'{{{GUID.upper()}}}', '{99999999-2222-3333-4444-555555555555}')
                     .replace('DisplayVersion=2.4', 'DisplayVersion=7.0'))
        found = self.get()
        self.assertFalse([item for item in found.get(INSTALLED, []) if item.get('role') == 'removed by MAU'])
