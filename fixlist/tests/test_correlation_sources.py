"""More facts per file for the correlation info box: Spor's newer format
(!log-syntax-in-name, SOFTWARE, "not hashed"), Spor FILES details and
module-section mentions, FRST Search File: entries and hits, Shortcut logs,
and how they reach an FRST line (case_correlations). Nothing here may call
centralbox."""

from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from .. import case_correlations, centralbox, spor_log
from ..file_hashes import extract_file_hashes
from ..log_highlighting import highlight_log, iter_lines
from ..models import InfectionCase, InfectionCaseLog, UploadedLogFileHash
from ..tool_log_facts import frst_search_facts, shortcut_mentions
from .factories import make_uploaded_log, make_user
from .spor_sample import (
    DLL_SHA, DOTNET_GUID, DOTNET_HOST_GUID, DRIVER, DROPPER, EVIL, EVIL_DLL, EVIL_SHA, FRST_SEARCH, LINES_V2,
    LINES_V3, LOADER, OTHER_DLL, REPORT_LNK, SEARCH_MD5, SHA1, SHORTCUT, SPOR, SPOR_V2, SPOR_V3, SVC_DLL,
    SVC_DLL_MD5, SVC_DLL_SHA, SYNTAX_PATH, TEAMVIEWER, X_SHA,
)
from .test_case_correlations import RUN_LINE, cache_analysis


def no(needle, lines=LINES_V2):
    for index, line in enumerate(lines):
        if needle in line:
            return index + 1
    raise AssertionError(f'{needle!r} not in fixture')


class SporNewerFormatTests(SimpleTestCase):
    def test_files_details_and_not_hashed(self):
        files = {parsed.path: parsed for parsed in spor_log.iter_file_lines(LINES_V2)}
        evil = files[EVIL]
        self.assertEqual(evil.hash, EVIL_SHA.upper())
        self.assertEqual(evil.details['original name'], 'svchost.exe')
        self.assertEqual(evil.details['company'], 'Microsoft Corporation')
        self.assertEqual(evil.details['file version'], '1.0')
        self.assertEqual(evil.details['amcache sha1'], SHA1.upper())
        # "not hashed": no hash, the signature is still read.
        self.assertEqual((files[TEAMVIEWER].hash, files[TEAMVIEWER].signature), ('', 'unsigned'))
        self.assertIn((no(f'{TEAMVIEWER} => not'), TEAMVIEWER, '', 'unsigned'), list(spor_log.iter_files(LINES_V2)))

    def test_a_path_with_log_syntax_stays_whole_in_files(self):
        files = {parsed.path: parsed for parsed in spor_log.iter_file_lines(LINES_V2)}
        self.assertEqual((files[SYNTAX_PATH].hash, files[SYNTAX_PATH].signature), (X_SHA.upper(), 'invalid'))

    def test_amcache_files(self):
        self.assertEqual(list(spor_log.iter_amcache_files(LINES_V2)),
                         [(no('old.exe =>'), 'C:\\Users\\Bob\\Desktop\\old.exe', SHA1.upper())])

    def test_syntax_flagged_lines_are_resolved_through_files_or_skipped(self):
        found = {item.path: item for item in spor_log.iter_timeline_evidence(LINES_V2)}
        self.assertIn(SYNTAX_PATH, found)
        self.assertEqual((found[SYNTAX_PATH].file_status, found[SYNTAX_PATH].details),
                         ('unsigned', 'from https://example.com/'))
        # "b => fake.exe" is not in FILES: no path of that line is trusted.
        self.assertFalse([path for path in found if path.startswith('C:\\Users\\Bob\\Desktop\\b')])

    def test_mentions_of_the_module_sections(self):
        mentions = spor_log.iter_mentions(LINES_V2)
        by_path = {}
        for mention in mentions:
            by_path.setdefault(mention.path, []).append(mention)
        (loaded,) = by_path[EVIL_DLL]
        self.assertEqual((loaded.section, loaded.role, loaded.parent, loaded.status),
                         ('PREFETCH', 'loaded', 'C:\\Windows\\System32\\rundll32.exe', 'unsigned'))
        (run,) = by_path[EVIL]
        self.assertEqual((run.section, run.subsection, run.role, run.status),
                         ('PERSISTENCE', 'Run keys (all entries)', 'target', 'unsigned'))
        (installed,) = by_path[TEAMVIEWER]
        self.assertEqual((installed.section, installed.role, installed.tags, installed.time),
                         ('SOFTWARE', 'target', 'machine', '2026-11-17 10:00:00'))
        # A Steam game points at steam.exe, outside its own folder: left out.
        self.assertNotIn('C:\\Program Files (x86)\\Steam\\steam.exe', by_path)
        (download,) = by_path['C:\\Users\\Bob\\Downloads\\tool.zip']
        self.assertEqual(download.extra, [['from', 'https://files.example/tool.zip'],
                                          ['page', 'https://www.virustotal.com/gui/file/abc']])
        (exclusion,) = by_path['C:\\Users\\Bob\\AppData\\Roaming\\evil']
        self.assertTrue(exclusion.folder)
        # Sections read elsewhere are no mentions (FILES, TIMELINE, SUMMARY).
        self.assertFalse([mention for mention in mentions if mention.section in ('FILES', 'TIMELINE', 'SUMMARY')])

    def test_highlighter_software_tags_and_syntax_lines(self):
        result = highlight_log('Spor', SPOR_V2)
        lines = {line.no: line for line in iter_lines(result)}
        self.assertIn(('hl-sev-w', '[11708]'), lines[no('[11708]')].tokens)
        self.assertIn(('hl-dim', '[1034]'), lines[no('[1034]')].tokens)
        syntax = lines[no(f'[NEW] {SYNTAX_PATH}')]
        # The fake "[gone]" in the name is not dimmed like a real status.
        self.assertNotIn(('hl-dim', '[gone]'), syntax.tokens)
        self.assertIn(('hl-sev-w', '<==== !log-syntax-in-name'), syntax.tokens)
        self.assertEqual(result.summary[0].severity, 'w')

    def test_hash_rows_keep_the_syntax_path_whole_and_check_it(self):
        rows = {row.path: row for row in extract_file_hashes('Spor', SPOR_V2) if row.source == 'spor'}
        self.assertEqual(set(rows), {EVIL, SYNTAX_PATH, EVIL_DLL})
        # Flagged in the SUMMARY (as the whole path FILES lists): checked by itself.
        self.assertTrue(rows[SYNTAX_PATH].auto)
        self.assertEqual(rows[SYNTAX_PATH].sha256, X_SHA)
        self.assertEqual(rows[EVIL_DLL].sha256, DLL_SHA)


class FrstSearchAndShortcutTests(SimpleTestCase):
    def test_frst_search_file_entries_folders_and_registry(self):
        files, mentions = frst_search_facts(FRST_SEARCH)
        (facts,) = files
        self.assertEqual((facts.path, facts.md5, facts.line_no, facts.hash_line_no),
                         (EVIL, SEARCH_MD5, no(EVIL, FRST_SEARCH.split('\n')), no(EVIL, FRST_SEARCH.split('\n')) + 1))
        self.assertEqual(facts.facts, {'created': '2026-10-21 17:21', 'modified': '2026-10-22 08:00', 'size': '123456',
                                       'attributes': '____A', 'signed': 'not signed'})
        folder, registry = mentions
        self.assertEqual((folder.path, folder.role), ('C:\\Users\\Bob\\AppData\\Roaming\\evil', 'listed'))
        self.assertEqual((registry.path, registry.role), (EVIL, 'registry'))
        self.assertTrue(registry.parent.endswith('\\CurrentVersion\\Run'))

    def test_frst_search_md5_rows(self):
        (row,) = extract_file_hashes('FRST Search', FRST_SEARCH)
        lines = FRST_SEARCH.split('\n')
        self.assertEqual((row.md5, row.sha256, row.path, row.source, row.auto), (SEARCH_MD5, '', EVIL, 'frst_search', False))
        self.assertEqual((row.line_no, row.anchor_line_no), (no(EVIL, lines) + 1, no(EVIL, lines)))

    def test_shortcut_targets_and_files(self):
        mentions = shortcut_mentions(SHORTCUT)
        target = next(mention for mention in mentions if mention.path == EVIL)
        self.assertEqual((target.role, target.status), ('shortcut target', 'gone'))
        self.assertEqual(target.extra, [['shortcut', 'C:\\Users\\Bob\\Desktop\\Evil.lnk'], ['company', 'No File']])
        lnk = next(mention for mention in mentions if mention.path == 'C:\\Users\\Bob\\Desktop\\Evil.lnk')
        self.assertEqual(lnk.role, 'shortcut')

    def test_original_name_differs(self):
        differs = case_correlations.original_name_differs
        self.assertTrue(differs(EVIL, 'svchost.exe'))
        self.assertFalse(differs(EVIL, 'EVIL.EXE'))
        self.assertFalse(differs(EVIL, 'evil.exe.mui'))
        self.assertFalse(differs('C:\\x\\setup.exe', 'setup'))


DLL_LINE = f'2026-11-18 07:48 - 2026-11-18 07:48 - 000012345 _____ () {EVIL_DLL}'


class InfoBoxCorrelationTests(TestCase):
    def setUp(self):
        user = make_user()
        self.client.force_login(user)
        case = InfectionCase.objects.create(owner=user, username='bob', auto_assign_new_items=False)
        frst = make_uploaded_log('frst-info', log_type='FRST', forum_username='nobody',
                                 content='\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)', RUN_LINE, DLL_LINE]))
        cache_analysis(frst, [RUN_LINE, DLL_LINE])
        uploads = [frst]
        for upload_id, log_type, content in (('spor-v2', 'Spor', SPOR_V2), ('search-log', 'FRST Search', FRST_SEARCH),
                                             ('shortcut-log', 'Shortcut', SHORTCUT)):
            upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username='nobody')
            UploadedLogFileHash.rebuild_for(upload)
            uploads.append(upload)
        for upload in uploads:
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)

    def get(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-info'}).json()
        http.assert_not_called()
        request.assert_not_called()
        return body

    def test_every_source_reaches_the_line(self):
        body = self.get()
        entries = body['correlations'][RUN_LINE]
        kinds = {(entry['kind'], entry['upload_id']) for entry in entries}
        self.assertTrue({('hash', 'spor-v2'), ('file_info', 'spor-v2'), ('mention', 'spor-v2'),
                         ('hash', 'search-log'), ('file_info', 'search-log'), ('mention', 'search-log'),
                         ('mention', 'shortcut-log')} <= kinds)
        spor_file = next(entry for entry in entries if entry['kind'] == 'file_info' and entry['upload_id'] == 'spor-v2')
        self.assertEqual((spor_file['original_name'], spor_file['company'], spor_file['signature'], spor_file['sha1']),
                         ('svchost.exe', 'Microsoft Corporation', 'unsigned', SHA1))
        self.assertTrue(spor_file['original_name_differs'])
        search_file = next(entry for entry in entries if entry['kind'] == 'file_info'
                           and entry['upload_id'] == 'search-log')
        self.assertEqual((search_file['md5'], search_file['signed'], search_file['size']), (SEARCH_MD5, 'not signed', '123456'))
        # The Defender path exclusion of the folder the file is in.
        exclusion = next(entry for entry in entries if entry.get('folder'))
        self.assertTrue(exclusion['in_folder'])
        self.assertEqual(exclusion['section'], 'DEFENDER')
        roles = {entry['role'] for entry in entries if entry['kind'] == 'mention'}
        self.assertTrue({'target', 'registry', 'shortcut target', 'item'} <= roles)
        # Facts and mentions without flags give the line no status.
        self.assertEqual(body['statuses'][RUN_LINE], '')

    def test_a_loaded_dll_names_the_program_that_loaded_it(self):
        body = self.get()
        loaded = next(entry for entry in body['correlations'][DLL_LINE] if entry['kind'] == 'mention'
                      and entry['role'] == 'loaded')
        self.assertEqual((loaded['parent'], loaded['file_status'], loaded['section']),
                         ('C:\\Windows\\System32\\rundll32.exe', 'unsigned', 'PREFETCH'))


class EntryCapTests(TestCase):
    def test_status_giving_entries_are_kept_when_a_line_has_too_many(self):
        user = make_user()
        self.client.force_login(user)
        case = InfectionCase.objects.create(owner=user, username='bob', auto_assign_new_items=False)
        line = f'2026-11-14 07:20 - 2026-11-14 07:20 - 012345678 _____ (Evil Ltd) {DROPPER}'
        frst = make_uploaded_log('frst-cap', log_type='FRST', forum_username='nobody',
                                 content='\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)', line]))
        cache_analysis(frst, [line])
        spor = make_uploaded_log('spor-cap', log_type='Spor', content=SPOR, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(spor)
        for upload in (frst, spor):
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)
        with mock.patch.object(case_correlations, 'MAX_ENTRIES_PER_LINE', 1):
            body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-cap'}).json()
        (entry,) = body['correlations'][line]
        self.assertEqual((entry['kind'], entry['detection']), ('detection', 'Trojan:Win32/Malgent!MSR'))
        self.assertEqual(body['statuses'][line], 'B')


class SoftwareFactTests(SimpleTestCase):
    def test_spor_software_sections(self):
        from .spor_sample import DOTNET_GUID, EVIL_PACKAGE, EVIL_PACKAGE_FOLDER, EVIL_TOOL, TAILSCALE_GUID

        facts = spor_log.iter_software(LINES_V2)
        by_name = {}
        for fact in facts:
            by_name.setdefault(fact.name, []).append(fact)
        (teamviewer,) = by_name['TeamViewer']
        self.assertEqual((teamviewer.kind, teamviewer.status, teamviewer.tags), ('uninstall', 'unsigned', 'machine'))
        self.assertEqual(teamviewer.details['key'], 'HKLM\\...\\TeamViewer')
        self.assertEqual(teamviewer.details['program'], TEAMVIEWER)
        self.assertEqual(teamviewer.details['version'], '15.83.7')
        (tool,) = by_name['Evil Tool']
        self.assertEqual((tool.details['program'], tool.details['hidden']), (EVIL_TOOL, 'yes'))
        (nextcloud,) = by_name['Nextcloud']
        self.assertEqual(nextcloud.details['program'], 'Windows Installer (msiexec)')
        # A collapsed group: one fact per "key:" sub-line, named by the group.
        group = by_name['2 entries from Microsoft Corporation']
        self.assertEqual(len(group), 2)
        self.assertEqual(group[0].details['key'], 'HKLM\\...\\{' + DOTNET_GUID + '}')
        (tailscale,) = by_name['Tailscale']
        self.assertEqual((tailscale.kind, tailscale.details['event'], tailscale.details['user']),
                         ('installer', 'installed', 'SYSTEM'))
        self.assertEqual(tailscale.details['product code'], '{' + TAILSCALE_GUID + '}')
        self.assertEqual(by_name['Evil Thing'][0].details['event'], 'install failed')
        (package,) = by_name['Evil App']
        self.assertEqual((package.kind, package.flags, package.details['folder']),
                         ('package', ['!from-web'], EVIL_PACKAGE_FOLDER))
        self.assertIn(EVIL_PACKAGE, package.text)
        # TIMELINE's [INS] lines repeat SOFTWARE: no facts of their own.
        self.assertFalse([fact for fact in facts if fact.line_no == no('[INS]')])

    def test_broad_folders_do_not_speak_for_their_files(self):
        broad = case_correlations.is_broad_folder
        for key in ('c:\\', 'c:\\windows', 'c:\\program files', 'c:\\program files (x86)\\common files',
                    'c:\\program files\\windowsapps', 'c:\\programdata', 'c:\\users\\username',
                    'c:\\users\\username\\appdata\\roaming', 'c:\\users\\username\\appdata\\local\\programs',
                    'c:\\users\\username\\downloads\\'):
            with self.subTest(key=key):
                self.assertTrue(broad(key))
        for key in ('c:\\program files\\teamviewer', 'c:\\users\\username\\appdata\\local\\discord',
                    'c:\\program files\\windowsapps\\claude_5.1.0.0_x64__abc'):
            with self.subTest(key=key):
                self.assertFalse(broad(key))


MAU_TAILSCALE = '\n'.join([
    '======================== MAU Log ========================',
    '',
    'Analyzing {795F9101-3A31-5313-82FC-13CFC9E0FE17}...',
    '----------------------------------------------------------------------------------------------',
    '                                       UNINSTALL / ARP',
    '----------------------------------------------------------------------------------------------',
    '',
    '  DisplayName=Tailscale',
    '  Publisher=Tailscale Inc.',
    'RESOLVED: DisplayName=Tailscale',
    'RESOLVED: Publisher=Tailscale Inc.',
])
MB_UNINSTALL = '\n'.join([
    'Malwarebytes',
    'www.malwarebytes.com',
    '',
    '-Log Details-',
    '',
    'PUP.Optional.TeamViewer, HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\UNINSTALL\\TeamViewer,'
    ' Quarantined, 58, 1129493, 1.0.116571, , ame, , , ',
])


class SoftwareCorrelationTests(TestCase):
    def setUp(self):
        from .spor_sample import EVIL_PACKAGE_FOLDER, TAILSCALE_GUID

        self.installed = 'TeamViewer (HKLM\\...\\TeamViewer) (Version: 15.83.7 - TeamViewer)'
        self.msi = 'Tailscale (HKLM\\...\\{' + TAILSCALE_GUID + '}) (Version: 1.104.7 - Tailscale Inc.)'
        self.package = 'Evil App -> ' + EVIL_PACKAGE_FOLDER + ' [2026-11-14] (Evil Ltd)'
        self.service = ('R2 TeamViewer; C:\\Program Files\\TeamViewer\\TeamViewer_Service.exe [123 2026-11-17]'
                        ' (TeamViewer Germany GmbH -> TeamViewer)')
        self.inside_package = 'R2 EvilSvc; ' + EVIL_PACKAGE_FOLDER + '\\svc.exe [1 2026-11-14] (Evil Ltd -> )'
        lines = [self.installed, self.msi, self.package, self.service, self.inside_package]
        user = make_user()
        self.client.force_login(user)
        case = InfectionCase.objects.create(owner=user, username='bob', auto_assign_new_items=False)
        frst = make_uploaded_log('frst-sw', log_type='FRST&Addition', forum_username='nobody',
                                 content='\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)'] + lines))
        cache_analysis(frst, lines)
        uploads = [frst]
        for upload_id, log_type, content in (('spor-sw', 'Spor', SPOR_V2), ('mau-sw', 'MAU', MAU_TAILSCALE),
                                             ('mb-sw', 'Malwarebytes', MB_UNINSTALL)):
            upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username='nobody')
            UploadedLogFileHash.rebuild_for(upload)
            uploads.append(upload)
        for upload in uploads:
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)

    def get(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-sw'}).json()
        http.assert_not_called()
        request.assert_not_called()
        return body['correlations']

    def test_installed_programs_line_gets_spor_and_the_scanner(self):
        entries = self.get()[self.installed]
        spor = next(entry for entry in entries if entry['upload_id'] == 'spor-sw')
        self.assertEqual((spor['role'], spor['match'], spor['file'], spor['section']),
                         ('uninstall entry', 'uninstall', 'TeamViewer', 'SOFTWARE'))
        detection = next(entry for entry in entries if entry['upload_id'] == 'mb-sw')
        self.assertEqual((detection['kind'], detection['detection'], detection['match']),
                         ('detection', 'PUP.Optional.TeamViewer', 'uninstall'))

    def test_msi_product_gets_the_installer_event_and_mau(self):
        entries = self.get()[self.msi]
        found = {(entry['upload_id'], entry['role']) for entry in entries}
        self.assertEqual(found, {('spor-sw', 'installer event'), ('mau-sw', 'removed by MAU')})
        mau = next(entry for entry in entries if entry['upload_id'] == 'mau-sw')
        self.assertEqual((mau['text'], mau['match']), ('Tailscale (Tailscale Inc.)', 'msi'))

    def test_packages_line_and_files_inside_the_package_and_install_folders(self):
        found = self.get()
        (package,) = [entry for entry in found[self.package] if entry['role'] == 'package']
        self.assertEqual((package['severity'], package['flags']), ('w', ['!from-web']))
        self.assertNotIn('in_folder', package)
        inside = next(entry for entry in found[self.inside_package] if entry['role'] == 'package')
        self.assertTrue(inside['in_folder'])
        install = next(entry for entry in found[self.service] if entry['role'] == 'uninstall entry')
        self.assertEqual((install['file'], install['in_folder']), ('TeamViewer', True))


def no3(needle):
    return no(needle, LINES_V3)


class SporLinkDetailTests(SimpleTestCase):
    """Spor's details for linking with FRST logs (README "Details for linking
    with FRST logs")."""

    def test_files_md5_size_and_times(self):
        files = {parsed.path: parsed for parsed in spor_log.iter_file_lines(LINES_V3)}
        self.assertEqual(files[EVIL].details['md5'], SEARCH_MD5.upper())
        self.assertEqual((files[EVIL].details['size'], files[EVIL].details['created'], files[EVIL].details['modified']),
                         ('123456', '2026-10-21 17:21:05', '2026-10-22 08:00:10'))
        self.assertEqual(files[EVIL].signature, 'unsigned')

    def test_persistence_identity_by_the_kind_tag(self):
        identities = set()
        for body in LINES_V3:
            if body[:1].isspace():
                continue
            identity = spor_log.persistence_identity(spor_log.split_item(body))
            if identity:
                identities.add(identity)
        self.assertEqual(identities, {
            # The value name holds a backslash: taken from "value", not cut from the key.
            ('run', 'Evil\\Name'), ('run', 'Upd'), ('svc', 'EvilSvc'), ('svc', 'evildrv'), ('svc', 'OtherSvc'),
            ('task', '\\Evil\\Updater'), ('task', '\\Evil\\Gone'),
        })
        # Startup items and lines without a kind tag have no identity.
        self.assertIsNone(spor_log.persistence_identity(spor_log.split_item(
            '2026-09-05 04:53:50 [startup] C:\\x\\Ok.lnk')))
        self.assertIsNone(spor_log.persistence_identity(spor_log.split_item(
            '2026-11-18 04:50:37 HKU\\Bob\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil => C:\\x.exe')))

    def test_mentions_of_services_tasks_and_service_dlls(self):
        mentions = [mention for mention in spor_log.iter_mentions(LINES_V3) if mention.section == 'PERSISTENCE']
        by_line = {}
        for mention in mentions:
            by_line.setdefault(mention.line_no, []).append(mention)
        # A registry line's target is the DLL itself, without " (svchost DLL)";
        # its dll: sub-line repeats it and is no second mention.
        (service,) = by_line[no3('[service] EvilSvc')]
        self.assertEqual((service.path, service.role, service.status, service.identity),
                         (SVC_DLL, 'target', 'unsigned', ('svc', 'EvilSvc')))
        self.assertNotIn(no3(f'    dll: {SVC_DLL}'), by_line)
        # A 7045 line: svchost.exe, and the DLL from its sub-line.
        (dll,) = by_line[no3(f'    dll: {OTHER_DLL}')]
        self.assertEqual((dll.path, dll.role, dll.parent, dll.status), (OTHER_DLL, 'dll', 'OtherSvc', 'unsigned'))
        # A Task Scheduler event names no file: an entry by its name only.
        (gone,) = by_line[no3('\\Evil\\Gone')]
        self.assertEqual((gone.path, gone.role, gone.identity), ('', 'entry', ('task', '\\Evil\\Gone')))

    def test_grouped_uninstall_keys_carry_their_own_name(self):
        group = [fact for fact in spor_log.iter_software(LINES_V3) if fact.text.startswith('key:')]
        self.assertEqual([(fact.name, fact.details['key'], fact.details['version']) for fact in group], [
            ('Microsoft .NET Runtime - 10.0.13 (x64)', f'HKLM\\...\\{{{DOTNET_GUID}}}', '80.52.61384'),
            ('Microsoft .NET Host - 10.0.13 (x64)', f'HKLM\\...\\{{{DOTNET_HOST_GUID}}}', '80.52.61384'),
        ])

    def test_hash_rows_carry_the_md5_and_the_loader_is_not_flagged(self):
        rows = {row.path: row for row in extract_file_hashes('Spor', SPOR_V3) if row.source == 'spor'}
        self.assertEqual((rows[EVIL].sha256, rows[EVIL].md5), (EVIL_SHA, SEARCH_MD5))
        self.assertEqual((rows[SVC_DLL].sha256, rows[SVC_DLL].md5), (SVC_DLL_SHA, SVC_DLL_MD5))
        # The SUMMARY flags the .lnk; the program that loaded it is not flagged.
        self.assertTrue(rows[REPORT_LNK].auto)
        self.assertFalse(rows[LOADER].auto)

    def test_summary_flags_written_inline(self):
        result = highlight_log('Spor', SPOR_V3)
        (item,) = [item for item in result.summary if REPORT_LNK in item.name]
        self.assertEqual((item.name, item.severity), (REPORT_LNK, 'w'))
        self.assertIn('!double-extension', item.action)
        tokens = {line.no: line.tokens for line in iter_lines(result)}[no3('!double-extension')]
        self.assertIn(('hl-path', REPORT_LNK), tokens)
        self.assertIn(('hl-sev-w', '!double-extension'), tokens)
        self.assertIn(('hl-path', LOADER), tokens)


def cache_parsed(upload, lines):
    """An analysis of `lines` with their parsed FRST entries, like the
    analyzer stores it (typed keys need the entry type and name)."""
    from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
    from ..frst_extractors import get_frst_entry
    from ..models import UploadedLogAnalysis

    payload_lines = []
    for text in lines:
        entry = get_frst_entry(text)
        payload_lines.append({
            'line': text, 'dominant_status': '?',
            'parsed_entry_type': entry.entry_type if entry else '',
            'components': {'name': entry.name, 'filepath': entry.filepath, 'arguments': entry.arguments} if entry else {},
        })
    payload = {'format': ANALYSIS_PAYLOAD_FORMAT, 'lines': payload_lines, 'summary': {}, 'warnings': []}
    UploadedLogAnalysis.objects.create(upload=upload, rule_set_key='shared', payload=payload,
                                       source_content_hash=upload.content_hash)


class SporLinkCorrelationTests(TestCase):
    """FRST lines find Spor's entries by name when their file differs or is
    gone, service DLLs, grouped installed programs by their own name, and
    FRST Search MD5s through Spor's MD5 / SHA256 pairs."""

    def setUp(self):
        signed = ' [File not signed]'
        self.run = ('HKU\\S-1-5-21-1-2-3-1001\\...\\Run: [Evil\\Name] => C:\\Users\\Bob\\AppData\\Local\\New\\new.exe'
                    ' [1 2026-11-18] ()' + signed)
        self.service = f'S2 EvilSvc; {SVC_DLL} [4096 2026-11-01] ()' + signed
        self.dll_service = f'S3 OtherSvc; {OTHER_DLL} [1 2026-11-01] ()' + signed
        self.driver = 'R1 evildrv; C:\\Windows\\System32\\drivers\\evildrv.sys [1 2026-11-01] ()' + signed
        self.task = ('Task: {12345678-1234-1234-1234-123456789012} - System32\\Tasks\\Evil\\Updater =>'
                     ' C:\\Users\\Bob\\other.exe [1 2026-11-02] ()' + signed)
        self.gone_task = ('Task: {12345678-1234-1234-1234-123456789013} - System32\\Tasks\\Evil\\Gone =>'
                          ' C:\\Users\\Bob\\gone.exe [1 2026-11-04] ()' + signed)
        self.installed = (f'Microsoft .NET Host - 10.0.13 (x64) (HKLM\\...\\{{{DOTNET_HOST_GUID}}})'
                          ' (Version: 80.52.61384 - Microsoft Corporation) Hidden')
        self.evil = f'R2 EvilFile; {EVIL} [123456 2026-10-21] ()' + signed
        lines = [self.run, self.service, self.dll_service, self.driver, self.task, self.gone_task, self.installed,
                 self.evil]
        user = make_user()
        self.client.force_login(user)
        case = InfectionCase.objects.create(owner=user, username='bob', auto_assign_new_items=False)
        frst = make_uploaded_log('frst-link', log_type='FRST&Addition', forum_username='nobody',
                                 content='\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)'] + lines))
        cache_parsed(frst, lines)
        uploads = [frst]
        for upload_id, log_type, content in (('spor-link', 'Spor', SPOR_V3), ('search-link', 'FRST Search', FRST_SEARCH)):
            upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username='nobody')
            UploadedLogFileHash.rebuild_for(upload)
            uploads.append(upload)
        for upload in uploads:
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)

    def get(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-link'}).json()
        http.assert_not_called()
        request.assert_not_called()
        return body['correlations']

    def spor(self, entries):
        return [entry for entry in entries if entry['upload_id'] == 'spor-link' and entry['kind'] == 'mention']

    def test_persistence_lines_by_name_when_the_file_differs(self):
        found = self.get()
        (run,) = self.spor(found[self.run])
        self.assertEqual((run['match'], run['file'], run['section']), ('registry', 'evil.exe', 'PERSISTENCE'))
        (driver,) = self.spor(found[self.driver])
        self.assertEqual((driver['match'], driver['file']), ('service', 'evil.sys'))
        (task,) = self.spor(found[self.task])
        self.assertEqual((task['match'], task['file']), ('task', 'evil.exe'))
        # The deleted task: no file of its own, named by the task.
        (gone,) = self.spor(found[self.gone_task])
        self.assertEqual((gone['match'], gone['role'], gone['file']), ('task', 'entry', '\\Evil\\Gone'))

    def test_svchost_services_by_their_dll(self):
        found = self.get()
        # The same Spor line by path and by name: listed once, by its path.
        (service,) = self.spor(found[self.service])
        self.assertEqual((service['role'], service['file']), ('target', 'evilsvc.dll'))
        self.assertNotIn('match', service)
        by_role = {entry['role']: entry for entry in self.spor(found[self.dll_service])}
        self.assertEqual((by_role['dll']['file'], by_role['dll']['parent']), ('other.dll', 'OtherSvc'))
        self.assertEqual((by_role['target']['match'], by_role['target']['file']), ('service', 'svchost.exe'))

    def test_grouped_installed_program_under_its_own_name(self):
        (entry,) = self.spor(self.get()[self.installed])
        self.assertEqual((entry['role'], entry['file'], entry['match']),
                         ('uninstall entry', 'Microsoft .NET Host - 10.0.13 (x64)', 'uninstall'))

    def test_frst_search_md5_finds_spors_sha256(self):
        entries = self.get()[self.evil]
        (search,) = [entry for entry in entries if entry['upload_id'] == 'search-link' and entry['kind'] == 'hash']
        self.assertEqual((search['md5'], search['sha256']), (SEARCH_MD5, EVIL_SHA))
        (info,) = [entry for entry in entries if entry['upload_id'] == 'spor-link' and entry['kind'] == 'file_info']
        self.assertEqual((info['md5'], info['size'], info['modified']), (SEARCH_MD5, '123456', '2026-10-22 08:00:10'))
