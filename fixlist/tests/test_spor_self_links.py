"""Links between the lines of one Spor log (correlations/spor_self.py): the same file
in other sections, SUMMARY and detail lines, entries of the same name, files
named in details, folders, copies; their status; the log page and endpoint."""

from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..correlations import spor_self
from ..models import HashVerdict, LogTypeDetectionRule
from ..correlations.spor_self import compute, self_links, self_status
from ..views.centralbox import add_self_link_context
from . import spor_sample as s
from .factories import make_uploaded_log, make_user


def no_of(lines, prefix, start=0):
    """The line number of the first line (from `start`) that starts with `prefix`."""
    return next(no for no, text in enumerate(lines, start=1) if no > start and text.strip().startswith(prefix))


def linked(links, no):
    """{other line no: match} of a line's links."""
    return {entry['line_no']: entry.get('match') for entry in links.get(str(no), ())}


UPD = 'C:\\Users\\Bob\\AppData\\Roaming\\Upd\\upd.exe'
COPY = 'C:\\ProgramData\\Upd\\copy.exe'
SVC = 'C:\\ProgramData\\Upd\\svc.exe'
GUID = '0F0F0F0F-1111-2222-3333-444444444444'
UPD_SHA = 'ab' * 32
UNITY_SHA = 'cd' * 32

# Entries of the same name, copies and host programs.
SPOR_LINKS = '\n'.join([
    '==================== Spor 0.4.0 - forensic triage log ==============================================',
    'Created:   2026-11-18 12:45:48 UTC (local time 13:45, UTC+01:00)',
    'Times:     UTC',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '',
    '2026-11-18 07:59:00 [timeline DEF] Defender paths exclusions changed (now 1: C:\\Users\\Bob\\Downloads)'
    ' <==== !defender-exclusion',
    '',
    '==================== TIMELINE - last 30 days, newest first =========================================',
    '(line: time [sources] file or event [status] => details <==== flags)',
    '',
    '2026-11-18 07:59:00 [DEF] Defender paths exclusions changed (now 1: C:\\Users\\Bob\\Downloads)'
    ' <==== !defender-exclusion',
    f'2026-11-18 08:00:00 [NEW] {UPD} => Upd: loader <==== !known-malware',
    f'2026-11-18 08:01:00 [PF] C:\\Windows\\System32\\cmd.exe => command line cmd /c {UPD} <==== !lolbin',
    '2026-11-18 08:02:00 [PF] C:\\Windows\\System32\\cmd.exe => command line cmd /c dir <==== !hidden-window',
    '',
    '==================== PERSISTENCE - Run keys, services, scheduled tasks, Startup folders, WMI, with times ====',
    '--- Services and drivers outside trusted locations ---',
    '(line: time [kind] service => program [status], start <==== flags)',
    '',
    f'2026-11-01 10:00:00 [service] UpdSvc => {SVC} [unsigned], start auto',
    '',
    '--- Services installed in the last 30 days (System event 7045), except signed programs in trusted locations ---',
    '(line: time [kind] service => program [status], account <==== flags)',
    '',
    '2026-11-01 09:59:00 [service] UpdSvc => C:\\ProgramData\\Other\\svc2.exe, account LocalSystem',
    '',
    '--- Scheduled tasks, except Microsoft tasks that run trusted programs ---',
    '(line: created [kind] task => program [status], changed; arguments <==== flags)',
    '',
    f'2026-11-02 08:00:00 [task] \\Upd\\Run => {SVC} [unsigned], changed 2026-11-03 08:00:00',
    '',
    '--- Task Scheduler events in the last 30 days ---',
    '(line: time [kind] [event] task => change; by)',
    '',
    '2026-11-04 08:00:00 [task] [106] \\Upd\\Run => registered; by Bob',
    '2026-11-04 08:00:00 [task] [141] \\Other\\Gone => deleted; by Bob',
    '',
    '==================== SOFTWARE - programs installed, updated or removed recently ====================',
    '--- Installed programs, installed or updated in the last 30 days (Uninstall keys) ---',
    '(line: time [scope] name => program [status], version; publisher; install date; folder; key; hidden <==== flags)',
    '',
    f'2026-11-12 03:46:25 [machine] Upd Tool => Windows Installer (msiexec), version 1.0; publisher Upd;'
    f' key HKLM\\...\\{{{GUID}}}',
    '',
    '--- Windows Installer: installs and removals in the last 30 days (Application log) ---',
    '(line: time [event] what => user; name; product code)',
    '',
    f'2026-11-12 03:46:20 [1033] installed: Upd Tool 1.0 (Upd) => SYSTEM; name Upd Tool; product code {{{GUID}}}',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '(line: file => sha256, signature; version; amcache sha1; md5; size; created; modified)',
    '',
    f'{UPD} => {UPD_SHA.upper()}, signature unsigned',
    f'{COPY} => {UPD_SHA.upper()}, signature unsigned',
    f'C:\\Games\\A\\UnityPlayer.dll => {UNITY_SHA.upper()}, signature unsigned',
    f'C:\\Games\\B\\UnityPlayer.dll => {UNITY_SHA.upper()}, signature unsigned',
    '',
    '==================== End of log. Scan took 9.9 s ====',
])
LINES_LINKS = SPOR_LINKS.split('\n')


class SameFileTests(TestCase):
    def test_a_file_links_its_lines_in_every_section(self):
        links = self_links('spor', s.SPOR)
        files = no_of(s.LINES, s.EVIL + ' => ')
        timeline = no_of(s.LINES, '2026-11-18 07:48:46 [PF PCA BAM]')
        loaded = no_of(s.LINES, f'loaded: {s.EVIL}')
        summary = no_of(s.LINES, '2026-09-30 03:55:49 [Persistence]')
        self.assertEqual(linked(links, files), {timeline: None, loaded: None, summary: None})
        self.assertEqual(set(linked(links, timeline)), {files, loaded, summary})
        # Nothing bad about evil.exe in this log but unsigned: no status.
        self.assertEqual(self_status(links[str(files)]), '')

    def test_a_defender_detection_colours_the_files_other_lines(self):
        links = self_links('spor', s.SPOR)
        files = no_of(s.LINES, s.DROPPER + ' => ')
        action = no_of(s.LINES, '2026-11-14 07:22:00 [1117]')
        detected = no_of(s.LINES, '2026-11-14 07:21:07 [1116]')
        self.assertEqual(set(linked(links, files)), {action, detected, no_of(s.LINES, '2026-11-14 07:21:07 [Defender]')})
        self.assertEqual(self_status(links[str(files)]), 'B')
        # Both Defender events of the file get its FILES line (signature invalid).
        self.assertIn(files, linked(links, action))
        self.assertIn(files, linked(links, detected))
        # Every entry jumps within this log.
        self.assertTrue(all(entry['upload_id'] == 'spor' for entry in links[str(files)]))

    def test_every_timeline_line_of_a_file_links(self):
        # The timeline evidence keeps one line per file; the 4688 start later
        # in the timeline is a line about qwXyZaB.exe too.
        links = self_links('spor', s.SPOR_V4)
        start = no_of(s.LINES_V4, '2026-11-20 03:33:53 [4688]')
        self.assertIsNone(linked(links, start)[no_of(s.LINES_V4, s.SIDE_HOST + ' => ')])
        self.assertIn(start, linked(links, no_of(s.LINES_V4, s.SIDE_HOST + ' => ')))

    def test_a_line_never_links_to_itself(self):
        for content in (s.SPOR, s.SPOR_V2, s.SPOR_V3, s.SPOR_V4, SPOR_LINKS):
            for no, entries in self_links('spor', content).items():
                self.assertNotIn(int(no), [entry['line_no'] for entry in entries])


class SummaryTests(TestCase):
    def test_summary_and_detail_lines_of_one_file_link_as_that_file(self):
        # Both name dropper.exe: the strongest link wins, the same file.
        links = self_links('spor', s.SPOR)
        summary = no_of(s.LINES, '2026-11-14 07:21:07 [Defender]')
        detail = no_of(s.LINES, '2026-11-14 07:21:07 [1116]')
        self.assertIsNone(linked(links, summary)[detail])
        self.assertIsNone(linked(links, detail)[summary])
        entry = next(entry for entry in links[str(detail)] if entry['line_no'] == summary)
        self.assertEqual(entry['section'], 'SUMMARY')

    def test_a_summary_without_a_file_finds_its_line(self):
        links = self_links('spor', SPOR_LINKS)
        summary = no_of(LINES_LINKS, '2026-11-18 07:59:00 [timeline DEF]')
        detail = no_of(LINES_LINKS, '2026-11-18 07:59:00 [DEF]')
        self.assertEqual(linked(links, summary), {detail: 'summary'})
        self.assertEqual(linked(links, detail), {summary: 'summary'})
        entry = links[str(detail)][0]
        self.assertEqual((entry['role'], entry['section']), ('in SUMMARY', 'SUMMARY'))
        # !defender-exclusion is strong: the pair colours both lines.
        self.assertEqual(self_status(links[str(summary)]), '!')

    def test_a_timeline_summary_finds_its_timeline_line(self):
        links = self_links('spor', s.SPOR_V4)
        summary = no_of(s.LINES_V4, '2026-11-20 03:33:38 [timeline NEW TSK]')
        detail = no_of(s.LINES_V4, '2026-11-20 03:33:38 [NEW TSK]')
        self.assertIn(detail, linked(links, summary))
        # !runtime-loader is strong: the pair colours both lines.
        self.assertEqual(self_status(links[str(summary)]), '!')
        self.assertEqual(self_status(links[str(detail)]), '!')


class ByNameTests(TestCase):
    def setUp(self):
        self.links = self_links('spor', SPOR_LINKS)

    def test_task_events_and_service_installs_find_their_entry(self):
        task = no_of(LINES_LINKS, '2026-11-02 08:00:00 [task]')
        event = no_of(LINES_LINKS, '2026-11-04 08:00:00 [task] [106]')
        self.assertEqual(linked(self.links, event), {task: 'task'})
        self.assertNotIn(str(no_of(LINES_LINKS, '2026-11-04 08:00:00 [task] [141]')), self.links)
        service = no_of(LINES_LINKS, '2026-11-01 10:00:00 [service]')
        install = no_of(LINES_LINKS, '2026-11-01 09:59:00 [service]')
        self.assertEqual(linked(self.links, install), {service: 'service'})

    def test_an_installer_event_finds_the_uninstall_entry_of_its_product_code(self):
        entry = no_of(LINES_LINKS, '2026-11-12 03:46:25 [machine]')
        event = no_of(LINES_LINKS, '2026-11-12 03:46:20 [1033]')
        self.assertEqual(linked(self.links, event), {entry: 'msi'})

    def test_a_timeline_install_finds_its_software_line(self):
        links = self_links('spor', s.SPOR_V2)
        install = no_of(s.LINES_V2, '2026-11-17 10:00:00 [INS]')
        software = no_of(s.LINES_V2, '2026-11-17 10:00:00 [machine] TeamViewer')
        self.assertEqual(linked(links, install), {software: 'uninstall'})


class RelatedTests(TestCase):
    def test_files_named_in_details(self):
        links = self_links('spor', s.SPOR_V4)
        cmd = no_of(s.LINES_V4, '2026-11-20 03:33:52 [SYSMON]')
        host_files = no_of(s.LINES_V4, s.SIDE_HOST + ' => ')
        self.assertEqual(linked(links, cmd)[host_files], 'detail')
        self.assertEqual(linked(links, host_files)[cmd], 'named_by')
        # Informational: the cmd.exe line gets no status from qwXyZaB.exe's flags.
        self.assertEqual(self_status(links[str(cmd)]), '')
        # "side-loads providers.dll": the DLL in the program's folder.
        timeline_host = no_of(s.LINES_V4, '2026-11-20 03:33:50 [NEW] ' + s.SIDE_HOST)
        self.assertEqual(linked(links, timeline_host)[no_of(s.LINES_V4, s.SIDE_DLL + ' => ')], 'detail')
        # "padded file X" of the launcher.
        launcher = no_of(s.LINES_V4, '2026-11-20 03:33:38 [NEW TSK]')
        self.assertEqual(linked(links, launcher)[no_of(s.LINES_V4, '2026-11-20 03:33:40 [NEW]')], 'detail')

    def test_a_hint_never_colours(self):
        links = self_links('spor', s.SPOR_V4)
        lure_files = no_of(s.LINES_V4, s.LURE + ' => ')
        self.assertEqual(linked(links, lure_files), {no_of(s.LINES_V4, '2026-11-20 03:40:00 [NEW]'): None})
        self.assertEqual(self_status(links[str(lure_files)]), '')

    def test_a_defender_excluded_folder_and_the_files_inside(self):
        links = self_links('spor', s.SPOR_V2)
        exclusion = no_of(s.LINES_V2, '2026-11-17 16:12:59 [Paths]')
        files = no_of(s.LINES_V2, s.EVIL + ' => ')
        entry = next(entry for entry in links[str(files)] if entry['line_no'] == exclusion)
        self.assertTrue(entry['in_folder'])
        self.assertEqual(linked(links, exclusion)[files], 'inside')
        self.assertEqual(self_status(links[str(exclusion)]), '')

    def test_a_copy_of_a_flagged_file_gets_its_findings(self):
        links = self_links('spor', SPOR_LINKS)
        copy = no_of(LINES_LINKS, COPY + ' => ')
        self.assertEqual(set(linked(links, copy).values()), {'same_hash'})
        self.assertEqual(self_status(links[str(copy)]), 'B')
        self.assertEqual(self_status(links[str(no_of(LINES_LINKS, UPD + ' => '))]), 'B')

    def test_copies_and_names_of_unflagged_files_are_not_linked(self):
        links = self_links('spor', SPOR_LINKS)
        self.assertNotIn(str(no_of(LINES_LINKS, 'C:\\Games\\A\\UnityPlayer.dll')), links)

    def test_host_programs_link_but_never_rate(self):
        links = self_links('spor', SPOR_LINKS)
        first = no_of(LINES_LINKS, '2026-11-18 08:01:00 [PF]')
        second = no_of(LINES_LINKS, '2026-11-18 08:02:00 [PF]')
        self.assertEqual(linked(links, first)[second], 'host')
        self.assertEqual(self_status(links[str(first)]), '')


class CodesTests(TestCase):
    def test_codes_mark_rated_and_notable_lines_only(self):
        links = compute('spor', s.SPOR)
        files = str(no_of(s.LINES, s.DROPPER + ' => '))
        evil_files = str(no_of(s.LINES, s.EVIL + ' => '))
        self.assertEqual(links.codes[files], 'B')
        # evil.exe is unsigned: a neutral marker.
        self.assertEqual(links.codes[evil_files], 'm')
        self.assertEqual(links.entries(files), self_links('spor', s.SPOR)[files])
        self.assertEqual(links.entries('999'), [])
        self.assertEqual(links.entries('x'), [])

    def test_lines_without_anything_notable_have_no_marker(self):
        links = compute('spor', s.SPOR_V2)
        self.assertEqual(links.codes[str(no_of(s.LINES_V2, s.TEAMVIEWER + ' => '))], 'm')   # unsigned
        content = s.SPOR_V2.replace(' [unsigned], version 15.83.7', ', version 15.83.7').replace(
            f'{s.TEAMVIEWER} => not hashed, signature unsigned', f'{s.TEAMVIEWER} => not hashed, signature valid')
        lines = content.split('\n')
        self.assertEqual(compute('spor', content).codes[str(no_of(lines, s.TEAMVIEWER + ' => '))], '')


class PageTests(TestCase):
    def setUp(self):
        spor_self._cache.clear()
        # The page detects the log type again (a database rule in production).
        LogTypeDetectionRule.objects.create(
            name='Spor', log_type='Spor', pattern=r'Spor [\d.]+ - forensic triage log',
            scope=LogTypeDetectionRule.SCOPE_START,
        )
        self.user = make_user()
        self.client.force_login(self.user)
        self.spor = make_uploaded_log('spor-log', log_type='Spor', content=s.SPOR)

    def test_page_has_codes_only_and_the_endpoint_gives_entries(self):
        response = self.client.get(reverse('view_uploaded_log', args=['spor-log']))
        data = response.context['correlations']
        files = str(no_of(s.LINES, s.DROPPER + ' => '))
        self.assertEqual(data['self_lines'][files], 'B')
        self.assertTrue(data['reverse'])
        self.assertEqual(data['lines'], {})
        self.assertIn('id="correlationData"', response.content.decode())
        answer = self.client.get(data['self_url'] + '&line=' + files).json()
        self.assertEqual(
            {entry['line_no'] for entry in answer['entries']},
            {int(no) for no in [no_of(s.LINES, '2026-11-14 07:22:00 [1117]'), no_of(s.LINES, '2026-11-14 07:21:07 [1116]'),
                                no_of(s.LINES, '2026-11-14 07:21:07 [Defender]')]},
        )

    def test_page_offers_centralbox_lookups(self):
        data = self.client.get(reverse('view_uploaded_log', args=['spor-log'])).context['correlations']
        self.assertEqual(data['hash_url'], reverse('centralbox_hash_check_api'))
        self.assertTrue(data['fresh_url'] and data['fresh_status_url'])
        self.assertIn('can_lookup', data)

    def test_lines_whose_files_hashes_can_be_looked_up_are_listed(self):
        from ..views.centralbox import add_self_link_context
        files_of_dropper = str(no_of(s.LINES, '2026-11-14 07:22:00 [1117]'))   # links the FILES line of dropper.exe
        with mock.patch('fixlist.views.centralbox.centralbox.is_available', return_value=True):
            lookup = add_self_link_context(self.spor, {})['self_lookup']
            self.assertIn(files_of_dropper, lookup)
            now = timezone.now()
            HashVerdict.objects.create(sha256=s.DROP_SHA, state='known', verdict='malicious', checked_at=now,
                                       next_check_at=now + timedelta(days=7))
            # A known hash has a report: nothing to look up there any more.
            self.assertNotIn(files_of_dropper, add_self_link_context(self.spor, {})['self_lookup'])
        with mock.patch('fixlist.views.centralbox.centralbox.is_available', return_value=False):
            self.assertNotIn('self_lookup', add_self_link_context(self.spor, {}))

    def test_endpoint_needs_a_login(self):
        self.client.logout()
        response = self.client.get(reverse('spor_self_links_api'), {'upload_id': 'spor-log', 'line': '1'})
        self.assertEqual(response.status_code, 302)

    def test_endpoint_gives_files_hashes_their_stored_centralbox_result(self):
        now = timezone.now()
        HashVerdict.objects.create(sha256=s.DROP_SHA, state='known', verdict='malicious', family='asyncrat',
                                   checked_at=now, next_check_at=now + timedelta(days=7))
        url = reverse('spor_self_links_api')
        # The Defender event of dropper.exe: its FILES line has the hash.
        action = str(no_of(s.LINES, '2026-11-14 07:22:00 [1117]'))
        entries = self.client.get(url, {'upload_id': 'spor-log', 'line': action}).json()['entries']
        info = next(entry for entry in entries if entry['kind'] == 'file_info')
        self.assertEqual((info['sha256'], info['centralbox']['family']), (s.DROP_SHA, 'asyncrat'))
        # A hash centralbox was never asked about has no result (the box offers a lookup).
        evil = str(no_of(s.LINES, '2026-11-18 07:48:46 [PF PCA BAM]'))
        entries = self.client.get(url, {'upload_id': 'spor-log', 'line': evil}).json()['entries']
        info = next(entry for entry in entries if entry['kind'] == 'file_info')
        self.assertEqual(info['sha256'], s.EVIL_SHA)
        self.assertNotIn('centralbox', info)

    def test_endpoint_answers_nothing_for_other_logs_and_bad_lines(self):
        make_uploaded_log('fix-log', log_type='Fixlog', content='Fix result of Farbar Recovery Scan Tool')
        url = reverse('spor_self_links_api')
        self.assertEqual(self.client.get(url, {'upload_id': 'fix-log', 'line': '1'}).json(), {'entries': []})
        self.assertEqual(self.client.get(url, {'upload_id': 'spor-log', 'line': 'x'}).json(), {'entries': []})
        self.assertEqual(self.client.get(url, {'upload_id': 'nope', 'line': '1'}).json(), {'entries': []})

    def test_reverse_lines_are_kept(self):
        context = {'fresh': False, 'reverse': True, 'lines': {'5': {'status': 'B', 'entries': [{'kind': 'reverse'}]}}}
        result = add_self_link_context(self.spor, context)
        self.assertEqual((result['fresh'], result['lines']['5']['status']), (False, 'B'))
        self.assertIn('self_lines', result)

    def test_other_logs_are_left_alone(self):
        fix = make_uploaded_log('fix-log', log_type='Fixlog', content='Fix result of Farbar Recovery Scan Tool')
        self.assertEqual(add_self_link_context(fix, {}), {})

    def test_the_cache_follows_the_content(self):
        first = spor_self.for_upload(self.spor)
        self.assertIs(spor_self.for_upload(self.spor), first)
        self.spor.content = s.SPOR_V2
        self.spor.content_hash = 'other'
        self.assertIsNot(spor_self.for_upload(self.spor), first)
