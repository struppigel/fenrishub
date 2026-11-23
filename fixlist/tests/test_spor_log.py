"""Spor logs (forensic triage): the parser (fixlist/spor_log.py), the
highlighter, the FILES hash rows, the correlations they feed into FRST lines
(hashes, Defender detections, timeline evidence), the header's machine
signals and the automatic centralbox candidates. Nothing here may call
centralbox."""

from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from .. import centralbox, centralbox_auto, spor_log
from ..file_hashes import extract_file_hashes
from ..log_highlighting import compute_tool_stats, highlight_log, iter_lines
from ..machine_signals import extract_signals
from ..models import CentralboxAutoQueue, InfectionCase, InfectionCaseLog, LogTypeDetectionRule, UploadedLogFileHash
from .factories import make_uploaded_log, make_user
from .spor_sample import DROP_SHA, DROPPER, EVIL, EVIL_SHA, INVOICE, LINES, NOTES_MD5, OK_SHA, SHA1, SPOR
from .test_case_correlations import RUN_LINE, cache_analysis


def no(needle, start=1):
    """1-based number of the first fixture line from `start` containing `needle`."""
    for index in range(start - 1, len(LINES)):
        if needle in LINES[index]:
            return index + 1
    raise AssertionError(f'{needle!r} not in fixture')


def classes(line):
    """{class: text of its first token} of a line's tokens, also under each single class."""
    out = {}
    for cls, text in line.tokens:
        if cls:
            out.setdefault(cls, text)
    for cls, text in line.tokens:
        for single in cls.split():
            out.setdefault(single, text)
    return out


class ParserTests(SimpleTestCase):
    def test_sections_by_title(self):
        titles = [title for title, _start, _end in spor_log.iter_sections(LINES)]
        self.assertEqual(titles[:3], ['Spor 0.1.0', 'SUMMARY', 'TIMELINE'])
        self.assertIn('AMCACHE FILES', titles)
        self.assertTrue(titles[-1].startswith('End of log'))

    def test_split_item(self):
        item = spor_log.split_item(LINES[no('[PF PCA BAM]') - 1])
        self.assertEqual((item.time, item.tags, item.item, item.status), ('2026-11-18 07:48:46', 'PF PCA BAM', EVIL, 'unsigned'))
        self.assertTrue(item.rest.startswith('PCA: Installer failed'))
        # Status after the target (persistence), no time, [user] tags, flags.
        item = spor_log.split_item('2026-09-30 03:55:49 EvilSvc => C:\\x\\a.exe [unsigned], start auto')
        self.assertEqual((item.tags, item.item, item.status), ('', 'EvilSvc', 'unsigned'))
        item = spor_log.split_item('[bob] cmd /c calc.exe => order 4 <==== !suspicious !lolbin')
        self.assertEqual((item.time, item.tags, item.item, item.rest), ('', 'bob', 'cmd /c calc.exe', 'order 4'))
        self.assertEqual((item.flags, item.loud_flags), (['!suspicious', '!lolbin'], ['!suspicious']))
        self.assertEqual(spor_log.split_item('C:\\x\\big.iso [> 600 MB, not hashed]').status, '> 600 MB, not hashed')
        # A bracket that is no status word stays part of the item.
        self.assertEqual(spor_log.split_item('C:\\x\\[a] b.exe').item, 'C:\\x\\[a] b.exe')

    def test_files_lines(self):
        files = {path: (line_no, value, signature) for line_no, path, value, signature in spor_log.iter_files(LINES)}
        self.assertEqual(files[EVIL], (no(f'{EVIL} => '), EVIL_SHA.upper(), 'unsigned'))
        self.assertEqual(files[DROPPER][2], 'invalid')
        self.assertEqual(files['C:\\Users\\Bob\\Desktop\\notes.ps1'][1:], (NOTES_MD5.upper(), ''))
        self.assertEqual(files['C:\\Users\\Bob\\Desktop\\big.iso'][1:], ('', ''))
        self.assertNotIn('C:\\Users\\Bob\\Desktop\\old.exe', files)  # AMCACHE FILES is another section

    def test_files_hidden_comment_is_no_file(self):
        # Spor 0.7.2+: FILES counts the validly signed files the whitelist leaves out in a comment.
        at = LINES.index('(line: file => sha256, signature; version; amcache sha1)') + 1
        hidden = ('(Hidden: 844 validly signed files no section above shows (Windows drivers and system files, '
                  'programs of trusted services); -nowhitelist lists them.)')
        lines = LINES[:at] + [hidden] + LINES[at:]
        rows = lambda found: [(path, value, signature) for _no, path, value, signature in found]
        self.assertEqual(rows(spor_log.iter_files(lines)), rows(spor_log.iter_files(LINES)))

    def test_defender_detections_one_per_file_and_threat_with_the_action(self):
        found = spor_log.iter_defender_detections(LINES)
        self.assertEqual(found, [
            (no('[1117]'), 'Trojan:Win32/Malgent!MSR', 'Quarantine', DROPPER),
            (no('[1116] Defender detected: PUA'), 'PUA:Win32/Presenoker', '', 'C:\\Users\\Bob\\Downloads\\bundle.exe'),
        ])

    def test_timeline_evidence_per_path(self):
        found = {item.path: item for item in spor_log.iter_timeline_evidence(LINES)}
        self.assertEqual(set(found), {
            EVIL, 'C:\\Windows\\System32\\mshta.exe', INVOICE,
            'C:\\Users\\Bob\\AppData\\Local\\App\\1.0.1\\app.exe', 'C:\\Users\\Bob\\AppData\\Local\\App\\1.0.0\\app.exe',
        })
        evil = found[EVIL]
        self.assertEqual((evil.line_no, evil.time, evil.sources, evil.file_status, evil.flags),
                         (no('[PF PCA BAM]'), '2026-11-18 07:48:46', 'PF PCA BAM', 'unsigned', []))
        self.assertEqual(found[INVOICE].flags, ['!double-extension'])
        # A "path:" sub-line: its own time and status, the sources of its line.
        old = found['C:\\Users\\Bob\\AppData\\Local\\App\\1.0.0\\app.exe']
        self.assertEqual((old.line_no, old.time, old.sources, old.file_status),
                         (no('1.0.0\\app.exe'), '2026-10-23 19:29:00', 'SRU', 'gone'))
        # The merged line's own path is listed once, at the merged line.
        self.assertEqual(found['C:\\Users\\Bob\\AppData\\Local\\App\\1.0.1\\app.exe'].line_no, no('[SRU]'))


class HighlightTests(SimpleTestCase):
    def setUp(self):
        self.result = highlight_log('Spor', SPOR)
        self.lines = {line.no: line for line in iter_lines(self.result)}

    def line(self, needle, start=1):
        return classes(self.lines[no(needle, start)])

    def test_sections_and_header(self):
        headers = [section.header.text.split(' - ')[0].strip('= ') for section in self.result.sections
                   if section.header is not None]
        self.assertEqual(headers, ['SUMMARY', 'TIMELINE', 'PREFETCH', 'DEFENDER', 'CLICKFIX', 'FILES',
                                   'AMCACHE FILES', 'LEGEND'])
        self.assertEqual(self.line('Spor 0.1.0')['hl-title'], LINES[0])
        self.assertEqual(self.line('Computer:')['hl-key'], 'Computer:')
        self.assertIn('hl-subheader', self.line('--- Files loaded'))
        self.assertEqual(self.line('(line: time [sources]'), {'hl-dim': LINES[no('(line: time [sources]') - 1]})

    def test_items_statuses_and_flags(self):
        evil = self.line('[PF PCA BAM]')
        self.assertEqual((evil['hl-dim'], evil['hl-accent'], evil['hl-path'], evil['hl-sev-w']),
                         ('2026-11-18 07:48:46', '[PF PCA BAM]', EVIL, '[unsigned]'))
        self.assertEqual(self.line('mshta.exe =>')['hl-sev-g'], '<==== !lolbin')
        invoice = self.line('[DL OPN]')
        self.assertEqual((invoice['hl-path'], invoice['hl-sev-w']), (INVOICE, '<==== !double-extension'))
        self.assertIn(('hl-dim', '[gone]'), self.lines[no('[DL OPN]')].tokens)
        loaded = self.line('    loaded:')
        self.assertEqual((loaded['hl-key'], loaded['hl-path']), ('loaded:', EVIL))

    def test_defender_threats_and_actions(self):
        detected = self.line('[1116] Defender detected: Trojan')
        self.assertEqual(detected['hl-threat hl-sev-b'], 'Trojan:Win32/Malgent!MSR')
        self.assertEqual(detected['hl-path'], DROPPER)
        self.assertEqual(self.line('[1116] Defender detected: PUA')['hl-threat hl-sev-p'], 'PUA:Win32/Presenoker')
        taken = self.line('[1117]')
        self.assertEqual((taken['hl-key'], taken['hl-sev-c']), ('action ', 'Quarantine'))

    def test_files_signatures_and_hashes(self):
        self.assertEqual(self.line(f'{EVIL} => ')['hl-sev-w'], 'unsigned')
        self.assertEqual(self.line(f'{DROPPER} => ')['hl-sev-b'], 'invalid')
        ok = self.line('ok.exe =>')
        self.assertEqual((ok['hl-sev-c'], ok['hl-hash']), ('valid', OK_SHA.upper()))
        self.assertEqual(self.line('old.exe =>')['hl-hash'], SHA1.upper())

    def test_powershell_history_is_not_tokenized(self):
        history = self.lines[no('789 [suspicious]')]
        self.assertEqual(classes(history)['hl-sev-w'], '[suspicious]')
        self.assertNotIn('hl-path', classes(history))
        self.assertIn(('hl-sev-w', '<==== !suspicious'), history.tokens)
        self.assertEqual(self.line('    PF ')['hl-key'], 'PF')

    def test_summary_lists_the_summary_section(self):
        items = [(item.line_no, item.severity, item.name) for item in self.result.summary]
        self.assertEqual(items, [
            (no('[timeline DEF]'), 'w', 'Defender paths exclusions changed (now 1: C:\\Users\\Bob\\Downloads)'),
            (no('[Persistence]'), 'g', f'service EvilSvc (auto): {EVIL}'),
            (no('[Defender] Defender detected: Trojan'), 'b', 'Trojan:Win32/Malgent!MSR'),
            (no('[Defender] Defender detected: PUA'), 'p', 'PUA:Win32/Presenoker'),
            (no('[ClickFix]'), 'i', 'Run dialog cmd /c calc.exe'),
        ])
        self.assertEqual(self.result.summary[2].target, DROPPER)
        self.assertEqual(self.result.summary[1].action, 'Persistence unsigned')
        self.assertEqual([(stat.label, stat.value, stat.severity) for stat in self.result.stats], [
            ('Defender', '2', 'b'), ('Flagged', '5', 'w'), ('Unsigned', '2', 'w'), ('Bad signature', '1', 'b'),
        ])

    def test_no_tool_chips(self):
        # Spor lists show the analyzer's status counts like FRST (StatusChipTests).
        self.assertEqual(compute_tool_stats('Spor', SPOR), [])


class StatusChipTests(TestCase):
    """Spor logs show the FRST status chips (B P C ... -> % known) in the
    lists and before the Spor stats on the log page."""

    COUNTS = dict(total_line_count=10, count_malware=2, count_warning=1, count_junk=5, count_unknown=2)

    def setUp(self):
        # The page detects the log type again (a database rule in production).
        LogTypeDetectionRule.objects.create(
            name='Spor', log_type='Spor', pattern=r'Spor [\d.]+ - forensic triage log',
            scope=LogTypeDetectionRule.SCOPE_START,
        )
        self.user = make_user()
        self.client.force_login(self.user)
        # Old rows still hold the Spor tool chips; they are no longer shown.
        self.spor = make_uploaded_log(
            'spor-chips', log_type='Spor', content=SPOR, recipient_user=self.user,
            tool_stats=[['defender', 2, 'b'], ['flagged', 5, 'w']], **self.COUNTS,
        )

    def assert_status_chips(self, response):
        self.assertContains(response, '<span class="stat-b">B 2</span>')
        self.assertContains(response, '<span class="stat-w">! 1</span>')
        self.assertContains(response, '<span class="stat-j">P 0</span>')
        self.assertContains(response, '<span class="stat-u">? 2</span>')
        self.assertContains(response, '80% known')
        self.assertNotContains(response, 'defender 2')

    def test_uploads_list(self):
        response = self.client.get(reverse('uploaded_logs'))
        self.assert_status_chips(response)
        self.assertContains(response, 'shared rules</span>')

    def test_case_page(self):
        case = InfectionCase.objects.create(owner=self.user, username='forum_user', auto_assign_new_items=False)
        InfectionCaseLog.objects.create(case=case, uploaded_log=self.spor)
        self.assert_status_chips(self.client.get(reverse('view_infection_case', args=[case.case_id])))

    def test_log_page_summary_head(self):
        response = self.client.get(reverse('view_uploaded_log', args=['spor-chips']))
        stats = [(stat.label, stat.value, stat.severity) for stat in response.context['highlight'].stats]
        self.assertEqual(stats[:11], [
            ('B', '2', 'b'), ('P', '0', 'j'), ('C', '0', 'j'), ('A', '0', 'j'), ('!', '1', 'w'), ('G', '0', 'j'),
            ('S', '0', 'j'), ('I', '0', 'j'), ('J', '5', 'j'), ('?', '2', 'u'), ('known', '80%', ''),
        ])
        self.assertEqual(stats[11][0], 'Defender')

    def test_known_percent_without_lines(self):
        self.assertEqual(make_uploaded_log('spor-empty', log_type='Spor', content=SPOR).known_percent(), 0)


BIG_ISO = 'C:\\Users\\anna\\Downloads\\big.iso'
FAILED_EXE = 'C:\\Users\\Bob\\evil.exe'
# Shapes Spor 0.1.1 writes that the main fixture does not have.
MORE_SHAPES = '\n'.join([
    '\ufeff==================== Spor 0.1.1 - forensic triage log ===========',
    'Created:   2026-11-19 21:09:24 UTC (local time 22:09, UTC+01:00)',
    'Times:     UTC',
    '',
    '==================== TIMELINE - last 30 days, oldest first ========',
    '2026-11-03 05:06:21 [NEW] C:\\T\\20261103\\w.dll [unsigned] => +2 more times since 2026-10-27 21:25',
    '    path: C:\\T\\20261027\\w.dll [unsigned] => 2026-10-27 21:25:28',
    '    path: C:\\T\\20261103\\w.dll [unsigned] => 2026-11-03 05:06:21',
    '2026-11-19 06:52:31 [MPL] \\\\?\\C:\\Users\\Bob\\x\\default_exe.exe',
    '',
    '==================== DOWNLOADS AND OPENED FILES - downloads ========',
    '2026-11-12 13:37:27 [strup] [7-Zip] archives created',
    f'2026-11-18 16:33:22 [[anna] Brave] {BIG_ISO} [> 600 MB, not hashed, unsigned]',
    '',
    '==================== PERSISTENCE - Run keys ========================',
    '--- Run keys (all entries) ---',
    '2026-01-01 00:00:00 [run] HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Game'
    ' => C:\\Games [x]\\a.exe [unsigned], value Game',
    '2026-01-02 00:00:00 [task] \\Evil\\Com => C:\\x\\evil.dll (COM handler, HKCU) [unsigned], arguments A',
    '',
    '==================== DEFENDER - detections ==========================',
    '--- Defender events (oldest first) ---',
    f'2026-11-19 06:53:24 [1118] Defender action FAILED: Trojan:Win32/Evil => {FAILED_EXE}; action Quarantine'
    ' <==== !not-removed',
    '',
    '==================== LEGEND ========================================',
    'Status (in brackets after a file):',
    '    no access           Spor could not read it',
    '    > N MB, not hashed  too big for the hash limit',
    '    PF    Prefetch: program run',
    '==================== End of log. Scan took 1.0 s ====',
])
MORE_LINES = MORE_SHAPES.split('\n')


def more_no(needle):
    return next(index + 1 for index, line in enumerate(MORE_LINES) if needle in line)


class MoreShapesTests(SimpleTestCase):
    def test_bom_before_the_banner(self):
        self.assertEqual(spor_log.section_title(MORE_LINES[0]), 'Spor 0.1.1')

    def test_defender_action_failed_is_a_detection(self):
        self.assertEqual(spor_log.iter_defender_detections(MORE_LINES),
                         [(more_no('action FAILED'), 'Trojan:Win32/Evil', 'Quarantine', FAILED_EXE)])

    def test_several_statuses_in_one_bracket(self):
        item = spor_log.split_item(MORE_LINES[more_no('[[anna] Brave]') - 1])
        self.assertEqual((item.item, item.status), (BIG_ISO, '> 600 MB, not hashed, unsigned'))
        self.assertEqual(spor_log.status_words(item.status), ['> 600 MB, not hashed', 'unsigned'])
        self.assertTrue(spor_log.is_bad_signature('gone, invalid signature'))
        self.assertFalse(spor_log.is_bad_signature(item.status))

    def test_several_tag_groups_and_a_user_inside_one(self):
        item = spor_log.split_item(MORE_LINES[more_no('[7-Zip]') - 1])
        self.assertEqual((item.tags, item.item), ('strup 7-Zip', 'archives created'))
        item = spor_log.split_item(MORE_LINES[more_no('[[anna] Brave]') - 1])
        self.assertEqual(item.tags, '[anna] Brave')
        mentions = {mention.path: mention for mention in spor_log.iter_mentions(MORE_LINES)}
        self.assertEqual(mentions[BIG_ISO].status, '> 600 MB, not hashed, unsigned')

    def test_target_paths_end_at_their_status_or_note(self):
        targets = {mention.line_no: (mention.path, mention.status) for mention in spor_log.iter_mentions(MORE_LINES)
                   if mention.role == 'target'}
        self.assertEqual(targets[more_no('Run\\Game')], ('C:\\Games [x]\\a.exe', 'unsigned'))
        self.assertEqual(targets[more_no('COM handler')], ('C:\\x\\evil.dll', 'unsigned'))

    def test_device_prefix_is_left_out(self):
        item = spor_log.split_item(MORE_LINES[more_no('[MPL]') - 1])
        self.assertEqual(item.item, 'C:\\Users\\Bob\\x\\default_exe.exe')
        self.assertEqual(spor_log.strip_device_prefix('\\??\\C:\\x.exe'), 'C:\\x.exe')
        self.assertEqual(spor_log.strip_device_prefix('\\\\server\\share\\x.exe'), '\\\\server\\share\\x.exe')

    def test_timeline_items_include_merged_paths_at_their_own_time(self):
        found = [(line_no, item.time, item.item, item.tags) for line_no, item in spor_log.iter_timeline_items(MORE_LINES)]
        self.assertEqual(found, [
            (more_no('[NEW]'), '2026-11-03 05:06:21', 'C:\\T\\20261103\\w.dll', 'NEW'),
            (more_no('20261027\\w.dll'), '2026-10-27 21:25:28', 'C:\\T\\20261027\\w.dll', 'NEW'),
            (more_no('[MPL]'), '2026-11-19 06:52:31', 'C:\\Users\\Bob\\x\\default_exe.exe', 'MPL'),
        ])

    def test_highlighting(self):
        lines = {line.no: line.tokens for line in iter_lines(highlight_log('Spor', MORE_SHAPES))}
        self.assertIn(('hl-threat hl-sev-b', 'Trojan:Win32/Evil'), lines[more_no('action FAILED')])
        self.assertIn(('hl-accent', '[7-Zip]'), lines[more_no('[7-Zip]')])
        brave = lines[more_no('[[anna] Brave]')]
        self.assertIn(('hl-accent', '[[anna] Brave]'), brave)
        self.assertIn(('hl-sev-w', '[> 600 MB, not hashed, unsigned]'), brave)
        self.assertIn(('hl-key', 'no access'), lines[more_no('    no access')])
        self.assertIn(('hl-key', '> N MB, not hashed'), lines[more_no('    > N MB')])
        self.assertIn(('hl-key', 'PF'), lines[more_no('    PF ')])


ROBLOX = 'C:\\Users\\patri\\AppData\\Local\\Roblox\\Versions\\version-11f1\\robloxplayerbeta.exe'
PCA_EXE = 'C:\\Users\\patri\\AppData\\Local\\Temp\\7zS8EDDFED4\\HD-CheckCpu.exe'
# Shapes of Spor 0.6.x (real logs) that bent the format.
V06_SHAPES = '\n'.join([
    '==================== Spor 0.6.0 - forensic triage log ===========',
    'Users:     patri, WsiAccount',
    'Times:     UTC',
    '',
    '==================== SUMMARY - flagged items =======================',
    '2026-10-18 14:39:18 [Accounts] account CodexSandboxOffline (user)  !hidden-account, password set 2026-10-18'
    ' 14:39, never signed in',
    '2026-11-14 14:57:54 [Downloads and opened files] download C:\\Users\\patri\\Downloads\\FRST64.exe [gone]'
    '  !kept-despite-warning from https://download.bleepingcomputer.com/dl/x/FRST64.exe',
    f'2026-10-22 01:34:00 [Network] {ROBLOX} [gone] sent 126839092 bytes (10-22 to 10-22, SRUM)',
    '2024-04-19 13:00:20 [Execution evidence] C:\\T\\x.dll\\bag\\vc.exe [gone]  !in-folder-named-like-file'
    '  (ShimCache: file modified)',
    '',
    '==================== TIMELINE - last 30 days, oldest first ========',
    f'2026-10-24 14:13:07 [PCA] %USERPROFILE%\\AppData\\Local\\Temp\\7zS8EDDFED4\\HD-CheckCpu.exe'
    ' => PCA: Abnormal process exit with code 0x1',
    f'2026-10-24 14:20:00 [SC] {PCA_EXE.upper()} [gone] => ShimCache entry',
    '',
    '==================== PERSISTENCE - Run keys ========================',
    '2026-07-30 10:05:39 [service] PlanetVPNService => D:/Program Files (x86)/PlanetVPN/PlanetVPNService.exe'
    ' [unsigned], start auto',
    '',
    '==================== REMOTE ACCESS - remote access tools ===========',
    '2026-07-30 12:39:12 [RMM folder] C:\\Program Files (x86)\\Radmin VPN\\ => 1 exe, 1 log/config files',
    '    exe: C:\\Program Files (x86)\\Radmin VPN\\Radmin.exe',
    '    file: 2026-07-30 12:39:12 C:\\Program Files (x86)\\Radmin VPN\\CHATLOGS\\info.txt',
    '',
    '==================== FILES - SHA256 ================================',
    f'{PCA_EXE} => {"A" * 64}, signature valid; signer X',
    '==================== End of log. Scan took 1.0 s ====',
])
V06_LINES = V06_SHAPES.split('\n')


def v06_no(needle):
    return next(index + 1 for index, line in enumerate(V06_LINES) if needle in line)


class Spor06ShapesTests(SimpleTestCase):
    def summary(self, needle):
        return dict(spor_log.iter_summary_items(V06_LINES))[v06_no(needle)]

    def test_inline_flags_followed_by_a_comma_or_text(self):
        item = self.summary('CodexSandboxOffline')
        self.assertEqual((item.item, item.flags), ('account CodexSandboxOffline (user)', ['!hidden-account']))
        item = self.summary('FRST64.exe')
        self.assertEqual((item.item, item.status, item.flags),
                         ('download C:\\Users\\patri\\Downloads\\FRST64.exe', 'gone', ['!kept-despite-warning']))

    def test_inline_flags_after_a_status_stay_flags(self):
        item = self.summary('vc.exe')
        self.assertEqual((item.item, item.status, item.flags),
                         ('C:\\T\\x.dll\\bag\\vc.exe', 'gone', ['!in-folder-named-like-file']))

    def test_status_followed_by_text_without_an_arrow(self):
        item = self.summary('robloxplayerbeta')
        self.assertEqual((item.item, item.status), (ROBLOX, 'gone'))
        self.assertTrue(item.rest.startswith('sent 126839092 bytes'))

    def test_forward_slash_targets_are_paths(self):
        self.assertEqual(spor_log.normalize_path('D:/a b/c.exe'), 'D:\\a b\\c.exe')
        self.assertEqual(spor_log.normalize_path('\\\\?\\C:\\x.exe'), 'C:\\x.exe')
        targets = {m.line_no: (m.path, m.status) for m in spor_log.iter_mentions(V06_LINES) if m.role == 'target'}
        self.assertEqual(targets[v06_no('PlanetVPNService =>')],
                         ('D:\\Program Files (x86)\\PlanetVPN\\PlanetVPNService.exe', 'unsigned'))

    def test_user_profile_of_the_only_user(self):
        known = spor_log.known_paths(V06_LINES)
        self.assertEqual(spor_log.user_profile(V06_LINES, known), 'C:\\Users\\patri')
        self.assertEqual(spor_log.user_profile(['Users:     anna, bob']), '')
        self.assertEqual(spor_log.user_profile(['Users:     Anna, defaultuser1'],
                                               {'d:\\users\\anna\\x.exe': 'D:\\Users\\ANNA\\x.exe'}),
                         'D:\\Users\\ANNA')
        # No file in FILES confirms the folder: the account's folder can be named otherwise.
        self.assertEqual(spor_log.user_profile(['Users:     anna']), '')
        self.assertEqual(spor_log.user_profile(['Times:     UTC']), '')

    def test_a_status_of_another_path_further_on_stays_in_the_line(self):
        item = spor_log.summary_item('2026-11-01 00:00:00 [Prefetch] C:\\U\\x.pdf.lnk  !double-extension'
                                     '  (loaded by C:\\W\\host.exe [unsigned])')
        self.assertEqual((item.item, item.status, item.flags), ('C:\\U\\x.pdf.lnk', '', ['!double-extension']))
        item = spor_log.split_item('[Network] C:\\a\\b.exe sent 5 bytes (by C:\\x\\y.exe [gone])')
        self.assertEqual(item.status, '')
        self.assertTrue(item.item.startswith('C:\\a\\b.exe sent'))
        # The bracket must follow something that ends like a file or folder.
        self.assertEqual(spor_log.split_item('[Network] C:\\a\\b.exe sent 5 bytes [gone] (SRUM)').status, '')
        item = spor_log.split_item('C:\\a b\\c.exe [unsigned], start auto')
        self.assertEqual((item.item, item.status, item.rest), ('C:\\a b\\c.exe', 'unsigned', 'start auto'))

    def test_inline_flags_keep_the_text_after_them(self):
        self.assertEqual(self.summary('CodexSandboxOffline').rest, 'password set 2026-10-18 14:39, never signed in')
        self.assertEqual(self.summary('FRST64.exe').rest,
                         'from https://download.bleepingcomputer.com/dl/x/FRST64.exe')

    def test_forward_slashes_of_a_url_after_the_path_stay(self):
        self.assertEqual(spor_log.normalize_path('D:/a/x.exe sent to http://1.2.3.4/a'),
                         'D:\\a\\x.exe sent to http://1.2.3.4/a')

    def test_user_profile_prefers_the_system_drive(self):
        known = {'e:\\users\\anna\\old\\a.exe': 'E:\\Users\\anna\\old\\a.exe',
                 'c:\\users\\anna\\b.exe': 'C:\\Users\\anna\\b.exe'}
        self.assertEqual(spor_log.user_profile(['Users:     anna'], known), 'C:\\Users\\anna')

    def test_userprofile_paths_are_expanded_and_keep_a_later_status(self):
        evidence = {e.path.lower(): e for e in spor_log.iter_timeline_evidence(V06_LINES)}
        found = evidence[PCA_EXE.lower()]
        self.assertEqual((found.line_no, found.path, found.file_status), (v06_no('[PCA]'), PCA_EXE, 'gone'))
        items = [item.item for _no, item in spor_log.iter_timeline_items(V06_LINES)]
        self.assertIn(PCA_EXE, items)
        self.assertEqual(spor_log.split_item('%USERPROFILE%\\a.exe').item, '%USERPROFILE%\\a.exe')

    def test_rmm_folder_files_are_mentions(self):
        mentions = {(m.role, m.path): m for m in spor_log.iter_mentions(V06_LINES)}
        self.assertIn(('exe', 'C:\\Program Files (x86)\\Radmin VPN\\Radmin.exe'), mentions)
        info = mentions[('file', 'C:\\Program Files (x86)\\Radmin VPN\\CHATLOGS\\info.txt')]
        self.assertEqual(info.time, '2026-07-30 12:39:12')


class FileHashTests(SimpleTestCase):
    def test_files_section_rows(self):
        rows = {row.path: row for row in extract_file_hashes('Spor', SPOR) if row.source == 'spor'}
        self.assertEqual(set(rows), {EVIL, DROPPER, 'C:\\Program Files\\Ok\\ok.exe', 'C:\\Users\\Bob\\Desktop\\notes.ps1'})
        evil = rows[EVIL]
        self.assertEqual((evil.sha256, evil.line_no, evil.anchor_line_no, evil.detection),
                         (EVIL_SHA, no(f'{EVIL} => '), no(f'{EVIL} => '), ''))
        self.assertEqual(rows[DROPPER].detection, 'Trojan:Win32/Malgent!MSR')
        notes = rows['C:\\Users\\Bob\\Desktop\\notes.ps1']
        self.assertEqual((notes.sha256, notes.md5, notes.auto), ('', NOTES_MD5, False))

    def test_only_files_spor_flags_are_checked_by_themselves(self):
        auto = {row.path for row in extract_file_hashes('Spor', SPOR) if row.auto}
        # evil.exe: in the SUMMARY; dropper.exe: Defender detection and invalid signature.
        self.assertEqual(auto, {EVIL, DROPPER})

    def test_a_process_named_by_defender_is_not_flagged(self):
        content = SPOR.replace('C:\\Program Files\\Ok\\ok.exe', 'C:\\Windows\\explorer.exe')
        auto = {row.path for row in extract_file_hashes('Spor', content) if row.auto}
        self.assertNotIn('C:\\Windows\\explorer.exe', auto)

    def test_sha1_values_are_not_rows(self):
        rows = extract_file_hashes('Spor', SPOR)
        self.assertFalse([row for row in rows if 'sha1only' in row.path or 'old.exe' in row.path])

    def test_crlf(self):
        plain = [(row.sha256, row.line_no, row.path, row.auto) for row in extract_file_hashes('Spor', SPOR)]
        crlf = [(row.sha256, row.line_no, row.path, row.auto)
                for row in extract_file_hashes('Spor', SPOR.replace('\n', '\r\n'))]
        self.assertEqual(plain, crlf)


class MachineSignalTests(SimpleTestCase):
    def test_header_gives_computer_and_profile(self):
        signals = extract_signals(SPOR)
        self.assertEqual(signals['computer'], {'pc-bob'})
        self.assertIn('bob', signals['profile'])


DROPPER_LINE = f'2026-11-14 07:20 - 2026-11-14 07:20 - 012345678 _____ (Evil Ltd) {DROPPER}'
INVOICE_LINE = f'2026-11-17 07:49 - 2026-11-17 07:49 - 000123456 _____ () {INVOICE}'
FRST = '\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)', RUN_LINE, DROPPER_LINE, INVOICE_LINE])


class CorrelationTests(TestCase):
    def setUp(self):
        user = make_user()
        self.client.force_login(user)
        case = InfectionCase.objects.create(owner=user, username='bob', auto_assign_new_items=False)
        frst = make_uploaded_log('frst-spor', log_type='FRST', content=FRST, forum_username='nobody')
        cache_analysis(frst, [RUN_LINE, DROPPER_LINE, INVOICE_LINE])
        spor = make_uploaded_log('spor-log', log_type='Spor', content=SPOR, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(spor)
        for upload in (frst, spor):
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)

    def get(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-spor'}).json()
        http.assert_not_called()
        request.assert_not_called()
        return body

    def test_hash_and_timeline_evidence_of_the_same_file(self):
        body = self.get()
        entries = body['correlations'][RUN_LINE]
        # The FILES line (its facts with its hash row: one entry), the timeline
        # and the Prefetch "loaded:" line.
        self.assertEqual({(entry['kind'], entry['upload_id']) for entry in entries},
                         {('evidence', 'spor-log'), ('file_info', 'spor-log'), ('mention', 'spor-log')})
        sha = next(entry for entry in entries if entry['kind'] == 'file_info')
        self.assertEqual((sha['sha256'], sha['log_type']), (EVIL_SHA, 'Spor'))
        # No line of the Spor log twice.
        lines = [entry['line_no'] for entry in entries]
        self.assertEqual(len(lines), len(set(lines)))
        evidence = next(entry for entry in entries if entry['kind'] == 'evidence')
        self.assertEqual(
            (evidence['line_no'], evidence['time'], evidence['sources'], evidence['file_status'], evidence['flags']),
            (no('[PF PCA BAM]'), '2026-11-18 07:48:46', 'PF PCA BAM', 'unsigned', []),
        )
        self.assertEqual(evidence['file'], 'evil.exe')
        # Running and being unsigned is no finding by itself.
        self.assertEqual(body['statuses'][RUN_LINE], '')

    def test_defender_detection_and_hash_with_its_name(self):
        body = self.get()
        entries = body['correlations'][DROPPER_LINE]
        detection = next(entry for entry in entries if entry['kind'] == 'detection')
        self.assertEqual((detection['detection'], detection['action'], detection['source'], detection['log_type']),
                         ('Trojan:Win32/Malgent!MSR', 'Quarantine', 'defender', 'Spor'))
        # The FILES line: its facts with the hash row's SHA-256 and detection.
        sha = next(entry for entry in entries if entry['kind'] == 'file_info')
        self.assertEqual((sha['sha256'], sha['detection']), (DROP_SHA, 'Trojan:Win32/Malgent!MSR'))
        self.assertEqual(body['statuses'][DROPPER_LINE], 'B')
        self.assertEqual(body['notes'][DROPPER_LINE], 'Trojan:Win32/Malgent!MSR · Spor')

    def test_flagged_evidence_gives_a_warning(self):
        body = self.get()
        (evidence,) = body['correlations'][INVOICE_LINE]
        self.assertEqual((evidence['kind'], evidence['severity'], evidence['flags']),
                         ('evidence', 'w', ['!double-extension']))
        self.assertEqual(body['statuses'][INVOICE_LINE], '!')
        self.assertEqual(body['notes'][INVOICE_LINE], '!double-extension · Spor')


class AutoCandidateTests(TestCase):
    def test_spor_rows_count_with_defender_malware_names_only(self):
        spor = make_uploaded_log('spor-auto', log_type='Spor', content=SPOR)
        UploadedLogFileHash.rebuild_for(spor)
        UploadedLogFileHash.objects.create(
            upload=spor, sha256='b2' * 32, line_no=1, anchor_line_no=1, path='C:\\x\\pua.exe',
            normalized_path='c:\\x\\pua.exe', detection='PUA:Win32/Presenoker', source='spor', auto=True,
        )
        found = centralbox_auto.auto_fresh_candidates([spor.pk])
        self.assertEqual(found, {
            DROP_SHA: (CentralboxAutoQueue.PRIORITY_SCANNER, 'Spor (Defender): Trojan:Win32/Malgent!MSR'),
        })
