"""Spor 0.6.0's USB worm scan (USB DRIVES section): Spor's <U+XXXX> markers
for characters that cannot be seen, the links within the log (a hidden
folder and its files, a worm's shortcut and the copy its arguments name,
autorun.inf and what it starts, SUMMARY lines), highlighting, and the match
with FRST's paths."""

from django.test import SimpleTestCase

from .. import log_highlighting as lh
from .. import spor_log
from ..correlations.spor_self import compute
from ..correlations.spor_source import build
from ..frst_extractors import decode_spor_chars, path_key
from ..log_types import LOG_TYPE_SPOR

NBSP = '\u00a0'
COPY = 'E:\\<U+00A0>\\IndexerVolumeGuid.exe'
COPY_SHA = 'c0' * 32
LNK_SHA = 'a1' * 32

SPOR_USB = '\n'.join([
    '==================== Spor 0.6.0 - forensic triage log ==============================================',
    'Created:   2026-11-20 14:56:39 UTC (local time 15:56, UTC+01:00)',
    'Options:   last 30 days, whitelist on, SHA256 hashes of files up to 500 MB, profile usb',
    'Times:     UTC',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '',
    '2026-11-20 14:57:06 [USB drives] E:\\<U+00A0>\\ => attributes hidden, system, folder <==== !invisible-char !hidden-system',
    f'2026-11-20 14:57:06 [timeline NEW] {COPY} => on USB drive E: STICK; attributes archive <==== !invisible-char',
    '2026-11-20 14:57:06 [USB drives] E:\\STICK.lnk => C:\\Windows\\System32\\cmd.exe <==== !usb-worm-lnk !disguised-icon',
    '2026-11-20 14:57:06 [USB drives] E:\\autorun.inf => starts <U+00A0>\\IndexerVolumeGuid.exe <==== !autorun',
    '',
    '==================== TIMELINE - last 30 days, oldest first =========================================',
    '(line: time [sources] file or event [status] => details <==== flags)',
    '',
    f'2026-11-20 14:57:06 [NEW] {COPY} => on USB drive E: STICK; attributes archive <==== !invisible-char',
    '2026-11-20 15:01:00 [USB] USB drive connected: SanDisk Cruzer Blade (serial 4C530001231115104383)',
    '',
    '==================== USB DRIVES - drives with hidden and invisible-named items, autorun.inf, shortcuts, USB device history ====',
    '',
    '--- Drives ---',
    '(line: drive => type; bus; device; label; file system; serial; size; listing)',
    '',
    'C: => type fixed; bus NVMe; label Windows; file system NTFS; serial 50636741; root and hidden root folders',
    'E: => type removable; bus USB; device SanDisk Cruzer Blade; label STICK; file system FAT32; serial 499602D2; deep',
    '',
    '--- Contents of E:\\ (STICK) ---',
    '(line: item [status] => attributes; created; modified; size; streams; details <==== flags)',
    '',
    'E:\\autorun.inf => attributes hidden, archive; created 2026-11-20 14:57:06; modified 2026-11-20 14:57:06; size 140 bytes',
    'E:\\Photos\\ => attributes folder; created 2026-01-02 10:00:00; modified 2026-01-02 10:00:00',
    'E:\\Photos\\cat.jpg => attributes archive; created 2026-01-02 10:00:00; modified 2026-01-02 10:00:00; size 1000 bytes',
    'E:\\STICK.lnk => attributes archive; created 2026-11-20 14:57:06; modified 2026-11-20 14:57:06; size 1122 bytes',
    'E:\\<U+00A0>\\ => attributes hidden, system, folder; created 2026-11-20 14:57:06; modified 2026-11-20 14:57:06'
    ' <==== !invisible-char !hidden-system',
    f'{COPY} => attributes archive; created 2026-11-20 14:57:06; modified 2026-10-28 20:12:19; size 360448 bytes'
    ' <==== !invisible-char',
    'E:\\<U+00A0>\\report.docx => attributes archive; created 2026-02-02 10:00:00; modified 2026-02-02 10:00:00;'
    ' size 5000 bytes <==== !invisible-char',
    '',
    '--- autorun.inf ---',
    '(line: file [status] => what <==== flags)',
    '',
    'E:\\autorun.inf => attributes hidden, archive; starts <U+00A0>\\IndexerVolumeGuid.exe <==== !autorun',
    '    inf: [autorun] open=<U+00A0>\\IndexerVolumeGuid.exe',
    '    inf: [autorun] shell\\open\\command=<U+00A0>\\IndexerVolumeGuid.exe',
    f'    target: {COPY} <==== !invisible-char',
    '',
    '--- Shortcuts on the drives ---',
    '(line: shortcut => target [status], args; icon; workdir; window; description; made on; volume; target from <==== flags)',
    '',
    'E:\\STICK.lnk => C:\\Windows\\System32\\cmd.exe, args /c start "" "<U+00A0>\\IndexerVolumeGuid.exe" & start explorer'
    ' "<U+00A0>"; icon %SystemRoot%\\system32\\SHELL32.dll,3 (folder icon); window minimized; made on desktop-x;'
    ' target from link info <==== !usb-worm-lnk !disguised-icon',
    '    worm signs: starts cmd.exe; points into hidden <U+00A0>; named like the drive label',
    f'    argument file: {COPY} <==== !invisible-char',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '(line: file => sha256, signature; version; amcache sha1; md5; size; created; modified)',
    '',
    f'{COPY} => {COPY_SHA}, signature valid; signer Microsoft Windows (catalog); file version 10.0.26100.1;'
    ' original name NOTEPAD.EXE; size 360448',
    f'E:\\STICK.lnk => {LNK_SHA}, size 1122',
    '',
    '==================== LEGEND ========================================================================',
    '',
    '==================== End of log. Scan took 1.0 s (usb 0.9 s) ======================================',
])
LINES = SPOR_USB.split('\n')


def no_of(prefix, start=0):
    """The line number of the first line (after `start`) that starts with `prefix` (stripped)."""
    return next(no for no, text in enumerate(LINES, start=1) if no > start and text.strip().startswith(prefix))


SECTION = no_of('==================== USB DRIVES')


class SporCharMarkerTests(SimpleTestCase):
    def test_markers_key_like_the_characters(self):
        self.assertEqual(path_key(COPY), path_key(f'E:\\{NBSP}\\IndexerVolumeGuid.exe'))
        self.assertEqual(path_key('C:\\a\\doc<RLO>fdp.exe'), path_key('C:\\a\\doc\u202efdp.exe'))
        self.assertEqual(path_key('E:\\x<U+3164>'), 'c:\\x\u3164')

    def test_a_decoded_blank_at_the_end_is_part_of_the_name(self):
        self.assertNotEqual(path_key('E:\\data<U+0020>'), path_key('E:\\data'))
        self.assertEqual(path_key(f'E:\\{NBSP}'), f'c:\\{NBSP}')
        self.assertEqual(path_key('  C:\\x.exe \r'), 'c:\\x.exe')

    def test_other_text_unchanged(self):
        self.assertEqual(decode_spor_chars('C:\\a <==== !x'), 'C:\\a <==== !x')
        self.assertEqual(decode_spor_chars('<U+FFFFFF>'), '<U+FFFFFF>')   # beyond Unicode: kept


class UsbMentionTests(SimpleTestCase):
    def mentions(self):
        return {(m.line_no, m.role): m for m in spor_log.iter_mentions(LINES) if m.section == spor_log.SECTION_USB}

    def test_hidden_folder_speaks_for_its_files(self):
        folder = self.mentions()[(no_of('E:\\<U+00A0>\\ =>', SECTION), 'item')]
        self.assertEqual(folder.path, 'E:\\<U+00A0>')
        self.assertTrue(folder.folder)

    def test_normal_folder_does_not(self):
        folder = self.mentions()[(no_of('E:\\Photos\\ =>', SECTION), 'item')]
        self.assertEqual(folder.path, 'E:\\Photos')
        self.assertFalse(folder.folder)

    def test_sub_lines_name_files(self):
        found = self.mentions()
        argument = found[(no_of('argument file:'), 'argument file')]
        self.assertEqual(argument.path, COPY)
        self.assertEqual(argument.parent, 'E:\\STICK.lnk')
        self.assertEqual(found[(no_of('target:'), 'target')].parent, 'E:\\autorun.inf')

    def test_drive_rows_are_no_paths(self):
        self.assertFalse(any(m.line_no == no_of('E: =>') for m in spor_log.iter_mentions(LINES)))


def linked(links, no):
    """{other line no: match} of a line's links."""
    return {entry['line_no']: entry.get('match') for entry in links.entries(no)}


class UsbSelfLinkTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.links = compute('usb', SPOR_USB)

    def test_shortcut_names_the_hidden_copy(self):
        lnk = no_of('E:\\STICK.lnk => C:', SECTION)
        files = no_of(COPY + ' => ' + COPY_SHA)
        self.assertEqual(linked(self.links, lnk).get(files), 'detail')
        self.assertIn(lnk, linked(self.links, files))   # named_by, the other way round

    def test_autorun_names_what_it_starts(self):
        autorun = no_of('E:\\autorun.inf => attributes hidden, archive; starts')
        self.assertEqual(linked(self.links, autorun).get(no_of(COPY + ' => ' + COPY_SHA)), 'detail')

    def test_hidden_folder_and_its_files(self):
        folder = no_of('E:\\<U+00A0>\\ =>', SECTION)
        inside = linked(self.links, folder)
        self.assertEqual(inside.get(no_of(COPY + ' => attributes')), 'inside')
        self.assertEqual(inside.get(no_of('E:\\<U+00A0>\\report.docx')), 'inside')
        self.assertIn(folder, linked(self.links, no_of(COPY + ' => attributes')))

    def test_summary_lines_find_their_section_lines(self):
        summary_folder = no_of('2026-11-20 14:57:06 [USB drives] E:\\<U+00A0>\\')
        self.assertIn(no_of('E:\\<U+00A0>\\ =>', SECTION), linked(self.links, summary_folder))
        summary_lnk = no_of('2026-11-20 14:57:06 [USB drives] E:\\STICK.lnk')
        self.assertIn(no_of('E:\\STICK.lnk => C:', SECTION), linked(self.links, summary_lnk))
        self.assertEqual(self.links.codes[str(summary_lnk)], '!')

    def test_drive_rows_link_nothing(self):
        self.assertEqual(self.links.entries(no_of('C: =>')), [])
        self.assertEqual(self.links.entries(no_of('E: =>')), [])

    def test_frst_path_with_the_real_character_finds_the_copy(self):
        index = build('usb', LINES).index
        found = index[path_key(f'E:\\{NBSP}\\IndexerVolumeGuid.exe')]
        self.assertIn('file_info', {entry['kind'] for entry in found})


class UsbHighlightTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.result = lh.highlight_log(LOG_TYPE_SPOR, SPOR_USB)
        cls.lines = {line.no: line for section in cls.result.sections
                     for line in ([section.header] if section.header else []) + section.lines}

    def test_summary_box_rates_usb_lines_with_their_flags(self):
        items = {item.line_no: item for item in self.result.summary}
        lnk = items[no_of('2026-11-20 14:57:06 [USB drives] E:\\STICK.lnk')]
        self.assertEqual(lnk.severity, 'w')
        self.assertIn('!usb-worm-lnk', lnk.action)

    def test_paths_with_markers_are_marked(self):
        html = lh._line_html(self.lines[no_of(COPY + ' => attributes')])
        self.assertIn('class="hl-path hl-oddchar"', html)
        self.assertIn('&lt;U+00A0&gt;', html)
        plain = lh._line_html(self.lines[no_of('E:\\Photos\\cat.jpg')])
        self.assertNotIn('hl-oddchar', plain)

    def test_flags_and_sub_line_keys(self):
        tokens = self.lines[no_of('argument file:')].tokens
        self.assertIn(('hl-key', 'argument file:'), tokens)
        self.assertIn(('hl-path', COPY), tokens)
        self.assertIn(('hl-sev-w', '<==== !invisible-char'), tokens)
