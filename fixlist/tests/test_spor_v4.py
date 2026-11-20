"""Spor 0.3.0 shapes (fixlist/tests/spor_sample.SPOR_V4): new flags with the
hint tier (!renamed-program), RUNNING PROCESSES with "module:" lines, a
runtime launcher's "script:" lines, the 4688 / SYSMON / PROC sources, the DNS
categories, and statuses never taken from details. Parser, highlighter,
correlation severity and the automatic centralbox candidates."""

from django.test import SimpleTestCase

from .. import spor_log
from ..case_correlations import evidence_severity, evidence_text, mention_text
from ..file_hashes import extract_file_hashes
from ..log_highlighting import highlight_log, iter_lines
from .spor_sample import (
    CHILD, LAUNCHER, LINES_V4, LURE, PADDED, SCRIPT_DOT, SCRIPT_RPA, SIDE_DETAILS, SIDE_DLL, SIDE_HOST, SPOR_V4,
)


def no(needle, start=1):
    """1-based number of the first SPOR_V4 line from `start` containing `needle`."""
    for index in range(start - 1, len(LINES_V4)):
        if needle in LINES_V4[index]:
            return index + 1
    raise AssertionError(f'{needle!r} not in fixture')


def line(needle, start=1):
    return LINES_V4[no(needle, start) - 1]


PROCESSES_LINE = no('==================== RUNNING PROCESSES')


class FlagTierTests(SimpleTestCase):
    def test_tiers(self):
        self.assertEqual([spor_log.flag_tier(flag) for flag in ('!lolbin', '!renamed-program', '!sideload', '!padded')],
                         ['quiet', 'hint', 'strong', 'strong'])

    def test_strong_and_loud_flags(self):
        item = spor_log.split_item(line(f'[NEW] {SIDE_HOST}'))
        self.assertEqual(item.flags, ['!motw-removed', '!renamed-program'])
        self.assertEqual(item.strong_flags, ['!motw-removed'])
        # loud = not quiet: hints still count where files are looked up
        self.assertEqual(item.loud_flags, ['!motw-removed', '!renamed-program'])

    def test_a_hint_alone_rates_info(self):
        self.assertEqual(evidence_severity(['!renamed-program'], ''), 'i')
        self.assertEqual(evidence_severity(['!renamed-program', '!sideload'], ''), 'w')
        self.assertEqual(evidence_severity(['!lolbin'], ''), '')
        self.assertEqual(evidence_severity(['!renamed-program'], 'invalid signature'), 'w')

    def test_texts_name_hints_too(self):
        self.assertEqual(mention_text({'flags': ['!lolbin', '!renamed-program']}), '!renamed-program')
        self.assertEqual(evidence_text({'flags': ['!renamed-program']}), '!renamed-program')


class ShapeTests(SimpleTestCase):
    def test_sections(self):
        titles = [title for title, _start, _end in spor_log.iter_sections(LINES_V4)]
        self.assertIn('RUNNING PROCESSES', titles)
        self.assertEqual(titles[0], 'Spor 0.3.0')

    def test_process_line(self):
        item = spor_log.split_item(line(f'[4321] {SIDE_HOST}'))
        self.assertEqual((item.time, item.tags, item.item, item.status, item.flags),
                         ('2026-11-20 03:33:53', '4321', SIDE_HOST, '', ['!proxy-exec', '!renamed-program']))
        self.assertTrue(item.rest.startswith('parent cmd.exe (4300) < pid 4200 (exited); command line'))

    def test_a_status_in_the_details_is_not_the_items(self):
        # a signed program's command line ends in "[unsigned]": not its status
        item = spor_log.split_item(line(f'[5557] {CHILD}'))
        self.assertEqual((item.item, item.status), (CHILD, ''))
        # the target's status still counts ("[run] X => C:\\a.exe [unsigned], ...")
        item = spor_log.split_item('2026-01-01 00:00:00 [run] HKCU\\...\\Run\\X => C:\\x\\a.exe [unsigned], value X')
        self.assertEqual(item.status, 'unsigned')
        item = spor_log.split_item(f'2026-11-20 03:33:50 [NEW] {SIDE_HOST} => side-loads providers.dll [unsigned]')
        self.assertEqual(item.status, '')
        # a target with ", " in its path, or quoted, keeps its status
        item = spor_log.split_item('2026-01-01 00:00:00 [run] HKCU\\...\\Run\\X => C:\\Program Files\\Foo, Inc\\a.exe [unsigned],'
                                   ' value X')
        self.assertEqual(item.status, 'unsigned')
        item = spor_log.split_item('2026-01-01 00:00:00 [task] \\Upd => "C:\\Users\\Bob\\x.exe" /s [unsigned]')
        self.assertEqual(item.status, 'unsigned')
        # a status after the details start is not the target's
        item = spor_log.split_item('2026-01-01 00:00:00 [run] HKCU\\...\\Run\\X => C:\\x\\a.exe, arguments -a; note [gone]')
        self.assertEqual(item.status, '')

    def test_modules_are_mentions_of_their_own(self):
        mentions = [mention for mention in spor_log.iter_mentions(LINES_V4) if mention.path == SIDE_DLL]
        by_section = {mention.section: mention for mention in mentions}
        self.assertEqual(set(by_section), {'PERSISTENCE', 'RUNNING PROCESSES'})
        process = by_section['RUNNING PROCESSES']
        self.assertEqual((process.role, process.parent, process.status, process.flags, process.time, process.tags),
                         ('module', SIDE_HOST, 'unsigned', ['!sideload'], '2026-11-20 03:33:53', '4321'))
        # under a Run value: loaded by its program, not by the registry entry
        self.assertEqual((by_section['PERSISTENCE'].role, by_section['PERSISTENCE'].parent), ('module', SIDE_HOST))

    def test_a_process_line_points_at_nothing(self):
        # the rest starts with "parent": no path target, the parents are names
        targets = [mention for mention in spor_log.iter_mentions(LINES_V4)
                   if mention.role == 'target' and mention.section == 'RUNNING PROCESSES']
        self.assertEqual(targets, [])
        child = next(mention for mention in spor_log.iter_mentions(LINES_V4) if mention.path == CHILD)
        self.assertEqual(child.extra, [['modules', 'no access']])

    def test_script_lines_are_timeline_evidence_at_their_own_time(self):
        evidence = {entry.path: entry for entry in spor_log.iter_timeline_evidence(LINES_V4)}
        rpa = evidence[SCRIPT_RPA]
        self.assertEqual((rpa.line_no, rpa.time, rpa.sources, rpa.details, rpa.flags),
                         (no(f'script: {SCRIPT_RPA}'), '2026-11-20 03:33:19', 'NEW TSK', '2048 bytes; script of Setup.exe', []))
        self.assertEqual(evidence[SCRIPT_DOT].details, '341 bytes; hidden; script of Setup.exe')
        self.assertEqual(evidence[LAUNCHER].flags, ['!runtime-loader'])
        self.assertEqual(evidence[PADDED].details, 'padded: 324 MB of byte 0x00')
        # one evidence entry per file (its first line); the host's later 4688 line is a timeline item
        self.assertEqual(evidence[SIDE_HOST].flags, ['!motw-removed', '!renamed-program'])
        items = [item for _no, item in spor_log.iter_timeline_items(LINES_V4) if item.tags == '4688']
        self.assertEqual([(item.item, item.flags) for item in items], [(SIDE_HOST, ['!proxy-exec'])])

    def test_a_script_line_without_its_own_time(self):
        content = SPOR_V4.replace(f'    script: {SCRIPT_RPA} => 2026-11-20 03:33:19; 2048 bytes',
                                  f'    script: {SCRIPT_RPA} => 2048 bytes; hidden file of the game')
        evidence = {entry.path: entry for entry in spor_log.iter_timeline_evidence(content.split('\n'))}
        self.assertEqual((evidence[SCRIPT_RPA].time, evidence[SCRIPT_RPA].details),
                         ('2026-11-20 03:33:38', '2048 bytes; hidden file of the game; script of Setup.exe'))

    def test_timeline_items_include_scripts_and_new_sources(self):
        found = {(item.item, item.time, item.tags) for _no, item in spor_log.iter_timeline_items(LINES_V4)}
        self.assertIn((SCRIPT_RPA, '2026-11-20 03:33:19', 'NEW TSK'), found)
        self.assertIn((SIDE_HOST, '2026-11-20 03:33:53', '4688'), found)
        self.assertIn(('C:\\Windows\\System32\\cmd.exe', '2026-11-20 03:33:52', 'SYSMON'), found)

    def test_dns_categories_have_no_path(self):
        self.assertFalse([mention for mention in spor_log.iter_mentions(LINES_V4) if 'example.click' in mention.path])


class HighlightTests(SimpleTestCase):
    def setUp(self):
        self.result = highlight_log('Spor', SPOR_V4)
        self.lines = {item.no: item.tokens for item in iter_lines(self.result)}

    def test_a_hint_alone_is_in_the_info_colour(self):
        self.assertIn(('hl-sev-hint', '<==== !renamed-program'), self.lines[no(f'[NEW] {LURE}')])

    def test_mixed_tiers_colour_each_flag(self):
        tokens = self.lines[no(f'[NEW] {SIDE_HOST}')]
        self.assertIn(('hl-sev-w', '<===='), tokens)
        self.assertIn(('hl-sev-w', '!motw-removed'), tokens)
        self.assertIn(('hl-sev-hint', '!renamed-program'), tokens)

    def test_one_tier_stays_one_token(self):
        self.assertIn(('hl-sev-w', '<==== !motw-removed !sideload'), self.lines[no(f'[NEW] {SIDE_DLL}')])
        self.assertIn(('hl-sev-g', '<==== !lolbin'), self.lines[no('[SYSMON]')])

    def test_new_sections_sources_and_sub_lines(self):
        self.assertIn(('hl-accent', '[4321]'), self.lines[no(f'[4321] {SIDE_HOST}')])
        self.assertIn(('hl-accent', '[SYSMON]'), self.lines[no('[SYSMON]')])
        self.assertIn(('hl-accent', '[4688]'), self.lines[no(f'[4688] {SIDE_HOST}')])
        self.assertIn(('hl-accent', '[victim ID in name]'), self.lines[no('[victim ID in name]')])
        module = self.lines[no(f'    module: {SIDE_DLL}')]
        self.assertIn(('hl-sev-w', '<==== !sideload'), module)
        self.assertIn(('hl-sev-w', '[unsigned]'), [(cls, text) for cls, text in module if text == '[unsigned]'])

    def test_legend_sources_and_hint_flag(self):
        self.assertIn(('hl-key', 'SYSMON'), self.lines[no('    SYSMON  ')])
        self.assertIn(('hl-key', '4688'), self.lines[no('    4688    ')])
        self.assertIn(('hl-key', '!renamed-program'), self.lines[no('    !renamed-program ')])

    def test_summary_box_severities(self):
        # strong flags warn; the hint next to them does not change that
        items = [(item.line_no, item.severity, item.name) for item in self.result.summary]
        self.assertEqual(items[:3], [
            (no('[timeline NEW TSK]'), 'w', LAUNCHER),
            (no(f'[timeline NEW] {SIDE_HOST}'), 'w', SIDE_HOST),
            (no(f'[timeline NEW] {SIDE_DLL}'), 'w', SIDE_DLL),
        ])

    def test_summary_box_hint_alone_is_info(self):
        content = SPOR_V4.replace(' <==== !motw-removed !renamed-program', ' <==== !renamed-program', 1)
        result = highlight_log('Spor', content)
        host = next(item for item in result.summary if item.name == SIDE_HOST)
        self.assertEqual(host.severity, 'i')


class FileHashTests(SimpleTestCase):
    def test_flagged_files_and_hints_are_checked_by_themselves(self):
        auto = {row.path for row in extract_file_hashes('Spor', SPOR_V4) if row.auto}
        # the side-loading pair (strong flags, SUMMARY) and the lure-named program with a hint only
        self.assertTrue({SIDE_HOST, SIDE_DLL, LURE} <= auto, auto)

    def test_side_details_name_no_paths(self):
        # "loaded by x.exe (signed by ...)" names the program, not a path: nothing extra is looked up there
        self.assertNotIn('\\', SIDE_DETAILS)


# Spor 0.4.0 Autodetect: a SUMMARY line naming a known malware family.
AUTODETECT_PATH = 'C:\\Users\\Bob\\AppData\\Local\\Temp\\tmp-20656-vmkfjqTWAOFi\\ehyISWlPN.exe'
AUTODETECT_LINE = (f'2026-11-20 03:33:52 [Autodetect] {AUTODETECT_PATH} => RenLoader: payload in a Node.js tmp folder'
                   ' <==== !known-malware')


def with_autodetect(content=SPOR_V4):
    """SPOR_V4 with an Autodetect line at the end of its SUMMARY."""
    marker = '2026-11-20 03:33:50 [Files] DLL side-loading:'
    lines = content.split('\n')
    index = next(i for i, text in enumerate(lines) if text.startswith(marker))
    return '\n'.join(lines[:index + 1] + [AUTODETECT_LINE] + lines[index + 1:])


class AutodetectTests(SimpleTestCase):
    def test_the_known_malware_flag_is_its_own_tier(self):
        self.assertEqual(spor_log.flag_tier('!known-malware'), 'malware')
        self.assertEqual(spor_log.worst_tier(['!sideload', '!known-malware', '!lolbin']), 'malware')
        item = spor_log.split_item(AUTODETECT_LINE)
        self.assertEqual((item.item, item.flags), (AUTODETECT_PATH, ['!known-malware']))
        # it is strong too: everything that looks at strong flags sees it
        self.assertEqual(item.strong_flags, ['!known-malware'])
        self.assertEqual(item.malware_flags, ['!known-malware'])

    def test_correlation_severity_is_malware(self):
        self.assertEqual(evidence_severity(['!known-malware'], ''), 'b')
        self.assertEqual(evidence_severity(['!renamed-program', '!known-malware'], 'invalid signature'), 'b')

    def test_summary_box_rates_it_malware(self):
        content = with_autodetect()
        result = highlight_log('Spor', content)
        item = next(item for item in result.summary if item.name == AUTODETECT_PATH)
        self.assertEqual(item.severity, 'b')
        # the heuristic lines keep their warning
        self.assertEqual(next(item for item in result.summary if item.name == SIDE_DLL).severity, 'w')

    def test_a_timeline_line_carries_it_to_the_correlations(self):
        # Spor 0.4.0 marks the file's own timeline line; correlations read the timeline, not SUMMARY
        timeline_line = (f'2026-11-20 03:33:52 [PROC NEW] {AUTODETECT_PATH} => known malware RenLoader: payload in a'
                         ' Node.js tmp folder; zone 0; running, pid 7716 <==== !motw-removed !known-malware')
        lines = SPOR_V4.split('\n')
        index = lines.index('(line: time [sources] file or event [status] => details <==== flags)') + 2
        content = '\n'.join(lines[:index] + [timeline_line] + lines[index:])
        evidence = {entry.path: entry for entry in spor_log.iter_timeline_evidence(content.split('\n'))}[AUTODETECT_PATH]
        self.assertEqual(evidence.flags, ['!motw-removed', '!known-malware'])
        self.assertTrue(evidence.details.startswith('known malware RenLoader: '))
        self.assertEqual(evidence_severity(evidence.flags, evidence.file_status), 'b')

    def test_a_timeline_line_in_the_summary_rates_malware(self):
        summary_line = (f'2026-11-20 03:33:52 [timeline PROC NEW] {AUTODETECT_PATH} => known malware RenLoader: payload'
                        ' <==== !motw-removed !known-malware')
        result = highlight_log('Spor', with_autodetect().replace(AUTODETECT_LINE, summary_line))
        item = next(item for item in result.summary if item.name == AUTODETECT_PATH)
        self.assertEqual(item.severity, 'b')

    def test_the_flag_is_painted_as_malware(self):
        content = with_autodetect()
        result = highlight_log('Spor', content)
        number = content.split('\n').index(AUTODETECT_LINE) + 1
        tokens = {item.no: item.tokens for item in iter_lines(result)}[number]
        self.assertIn(('hl-sev-b', '<==== !known-malware'), tokens)
