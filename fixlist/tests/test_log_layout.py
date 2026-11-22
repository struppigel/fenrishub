"""log_layout.analyzed_lines: the analyzer's line sequence plus log page line numbers."""

import random

from django.test import SimpleTestCase

from ..log_layout import analyzed_lines, layout
from .spor_sample import FRST_SEARCH, SPOR
from .test_correlation_keys import ADDITION

# Every boundary str.splitlines() knows, plus a BOM and other whitespace.
_BOUNDARIES = ['\n', '\r\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029']
_ALPHABET = _BOUNDARIES + [' ', '\t', '\ufeff', '\xa0', 'a', 'b', 'C:\\x.exe', '    path: y']


def _old_loop(text):
    """The analyzer's loop before log_layout existed."""
    return [raw.strip() for raw in (text or '').splitlines() if raw.strip()]


class AnalyzedLinesTests(SimpleTestCase):
    def test_same_lines_as_the_old_analyzer_loop_for_every_boundary(self):
        for boundary in _BOUNDARIES:
            text = f'one{boundary}two{boundary}{boundary}  three  {boundary}'
            with self.subTest(boundary=repr(boundary)):
                self.assertEqual([item.text for item in analyzed_lines(text)], _old_loop(text))

    def test_same_lines_as_the_old_analyzer_loop_on_random_text(self):
        rng = random.Random(1234)
        for _ in range(2000):
            text = ''.join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, 30)))
            self.assertEqual([item.text for item in analyzed_lines(text)], _old_loop(text), repr(text))

    def test_line_numbers_count_split_on_newline_from_one(self):
        text = 'first\n\n  second\r\nthird\rfourth\n'
        self.assertEqual(
            [(item.index, item.line_no, item.text) for item in analyzed_lines(text)],
            [(0, 1, 'first'), (1, 3, 'second'), (2, 4, 'third'), (3, 4, 'fourth')],
        )

    def test_raw_keeps_indentation(self):
        [item, sub] = analyzed_lines('item => x\n    path: C:\\a.exe\r\n')
        self.assertEqual(sub.raw, '    path: C:\\a.exe')
        self.assertEqual(sub.text, 'path: C:\\a.exe')
        self.assertEqual(item.raw, 'item => x')

    def test_empty_and_none(self):
        self.assertEqual(analyzed_lines(''), [])
        self.assertEqual(analyzed_lines(None), [])
        self.assertEqual(analyzed_lines('\n \n\t\n'), [])


def _blocks(text, log_type=None):
    """The analyzed lines grouped by block, in order."""
    lines = analyzed_lines(text)
    result = layout(text, log_type)
    groups = {}
    for item in lines:
        groups.setdefault(result.block_of[item.index], []).append(item.text)
    return list(groups.values())


def _block_with(text, needle, log_type=None):
    return next(group for group in _blocks(text, log_type) if any(needle in line for line in group))


def _section_title(text, needle, log_type=None):
    result = layout(text, log_type)
    for item in analyzed_lines(text):
        if needle in item.text:
            return result.sections[result.section_of[item.index]][0]
    raise AssertionError(needle)


class LayoutTests(SimpleTestCase):
    def test_one_entry_per_analyzed_line(self):
        for text, log_type in ((SPOR, 'Spor'), (FRST_SEARCH, 'FRST Search'), (ADDITION, 'Addition')):
            with self.subTest(log_type=log_type):
                result = layout(text, log_type)
                self.assertEqual(len(result.block_of), len(analyzed_lines(text)))
                self.assertEqual(len(result.section_of), len(result.block_of))

    def test_spor_item_and_its_sub_lines_are_one_block(self):
        block = _block_with(SPOR, 'SRUM first activity', 'Spor')
        self.assertEqual(len(block), 3)
        self.assertTrue(all(line.startswith('path: ') for line in block[1:]))
        loaded = _block_with(SPOR, 'consent.exe', 'Spor')
        self.assertEqual(len(loaded), 2)
        self.assertTrue(loaded[1].startswith('loaded: '))

    def test_other_spor_lines_are_blocks_of_their_own(self):
        block = _block_with(SPOR, 'Defender detection history deleted', 'Spor')
        self.assertEqual(len(block), 1)

    def test_indented_lines_are_grouped_only_in_spor_logs(self):
        text = 'item => x\n' + r'    path: C:\a.exe' + '\n'
        self.assertEqual(_blocks(text, 'Spor'), [['item => x', r'path: C:\a.exe']])
        self.assertEqual(_blocks(text, 'FRST'), [['item => x'], [r'path: C:\a.exe']])

    def test_spor_sections(self):
        self.assertEqual(_section_title(SPOR, 'Defender detection history deleted', 'Spor'), 'TIMELINE')
        self.assertEqual(_section_title(SPOR, 'consent.exe', 'Spor'), 'PREFETCH')
        self.assertEqual(_section_title(SPOR, 'Computer:', 'Spor'), 'Spor 0.1.0')

    def test_frst_search_path_and_meta_line_are_one_block(self):
        block = _block_with(FRST_SEARCH, '389700D32DB7ECC74AF1DCF801F05A05')
        self.assertEqual(len(block), 2)
        self.assertEqual(_block_with(FRST_SEARCH, 'File:'), ['File:'])
        self.assertEqual(_section_title(FRST_SEARCH, '389700D32DB7ECC74AF1DCF801F05A05'), 'Search Files: "evil"')

    def test_frst_search_folder_lines_are_not_joined(self):
        block = _block_with(FRST_SEARCH, r'_____ C:\Users\Bob\AppData\Roaming\evil')
        self.assertEqual(len(block), 1)

    def test_addition_event_entries(self):
        first = _block_with(ADDITION, 'TimeCreated : 11/4/2026 4:07:39 AM')
        self.assertEqual(first[0], 'TimeCreated : 11/4/2026 4:07:39 AM')
        self.assertIn('Detection Origin: Local machine', first)
        # The wrapped path piece belongs to its event too.
        self.assertIn(r's1; file:_C:\Windows\Installer\1284762.msi', first)
        second = _block_with(ADDITION, 'TimeCreated : 11/4/2026 4:07:40 AM')
        self.assertNotEqual(first, second)
        self.assertEqual(_block_with(ADDITION, 'Windows Defender:'), ['Windows Defender:'])
        self.assertEqual(_section_title(ADDITION, 'Severity: Severe'), 'Event log errors:')

    def test_addition_sub_section_without_a_blank_line(self):
        self.assertEqual(_block_with(ADDITION, 'CodeIntegrity:'), ['CodeIntegrity:'])
        entry = _block_with(ADDITION, 'Date: 2026-11-13 11:18:31')
        self.assertEqual(entry, ['Date: 2026-11-13 11:18:31', r'Path: file:_C:\Never\counted.exe'])

    def test_error_entries_with_description(self):
        text = '\n'.join([
            '==================== Event log errors: ========================',
            'Application errors:',
            '==================',
            'Error: (11/20/2026 10:15:02 AM) (Source: Application Error) (EventID: 1000) (User: )',
            'Description: Faulting application name: evil.exe',
            'Error: (11/20/2026 10:16:02 AM) (Source: Application Error) (EventID: 1000) (User: )',
            'Description: Faulting application name: other.exe',
            '',
            'Warning: (11/20/2026 10:17:02 AM) (Source: X) (EventID: 1) (User: )',
            'Description: something',
        ])
        self.assertEqual(len(_block_with(text, 'evil.exe')), 2)
        self.assertEqual(len(_block_with(text, 'other.exe')), 2)
        self.assertNotIn('Description: Faulting application name: other.exe', _block_with(text, 'evil.exe'))
        self.assertEqual(len(_block_with(text, 'something')), 2)

    def test_event_grouping_only_in_event_log_sections(self):
        text = '\n'.join([
            '==================== Registry (Whitelisted) ===================',
            'Error: (11/20/2026 10:15:02 AM) not an event',
            'Description: also not',
        ])
        self.assertEqual(len(_block_with(text, 'not an event')), 1)

    def test_end_banner_closes_its_section(self):
        text = '\n'.join([
            '==================== Processes (Whitelisted) =================',
            'process line',
            '==================== End of FRST.txt ========================',
            'appended text',
        ])
        self.assertEqual(_section_title(text, 'process line'), 'Processes (Whitelisted)')
        self.assertEqual(_section_title(text, 'End of FRST'), 'Processes (Whitelisted)')
        self.assertEqual(_section_title(text, 'appended text'), '')
        result = layout(text)
        self.assertNotEqual(result.section_of[1], result.section_of[3])

    def test_lines_before_the_first_banner(self):
        result = layout('header line\n==================== A ====\nline')
        self.assertEqual(result.sections, [('', 0), ('A', 1)])
        self.assertEqual(result.section_of, [0, 1, 1])
