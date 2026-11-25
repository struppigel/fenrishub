"""Normal Spor logs end the lines its aggressive whitelist (-aggressive, a
command line trial) would hide with " ~". FenrisHub reads such a line as if
the mark were not there: parsing, Spor entries and paths, rules made from the
line and rule matches; the analysis payload keeps the line as the log has it."""

from django.test import SimpleTestCase

from .. import frst_extractors as ex
from .. import spor_extractors
from .. import spor_log as sl
from ..analyzer import analyze_log_text, parse_rule_for_line
from ..models import ClassificationRule
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase
from .spor7_sample import PROGRAM, RUN_BLOCK, SHA, SPOR7

B = ClassificationRule.STATUS_MALWARE
C = ClassificationRule.STATUS_CLEAN
MARK = sl.AGGR_MARK
FILES_LINE = f'{PROGRAM} => {SHA.upper()}, signature unsigned'


def marked(text, *lines):
    """`text` with the mark at the end of each of `lines`."""
    for line in lines:
        assert line in text, line
        text = text.replace(line + '\n', line + MARK + '\n', 1)
    return text


class StripTests(SimpleTestCase):
    def test_the_mark_at_the_end_goes(self):
        self.assertEqual(sl.strip_aggr_mark('C:\\a\\x.exe ~'), 'C:\\a\\x.exe')
        self.assertEqual(sl.strip_aggr_mark('C:\\a\\x.exe ~\r'), 'C:\\a\\x.exe\r')
        self.assertEqual(sl.strip_aggr_mark('x <==== !lolbin ~'), 'x <==== !lolbin')
        self.assertEqual(sl.strip_aggr_mark('a ~\n    program: b ~\nc'), 'a\n    program: b\nc')

    def test_anything_else_stays(self):
        for text in ('C:\\PROGRA~1\\x.exe', 'C:\\a\\x.txt~', 'C:\\a ~\\x.exe', '', None):
            self.assertEqual(sl.strip_aggr_mark(text), text)

    def test_an_item_line_splits_the_same(self):
        line = '2026-11-21 08:38:17 [run] HKU\\Bob\\Software\\Run\\Updater [unsigned] => x <==== !lolbin'
        plain, mark = sl.split_item(line), sl.split_item(line + MARK)
        self.assertEqual((mark.time, mark.item, mark.status, mark.rest, mark.flags),
                         (plain.time, plain.item, plain.status, plain.rest, plain.flags))

    def test_spor_entries_and_paths_are_the_same(self):
        block = [RUN_BLOCK[0] + MARK] + RUN_BLOCK[1:]
        self.assertEqual(spor_extractors.parse_block(block), spor_extractors.parse_block(RUN_BLOCK))
        loaded = f'    loaded: {PROGRAM} [gone]'
        self.assertEqual(spor_extractors.line_path(loaded + MARK, sub_line=True), PROGRAM)
        self.assertEqual(spor_extractors.line_path(FILES_LINE + MARK), PROGRAM)

    def test_files_lines_are_the_same(self):
        plain = list(sl.iter_files(SPOR7.split('\n')))
        mark = list(sl.iter_files(marked(SPOR7, FILES_LINE).split('\n')))
        self.assertTrue(plain)
        self.assertEqual(mark, plain)


class RuleFromAMarkedLineTests(SimpleTestCase):
    def test_a_marked_line_makes_the_rule_of_the_unmarked_line(self):
        for line in (FILES_LINE, RUN_BLOCK[0]):
            self.assertEqual(parse_rule_for_line(line + MARK, B, log_type='Spor'),
                             parse_rule_for_line(line, B, log_type='Spor'))
        block = '\n'.join([RUN_BLOCK[0] + MARK] + RUN_BLOCK[1:])
        self.assertEqual(parse_rule_for_line(RUN_BLOCK[0] + MARK, B, log_type='Spor', block_text=block),
                         parse_rule_for_line(RUN_BLOCK[0], B, log_type='Spor', block_text='\n'.join(RUN_BLOCK)))


class MarkedAnalysisTests(LogAnalyzerApiBaseTestCase):
    def setUp(self):
        super().setUp()
        ClassificationRule.objects.create(
            owner=self.user, status=B, match_type=ClassificationRule.MATCH_FILEPATH, source_text=PROGRAM,
            filepath=PROGRAM, normalized_filepath=ex.path_key(PROGRAM), all_log_types=True,
        )
        ClassificationRule.objects.create(
            owner=self.user, status=C, match_type=ClassificationRule.MATCH_EXACT,
            source_text='2026-11-21 08:08:57 [RUN] Run dialog: joy.cpl', all_log_types=True,
        )

    def test_marked_lines_get_the_same_verdicts(self):
        lines = ['2026-11-21 08:08:57 [RUN] Run dialog: joy.cpl', FILES_LINE]
        plain = analyze_log_text(SPOR7, log_type='Spor')['lines']
        mark = analyze_log_text(marked(SPOR7, *lines), log_type='Spor')['lines']
        self.assertEqual([e['dominant_status'] for e in mark], [e['dominant_status'] for e in plain])
        statuses = {e['line']: e['dominant_status'] for e in mark}
        self.assertEqual(statuses['2026-11-21 08:08:57 [RUN] Run dialog: joy.cpl' + MARK], C)
        self.assertEqual(statuses[FILES_LINE + MARK], B)   # the payload keeps the line as the log has it

    def test_the_path_highlight_stays_in_place(self):
        mark = analyze_log_text(marked(SPOR7, FILES_LINE), log_type='Spor')['lines']
        entry = next(e for e in mark if e['line'] == FILES_LINE + MARK)
        self.assertEqual([(s['start'], s['end']) for s in entry['highlights']], [(0, len(PROGRAM))])
