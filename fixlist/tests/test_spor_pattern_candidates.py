"""spor_pattern_candidates: reading the covered FenrisHub rule ids of Spor's
autodetect.txt (tools/Spor is not part of this repository, so the rows are
written here)."""

from django.test import SimpleTestCase

from ..management.commands.spor_pattern_candidates import _EXTENSION_ID_RE, covered_ids


class CoveredIdsTests(SimpleTestCase):
    def test_ids_of_the_last_column(self):
        text = '\r\n'.join([
            '# kind, match, family, note, example, ids',
            '',
            'path\t*\\pcappstore\\\tPC App Store\tfolder\tC:\\PCAppStore\\x.exe\t14796,14807',
            'task\t=\\Real\\Launch\tReal\ttask\t\\Real\\Launch\t26793',
            'run\t=X\tF\tn\tX',              # no ids column
            'path\t*abc\tF\tn\tabc\t1,,x,2',  # junk is skipped
        ])
        self.assertEqual(covered_ids(text), {14796, 14807, 26793, 1, 2})

    def test_extension_ids_are_left_out(self):
        self.assertTrue(_EXTENSION_ID_RE.match('fgmeppijnhhafacemgoocgelcflipnfd'))
        self.assertTrue(_EXTENSION_ID_RE.match('twitchenhancedviewer@example.com'))
        self.assertFalse(_EXTENSION_ID_RE.match('C:\\ProgramData\\Chromnius'))
        self.assertFalse(_EXTENSION_ID_RE.match('snconor.vg'))
