"""The migration that replaces apply_to_block with match_unit: which rules
become block rules, and which of them are exact rules to look at."""

import importlib
import re

from django.test import SimpleTestCase

migration = importlib.import_module('fixlist.migrations.0118_rule_match_unit')


class RulesToMigrateTests(SimpleTestCase):
    def test_block_verdict_rules_become_block_rules(self):
        rows = [
            (1, 7, 'substring', 'evil', False, True),
            (2, 7, 'exact', '2026-11-20 [task] \\Evil', False, True),
            (3, 7, 'regex', 'x', False, False),          # no block verdict
            (4, 7, 'regex', 'y', True, True),            # whole-log: never a block
            (5, 7, 'script', 'result = True', False, True),  # scripts always test lines
        ]
        block_pks, exact_rows = migration.rules_to_migrate(rows)
        self.assertEqual(block_pks, [1, 2])
        self.assertEqual(exact_rows, [(2, 7, '2026-11-20 [task] \\Evil')])

    def test_an_exact_rule_becomes_a_regex_for_its_line_in_the_block(self):
        line = '2026-11-20 08:14:02 [task] \\Evil\\UpdateCheck (x) <==== !hidden-task'
        pattern = re.compile('(?m)' + migration.exact_as_block_regex(line))
        self.assertTrue(pattern.search(f'{line}\nprogram: C:\\x.exe'))
        self.assertTrue(pattern.search(f'other\n{line}'))
        self.assertFalse(pattern.search(f'{line} more\nprogram: C:\\x.exe'))

    def test_regexes_that_may_cross_lines(self):
        self.assertTrue(migration.regex_may_cross_lines(r'evil\s+svc'))
        self.assertTrue(migration.regex_may_cross_lines(r'a[^b]c'))
        self.assertFalse(migration.regex_may_cross_lines(r'evil.+svc'))
        self.assertFalse(migration.regex_may_cross_lines(r'C:\\Users\\.*\.exe'))
