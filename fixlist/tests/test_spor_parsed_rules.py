"""Setting a status on a Spor block in the analyzer: the review and the save
turn it into one parsed block rule of its Spor type (scope Spor), whichever
line of the block was chosen; other logs are unchanged."""

import json

from django.urls import reverse

from ..analyzer import analyze_log_text, convert_exact_rules_to_parsed, parse_rule_line, reparse_rules
from ..models import ClassificationRule, LogTypeBadge
from ..rule_utils import _build_pending_rule_preview, _persist_selected_pending_rules
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase
from . import spor7_sample as sample

B = ClassificationRule.STATUS_MALWARE
BLOCK = ClassificationRule.MATCH_UNIT_BLOCK
RUN_TEXT = '\n'.join(line.strip() for line in sample.RUN_BLOCK)
SERVICE = r"S2 AVP; C:\Program Files\Kaspersky\avp.exe [123 2026-01-01] (Kaspersky -> Kaspersky)"


class SporParsedRuleTests(LogAnalyzerApiBaseTestCase):
    def persist(self, line, log_type='Spor', **change):
        _persist_selected_pending_rules(
            raw_pending_changes=[{'id': 'c1', 'line': line, 'new_status': B, 'original_status': '?', **change}],
            raw_selected_ids=['c1'], raw_conflict_resolutions=[], username=self.user.username,
            source_prefix='test', owner=self.user, log_type=log_type,
        )
        return ClassificationRule.objects.get(owner=self.user)

    def test_the_review_shows_a_parsed_block_rule(self):
        preview = _build_pending_rule_preview(
            [{'id': 'c1', 'line': sample.RUN_BLOCK[0], 'original_status': '?', 'new_status': B, 'order': 1,
              'description': None, 'tag_ids': None, 'log_scope': None, 'block_text': RUN_TEXT}],
            self.user.username, self.user, log_type='Spor',
        )
        [change] = preview['rule_changes']
        self.assertEqual((change['match_type'], change['match_unit'], change['entry_type']), ('parsed', BLOCK, 'spor_run'))
        self.assertEqual(change['source_text'], RUN_TEXT)
        self.assertEqual(change['log_types'], ['Spor'])

    def test_saving_makes_the_rule_and_it_matches_the_block_in_another_log(self):
        rule = self.persist(sample.RUN_BLOCK[0], block_text=RUN_TEXT)
        self.assertEqual((rule.match_type, rule.match_unit, rule.entry_type, rule.name), ('parsed', BLOCK, 'spor_run', 'Updater'))
        self.assertEqual((rule.all_log_types, rule.log_types), (False, ['Spor']))
        other = '\n'.join([
            '==================== Spor 0.7.2 - forensic triage log ====================',
            '2025-01-02 03:04:05 [run] HKU\\anna\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater',
            '    program: C:\\Users\\anna\\AppData\\Roaming\\Upd\\upd.exe [unsigned]',
            '    arguments: --silent',
        ])
        statuses = [line['dominant_status'] for line in analyze_log_text(other, log_type='Spor')['lines']]
        self.assertEqual(statuses, ['?', B, B, B])

    def test_a_sub_line_gives_the_same_rule(self):
        rule = self.persist(sample.RUN_BLOCK[1].strip(), block_text=RUN_TEXT)
        self.assertEqual((rule.entry_type, rule.source_text), ('spor_run', RUN_TEXT))

    def test_the_same_rule_again_is_an_update(self):
        self.persist(sample.RUN_BLOCK[0], block_text=RUN_TEXT)
        self.persist(sample.RUN_BLOCK[0], block_text=RUN_TEXT)
        self.assertEqual(ClassificationRule.objects.count(), 1)

    def test_a_block_text_without_its_line_is_ignored(self):
        # Without its block (the analyzer sends it for the lines of a block it
        # read an entry from) a line gets a line rule, as before.
        line = '2026-11-20 08:14:02 [task] \\Evil\\Other'
        rule = self.persist(line, block_text=RUN_TEXT)
        self.assertEqual((rule.match_type, rule.match_unit, rule.source_text), ('exact', 'line', line))

    def test_a_one_line_block_with_its_text_is_a_block_rule(self):
        line = sample.TASK_BLOCK[0]
        rule = self.persist(line, block_text=line)
        self.assertEqual((rule.entry_type, rule.match_unit, rule.name), ('spor_task', BLOCK, '\\Evil\\UpdateCheck'))

    def test_older_spor_logs_get_line_rules(self):
        # Spor before 0.7.0: the analysis reads no entries, so the analyzer
        # sends no block and the line stays a line rule.
        old = sample.SPOR7.replace('Spor 0.7.1', 'Spor 0.6.1', 1)
        lines = analyze_log_text(old, log_type='Spor')['lines']
        self.assertFalse(any(line.get('block_entry_type') for line in lines))
        rule = self.persist(sample.RUN_BLOCK[0])
        self.assertEqual(rule.match_unit, 'line')

    def test_a_sub_line_naming_another_file_is_not_the_entry(self):
        defender = [
            '2026-11-21 08:18:43 [1116] Defender detected: Trojan:JS/Fake.A!ams',
            r'    file: C:\Users\Bob\AppData\Local\Temp\a.js',
        ]
        log = '\n'.join(['==================== Spor 0.7.1 - forensic triage log ====================', *defender])
        lines = analyze_log_text(log, log_type='Spor')['lines']
        self.assertEqual(lines[1]['block_entry_type'], 'spor_defender')
        self.assertNotIn('block_entry_type', lines[2])
        self.assertEqual(lines[2]['parsed_entry_type'], '')
        # Its status is its own line's rule, even with the block's text sent.
        rule = self.persist(defender[1].strip(), block_text='\n'.join(line.strip() for line in defender))
        self.assertEqual((rule.match_unit, rule.match_type), ('line', 'filepath'))

    def test_a_dll_line_keeps_its_own_components(self):
        log = '\n'.join([
            '==================== Spor 0.7.1 - forensic triage log ====================',
            r'2026-11-21 08:38:17 [run] HKU\Bob\Software\Microsoft\Windows\CurrentVersion\Run\X',
            r'    program: C:\x.exe',
            r'    arguments: C:\evil\payload.dat',
            r'    module: C:\Users\Bob\AppData\Local\side.dll [unsigned]',
        ])
        lines = analyze_log_text(log, log_type='Spor')['lines']
        self.assertEqual(lines[3]['components'].get('arguments'), r'C:\evil\payload.dat')
        self.assertNotIn('arguments', lines[4]['components'])
        self.assertEqual(lines[4]['components']['filepath'], r'C:\Users\Bob\AppData\Local\side.dll')

    def test_frst_logs_are_unchanged(self):
        rule = self.persist(SERVICE, log_type='FRST', block_text=SERVICE)
        self.assertEqual((rule.match_type, rule.match_unit, rule.entry_type), ('parsed', 'line', 'service'))

    def test_the_inspector_offers_the_block_rule(self):
        LogTypeBadge.objects.create(name='Spor')   # a log type the site knows
        self.client.force_login(self.user)
        response = self.client.post(reverse('analyze_line_details_api'), data=json.dumps({
            'line': sample.RUN_BLOCK[2].strip(), 'status': B, 'log_type': 'Spor',
            'block_lines': [line.strip() for line in sample.RUN_BLOCK],
        }), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        parsed = response.json()['parsed_rule']
        self.assertEqual((parsed['entry_type'], parsed['match_unit'], parsed['source_text']), ('spor_run', BLOCK, RUN_TEXT))

    def test_the_inspector_reads_no_entry_the_analysis_did_not_read(self):
        # A block the analysis read no Spor entry from (e.g. a Spor log before
        # 0.7.0): the page says so, and the inspector offers no block rule.
        LogTypeBadge.objects.create(name='Spor')
        self.client.force_login(self.user)
        response = self.client.post(reverse('analyze_line_details_api'), data=json.dumps({
            'line': sample.RUN_BLOCK[0].strip(), 'status': B, 'log_type': 'Spor',
            'block_lines': [line.strip() for line in sample.RUN_BLOCK], 'block_entry': False,
        }), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        parsed = response.json()['parsed_rule']
        self.assertEqual(parsed['match_unit'], 'line')
        self.assertFalse((parsed['entry_type'] or '').startswith('spor_'))

    def test_an_edit_keeps_a_spor_parsed_rule_a_block_rule(self):
        rule = self.persist(sample.RUN_BLOCK[0], block_text=RUN_TEXT)
        self.client.force_login(self.user)
        self.client.post(reverse('edit_rule', args=[rule.pk]), {
            'status': B, 'match_type': 'parsed', 'source_text': RUN_TEXT, 'is_enabled': 'on',
            'priority': '15', 'match_unit': 'line',
        })
        rule.refresh_from_db()
        self.assertEqual((rule.match_unit, rule.entry_type), (BLOCK, 'spor_run'))

    def test_reparse_and_conversion_respect_the_unit(self):
        rule = self.persist(sample.RUN_BLOCK[0], block_text=RUN_TEXT)
        ClassificationRule.objects.filter(pk=rule.pk).update(name='stale')
        report = reparse_rules(ClassificationRule.objects.all(), apply=True)
        self.assertEqual((report['changed'], report['match_type_skip']), (1, 0))
        rule.refresh_from_db()
        self.assertEqual(rule.name, 'Updater')
        # An exact line rule of a Spor item line never becomes a Spor rule.
        line_rule = ClassificationRule.objects.create(
            owner=self.user, status='P', match_type='exact', source_text=sample.RUN_BLOCK[0],
        )
        self.assertEqual(convert_exact_rules_to_parsed(ClassificationRule.objects.filter(pk=line_rule.pk),
                                                       ['spor_run']), {'converted': 0, 'deleted': 0})
        # An exact block rule of that block does.
        block_rule = ClassificationRule.objects.create(
            owner=self.user, status='P', match_type='exact', source_text=RUN_TEXT, match_unit=BLOCK,
        )
        self.assertEqual(convert_exact_rules_to_parsed(ClassificationRule.objects.filter(pk=block_rule.pk),
                                                       ['spor_run'])['converted'], 1)
        block_rule.refresh_from_db()
        self.assertEqual((block_rule.match_type, block_rule.entry_type), ('parsed', 'spor_run'))

    def test_line_rules_parse_as_before(self):
        self.assertEqual(parse_rule_line(sample.RUN_BLOCK[0], B)['match_type'], 'exact')
        self.assertEqual(parse_rule_line(SERVICE, B)['match_unit'], 'line')
