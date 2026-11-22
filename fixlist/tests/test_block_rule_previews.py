"""The rule editor's previews of block rules: pasted Spor lines laid out
into blocks, and the stored-log scan listing whole blocks."""

import json

from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule
from .factories import make_uploaded_log, make_user
from . import spor7_sample as sample

BLOCK_LOG = '\n'.join([
    '==================== Spor 0.7.1 - forensic triage log ====================',
    '==================== PERSISTENCE - autostarts ====================',
    *sample.TASK_BLOCK,
    r'2026-11-20 08:15:02 [task] \Microsoft\Windows\Defrag',
    r'    program: C:\Windows\System32\defrag.exe',
])


class BlockRulePreviewTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.login(username='alice', password='password123')

    def _post(self, name, payload):
        return self.client.post(reverse(name), json.dumps(payload), content_type='application/json')

    def test_pasted_lines_match_by_block(self):
        lines = BLOCK_LOG.split('\n')
        data = self._post('test_rule_api', {
            'source_text': 'UpdateCheck', 'match_type': 'substring', 'status': 'B', 'match_unit': 'block',
            'lines': lines, 'log_text': BLOCK_LOG, 'log_types': ['Spor'],
        }).json()
        self.assertEqual([result['matched'] for result in data['results']],
                         [False, False, True, True, True, True, False, False])

    def test_a_pasted_spor_block_gives_its_parsed_rule(self):
        block = '\n'.join(sample.RUN_BLOCK)
        data = self._post('test_rule_api', {
            'source_text': block, 'match_type': 'parsed', 'status': 'B', 'match_unit': 'block',
            'lines': sample.RUN_BLOCK, 'log_text': block,
        }).json()
        self.assertEqual(data['rule']['entry_type'], 'spor_run')
        self.assertEqual([result['matched'] for result in data['results']], [True, True, True])

    def test_line_rules_are_unchanged(self):
        data = self._post('test_rule_api', {
            'source_text': 'UpdateCheck', 'match_type': 'substring', 'status': 'B',
            'lines': BLOCK_LOG.split('\n'), 'log_text': BLOCK_LOG,
        }).json()
        self.assertEqual([result['matched'] for result in data['results']],
                         [False, False, True, False, False, False, False, False])

    def test_a_spor_rule_scans_only_spor_logs(self):
        make_uploaded_log('frst-log', content='\n'.join(sample.RUN_BLOCK), log_type='FRST&Addition')
        make_uploaded_log('spor-log', content=BLOCK_LOG.replace(
            '\n'.join(sample.TASK_BLOCK), '\n'.join(sample.TASK_BLOCK + sample.RUN_BLOCK),
        ), log_type='Spor')
        data = self._post('test_rule_logs_api', {
            'source_text': '\n'.join(sample.RUN_BLOCK), 'match_type': 'parsed', 'status': 'B', 'match_unit': 'block',
            # The picker's default: the FRST types.
            'log_types': ['FRST&Addition', 'FRST', 'Addition'],
        }).json()
        self.assertEqual(data['log_types'], ['Spor'])
        self.assertEqual(data['logs_scanned'], 1)
        self.assertEqual([result['logs'][0]['upload_id'] for result in data['results']], ['spor-log'])

    def test_the_pickers_default_saves_a_spor_rule_for_spor(self):
        self.client.post(reverse('add_rule'), {
            'status': 'B', 'match_type': 'parsed', 'source_text': '\n'.join(sample.RUN_BLOCK), 'priority': '',
            'match_unit': 'block', 'log_scope': 'default', 'log_types': ['FRST&Addition', 'FRST', 'Addition'],
        })
        rule = ClassificationRule.objects.get()
        self.assertEqual((rule.entry_type, rule.all_log_types, rule.log_types), ('spor_run', False, ['Spor']))
        # Edited with the default again, it stays a Spor rule.
        self.client.post(reverse('edit_rule', args=[rule.pk]), {
            'status': 'P', 'match_type': 'parsed', 'source_text': rule.source_text, 'is_enabled': 'on',
            'priority': '15', 'match_unit': 'block', 'log_scope': 'default',
            'log_types': ['FRST&Addition', 'FRST', 'Addition'],
        })
        rule.refresh_from_db()
        self.assertEqual((rule.status, rule.log_types), ('P', ['Spor']))

    def test_the_editor_shows_priority_and_matches_side_by_side(self):
        page = self.client.get(reverse('add_rule')).content.decode()
        pair = page[page.index('class="rule-field-pair"'):]
        self.assertLess(pair.index('id="rulePriorityGroup"'), pair.index('id="ruleMatchUnitGroup"'))
        self.assertIn('<option value="line" selected>line</option>', page)
        self.assertIn('<option value="block" >block</option>', page)

    def test_the_stored_log_scan_lists_blocks(self):
        make_uploaded_log('spor-log', content=BLOCK_LOG, log_type='Spor')
        data = self._post('test_rule_logs_api', {
            'source_text': 'UpdateCheck', 'match_type': 'substring', 'status': 'B', 'match_unit': 'block',
            'log_types': ['Spor'],
        }).json()
        [result] = data['results']
        self.assertEqual(result['line'], '\n'.join(line.strip() for line in sample.TASK_BLOCK))
        self.assertTrue(result['matched'])
        self.assertEqual(result['logs'][0]['line_number'], 3)
