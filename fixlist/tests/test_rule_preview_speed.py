"""The rule editor's previews stay fast: the pasted-lines preview uses the
cached rule buckets, and the stored-log scan reads a Spor line's features
(an FRST parse of the line) only for a rule that needs them, so it gets
through every Spor log within its time budget."""

import json
import time
from unittest import mock

from django.contrib.admin import site
from django.test import RequestFactory, TestCase
from django.urls import reverse

from .. import analyzer
from ..analyzer import invalidate_rule_buckets_cache
from ..models import ClassificationRule, UserProfile
from ..rule_test_service import scan_logs_for_rule_matches
from . import spor7_sample as sample
from .factories import make_rule, make_uploaded_log, make_user

SPOR_LOG = '\n'.join([
    '==================== Spor 0.7.1 - forensic triage log ====================',
    '==================== PERSISTENCE - autostarts ====================',
    *sample.TASK_BLOCK,
    *sample.RUN_BLOCK,
])


class RulePreviewSpeedTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.login(username='alice', password='password123')
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)

    def _post(self, name, payload):
        return self.client.post(reverse(name), json.dumps(payload), content_type='application/json').json()

    def _counting_line_features(self):
        return mock.patch.object(analyzer, 'line_features', wraps=analyzer.line_features)

    def test_a_text_rule_scans_spor_logs_without_parsing_their_lines(self):
        for match_type, pattern in (('substring', 'UpdateCheck'), ('regex', r'UpdateCheck\b')):
            with self._counting_line_features() as features:
                scan = scan_logs_for_rule_matches(
                    [pattern], 'B', match_type, [('spor-log', SPOR_LOG)],
                    max_lines=200, deadline=time.monotonic() + 60, log_type_for=lambda _upload_id: 'Spor',
                )
            # Only the matched line, for its rebuilt verdict: not every line of the log.
            self.assertEqual(features.call_count, len(scan['matches']), match_type)
            self.assertEqual([entry['line'] for entry in scan['matches']], [sample.TASK_BLOCK[0]], match_type)

    def test_the_spor_scan_finds_a_text_rules_lines(self):
        make_uploaded_log('spor-log', content=SPOR_LOG, log_type='Spor')
        data = self._post('test_rule_logs_api', {
            'source_text': 'UpdateCheck', 'match_type': 'substring', 'status': 'B', 'log_types': ['Spor'],
        })
        self.assertEqual([result['line'] for result in data['results']], [sample.TASK_BLOCK[0]])
        self.assertEqual(data['logs_scanned'], 1)
        self.assertFalse(data['timed_out'])

    def test_a_text_rule_restricted_to_entry_types_still_checks_spor_lines(self):
        make_uploaded_log('spor-log', content=SPOR_LOG, log_type='Spor')
        found = {}
        for entry_type in ('spor_task', 'spor_run'):
            data = self._post('test_rule_logs_api', {
                'source_text': 'UpdateCheck', 'match_type': 'substring', 'status': 'B', 'log_types': ['Spor'],
                'only_entry_types': [entry_type],
            })
            # Listed lines are reported as matched: their verdict is rebuilt
            # from the line as read in its Spor log, not as a lone FRST line.
            found[entry_type] = [(result['line'], result['matched']) for result in data['results']]
        self.assertEqual(found, {'spor_task': [(sample.TASK_BLOCK[0], True)], 'spor_run': []})

    def test_a_filepath_rule_still_reads_spor_line_paths(self):
        make_uploaded_log('spor-log', content=SPOR_LOG, log_type='Spor')
        data = self._post('test_rule_logs_api', {
            'source_text': sample.TASK_PROGRAM, 'match_type': 'filepath', 'status': 'B', 'log_types': ['Spor'],
        })
        results = {result['line']: result for result in data['results']}
        self.assertIn(sample.TASK_BLOCK[1].strip(), results)
        self.assertTrue(all(result['matched'] for result in results.values()))
        self.assertEqual(results[sample.TASK_BLOCK[1].strip()]['combined_status'], 'B')

    def test_pasted_spor_lines_still_match_a_text_rule(self):
        data = self._post('test_rule_api', {
            'source_text': 'UpdateCheck', 'match_type': 'substring', 'status': 'B',
            'lines': SPOR_LOG.split('\n'), 'log_text': SPOR_LOG, 'log_types': ['Spor'],
        })
        self.assertEqual([result['line'] for result in data['results'] if result['matched']], [sample.TASK_BLOCK[0]])

    def test_the_paste_preview_reuses_the_rule_buckets_until_a_rule_is_saved(self):
        payload = {
            'source_text': 'EVIL.EXE', 'match_type': 'exact', 'status': 'B', 'lines': ['EVIL.EXE'],
        }
        with mock.patch.object(analyzer, '_load_rule_buckets', wraps=analyzer._load_rule_buckets) as load:
            first = self._post('test_rule_api', payload)
            self._post('test_rule_api', payload)
            self.assertEqual(load.call_count, 1)
            self.assertEqual(first['results'][0]['existing_matches'], [])

            # Saved through the editor: the next preview sees it at once.
            self.client.post(reverse('add_rule'), {
                'status': 'P', 'match_type': 'exact', 'source_text': 'EVIL.EXE', 'priority': '',
                'match_unit': 'line', 'log_scope': 'default', 'log_types': ['FRST&Addition', 'FRST', 'Addition'],
            })
            rule = ClassificationRule.objects.get()
            after = self._post('test_rule_api', payload)
        self.assertEqual([match['id'] for match in after['results'][0]['existing_matches']], [rule.pk])
        self.assertEqual(after['results'][0]['existing_status'], 'P')

    def test_previews_use_the_helpers_private_rule_set(self):
        UserProfile.objects.create(user=self.user, rule_set_mode='private')
        own = make_rule('EVIL.EXE', status=ClassificationRule.STATUS_PUP, owner=self.user)
        other = make_user(username='bob')
        UserProfile.objects.create(user=other, rule_set_mode='shared')
        make_rule('EVIL.EXE', status=ClassificationRule.STATUS_CLEAN, owner=other)
        make_uploaded_log('frst-log', content='EVIL.EXE', log_type='FRST&Addition')
        payload = {'source_text': 'EVIL.EXE', 'match_type': 'exact', 'status': 'B'}

        pasted = self._post('test_rule_api', {**payload, 'lines': ['EVIL.EXE']})['results'][0]
        stored = self._post('test_rule_logs_api', {**payload, 'log_types': ['FRST&Addition']})['results'][0]
        for result in (pasted, stored):
            self.assertEqual([match['id'] for match in result['existing_matches']], [own.pk])
            self.assertEqual(result['existing_status'], 'P')

    def test_a_rule_changed_in_the_admin_shows_in_the_next_preview(self):
        rule = make_rule('EVIL.EXE', status=ClassificationRule.STATUS_PUP)
        payload = {'source_text': 'EVIL.EXE', 'match_type': 'exact', 'status': 'B', 'lines': ['EVIL.EXE']}
        self.assertEqual(self._post('test_rule_api', payload)['results'][0]['existing_status'], 'P')

        admin = site._registry[ClassificationRule]
        rule.status = ClassificationRule.STATUS_CLEAN
        admin.save_model(RequestFactory().post('/'), rule, form=None, change=True)
        self.assertEqual(self._post('test_rule_api', payload)['results'][0]['existing_status'], 'C')

        admin.delete_model(RequestFactory().post('/'), rule)
        self.assertEqual(self._post('test_rule_api', payload)['results'][0]['existing_status'], '?')
