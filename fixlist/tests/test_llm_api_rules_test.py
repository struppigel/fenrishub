"""The rule dry run (/api/v1/rules/test/) and rule matching (/api/v1/rules/match/).

Both are read-only POST endpoints any token may call: they answer "what would
this candidate rule do across the corpus" and "which rules decide these lines
today" in one request each.
"""

import json

from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from ..analyzer import invalidate_rule_buckets_cache
from ..models import ApiToken, ClassificationRule, UserProfile
from .factories import make_rule, make_uploaded_log, make_user
from .test_llm_api import enable_api

TASK_LINE = (
    r'Task: {9ADF6FEE} - System32\Tasks\Updater => '
    r'C:\Users\Bob\AppData\Roaming\BuilderBeta.exe [213708 2026-07-07] () [File not signed]'
)


class RuleApiBase(TestCase):
    def setUp(self):
        cache.clear()
        enable_api()
        invalidate_rule_buckets_cache()
        self.user = make_user('alice')
        _token, self.raw = ApiToken.issue(self.user, 'laptop')

    def post(self, name, body):
        return self.client.post(
            reverse(name), json.dumps(body), content_type='application/json',
            secure=True, HTTP_AUTHORIZATION=f'Bearer {self.raw}',
        )

    def dry_run(self, **body):
        response = self.post('api_v1_rule_test', body)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()


class RuleDryRunTests(RuleApiBase):
    def test_counts_cover_every_log_even_past_the_sample(self):
        make_uploaded_log('log-one', content='evilthing one\nclean\nevilthing one\n', log_type='FRST')
        make_uploaded_log('log-two', content='evilthing two\n', log_type='FRST')
        make_uploaded_log('log-three', content='evilthing three\nnothing\n', log_type='FRST&Addition')
        make_uploaded_log('log-none', content='nothing here\n', log_type='FRST')

        body = self.dry_run(source_text='evilthing', match_type='substring', status='B', sample_lines=1)

        self.assertEqual(body['logs_in_scope'], 4)
        self.assertEqual(body['logs_matched'], 3)
        self.assertEqual(body['distinct_lines'], 3)
        # The repeated line in log-one counts twice.
        self.assertEqual(body['line_hits'], 4)
        self.assertEqual(len(body['untrusted_sample']), 1)
        self.assertTrue(body['sample_truncated'])
        self.assertTrue(body['complete'])
        self.assertTrue(body['prefiltered'])

    def test_new_rule_that_outranks_today_s_rule_and_makes_it_redundant(self):
        old = make_rule('evilthing', status='C', match_type='substring')
        make_uploaded_log('log-one', content='evilthing one\n', log_type='FRST')

        body = self.dry_run(source_text='evilthing', match_type='substring', status='B', priority=10)

        row = body['untrusted_sample'][0]
        self.assertEqual(row['untrusted_line'], 'evilthing one')
        self.assertEqual(row['current_status'], 'C')
        self.assertEqual(row['current_rule_ids'], [old.pk])
        self.assertEqual(row['current_priority'], 7)
        self.assertEqual(row['new_status'], 'B')
        self.assertEqual(row['outcome'], 'wins')
        self.assertEqual(row['logs'], [{'upload_id': 'log-one', 'line_number': 1}])

        summary = body['summary']
        self.assertEqual(summary['outcome_counts']['wins'], 1)
        self.assertEqual(summary['verdict_changes'], {'C->B': 1})
        [existing] = summary['existing_rules']
        self.assertEqual(existing['rule_id'], old.pk)
        self.assertEqual((existing['lines'], existing['decided_lines'], existing['redundant_lines']), (1, 1, 1))
        self.assertTrue(existing['redundant_on_all_sample_lines'])

    def test_new_rule_shadowed_by_a_higher_priority_rule(self):
        line = 'C:\\Program Files\\Good\\good.exe'
        make_rule(line, status='C', match_type='exact')
        make_uploaded_log('log-one', content=line + '\n', log_type='FRST')

        body = self.dry_run(source_text='good.exe', match_type='substring', status='P')

        row = body['untrusted_sample'][0]
        self.assertEqual(row['outcome'], 'shadowed')
        self.assertEqual(row['new_status'], 'C')
        self.assertEqual(body['summary']['outcome_counts']['shadowed'], 1)
        self.assertEqual(body['summary']['unchanged_lines'], 1)
        self.assertFalse(body['summary']['existing_rules'][0]['redundant_on_all_sample_lines'])

    def test_line_nobody_decided_yet(self):
        make_uploaded_log('log-one', content='brand new threat\n', log_type='FRST')
        body = self.dry_run(source_text='new threat', match_type='substring', status='B')
        self.assertEqual(body['untrusted_sample'][0]['outcome'], 'new_verdict')
        self.assertEqual(body['summary']['verdict_changes'], {'?->B': 1})
        self.assertEqual(body['summary']['existing_rules'], [])

    def test_compare_with_the_rule_it_would_replace(self):
        old = make_rule('evil1.exe', status='B', match_type='substring')
        make_uploaded_log('log-one', content='run evil1.exe\nrun evil2.exe\nrun other.exe\n', log_type='FRST')

        body = self.dry_run(source_text=r'evil\d\.exe', match_type='regex', status='B', compare_rule_id=old.pk)

        compare = body['compare']
        self.assertEqual(compare['rule']['rule_id'], old.pk)
        self.assertEqual((compare['both'], compare['only_new'], compare['only_old']), (1, 1, 0))
        self.assertEqual([row['untrusted_line'] for row in compare['untrusted_only_new_sample']], ['run evil2.exe'])
        self.assertTrue(compare['complete'])
        # The compared rule is left out of today's verdicts, as if it were replaced.
        self.assertEqual(body['summary']['existing_rules'], [])
        self.assertFalse(body['prefiltered'])

    def test_compare_with_an_unknown_rule_is_400(self):
        response = self.post('api_v1_rule_test', {
            'source_text': 'x', 'match_type': 'substring', 'status': 'B', 'compare_rule_id': 999999,
        })
        self.assertEqual(response.status_code, 400)

    def test_default_scope_is_frst_and_addition_logs(self):
        make_uploaded_log('the-frst', content='needle\n', log_type='FRST')
        make_uploaded_log('the-fixlog', content='needle\n', log_type='Fixlog')
        make_uploaded_log('the-unknown', content='needle\n', log_type='Unknown')

        body = self.dry_run(source_text='needle', match_type='substring', status='B')
        self.assertEqual(body['logs_matched'], 1)

        body = self.dry_run(source_text='needle', match_type='substring', status='B', type='')
        self.assertEqual(body['logs_matched'], 3)

        body = self.dry_run(source_text='needle', match_type='substring', status='B', type='', exclude_type='Fixlog')
        self.assertEqual(body['logs_matched'], 2)

    def test_max_logs_takes_the_newest(self):
        for index in range(3):
            make_uploaded_log(f'log-{index}', content='needle\n', log_type='FRST')
        body = self.dry_run(source_text='needle', match_type='substring', status='B', max_logs=2)
        self.assertEqual(body['logs_in_scope'], 2)
        self.assertEqual(body['logs_matched'], 2)

    def test_dedupe_counts_one_scan_once(self):
        make_uploaded_log('first-copy', content='needle\n', log_type='FRST')
        make_uploaded_log('second-copy', content='needle\n', log_type='FRST')
        self.assertEqual(self.dry_run(source_text='needle', match_type='substring', status='B')['logs_matched'], 2)
        body = self.dry_run(source_text='needle', match_type='substring', status='B', dedupe=True)
        self.assertEqual(body['logs_matched'], 1)
        self.assertEqual(body['duplicates_hidden'], 1)

    def test_parsed_rule_reports_the_parsed_line(self):
        make_uploaded_log('log-one', content=TASK_LINE + '\n', log_type='FRST')
        body = self.dry_run(source_text=TASK_LINE, match_type='parsed', status='B')
        self.assertEqual(body['logs_matched'], 1)
        self.assertEqual(body['untrusted_sample'][0]['parsed']['entry_type'], 'scheduled_task')

    def test_whole_log_rule_lists_the_logs_it_fires_on(self):
        make_uploaded_log('log-one', content='alpha\nbeta\n', log_type='FRST')
        make_uploaded_log('log-two', content='gamma\n', log_type='FRST')
        body = self.dry_run(source_text='alpha', match_type='regex', status='A', whole_log=True)
        self.assertTrue(body['whole_log'])
        self.assertEqual([entry['upload_id'] for entry in body['logs']], ['log-one'])

    def test_verdicts_use_the_callers_private_rule_set(self):
        UserProfile.objects.create(user=self.user, rule_set_mode='private')
        other = make_user('bob')
        make_rule('evilthing', status='C', match_type='substring', owner=other)
        mine = make_rule('evilthing', status='G', match_type='substring', owner=self.user)
        make_uploaded_log('log-one', content='evilthing\n', log_type='FRST')

        body = self.dry_run(source_text='evilthing', match_type='substring', status='B', priority=10)
        self.assertEqual(body['rule_set'], 'private')
        self.assertEqual(body['untrusted_sample'][0]['current_rule_ids'], [mine.pk])

    def test_script_rules_are_for_moderators_only(self):
        response = self.post('api_v1_rule_test', {
            'source_text': 'return True', 'match_type': 'script', 'status': 'B',
        })
        self.assertEqual(response.status_code, 403)

    def test_invalid_regex_is_400(self):
        response = self.post('api_v1_rule_test', {'source_text': '(unclosed', 'match_type': 'regex', 'status': 'B'})
        self.assertEqual(response.status_code, 400)

    def test_bad_scope_value_is_400(self):
        response = self.post('api_v1_rule_test', {
            'source_text': 'x', 'match_type': 'substring', 'status': 'B', 'created_after': 'yesterday',
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn('created_after', response.json()['error'])

    def test_nothing_is_saved(self):
        make_uploaded_log('log-one', content='needle\n', log_type='FRST')
        self.dry_run(source_text='needle', match_type='substring', status='B')
        self.assertFalse(ClassificationRule.objects.exists())


class RuleMatchTests(RuleApiBase):
    def test_winning_and_shadowed_rules_per_line(self):
        exact = make_rule(TASK_LINE, status='B', match_type='exact')
        substring = make_rule('BuilderBeta.exe', status='C', match_type='substring')

        response = self.post('api_v1_rule_match', {'lines': [TASK_LINE, 'unmatched line']})
        self.assertEqual(response.status_code, 200)
        first, second = response.json()['results']

        self.assertEqual(first['status'], 'B')
        self.assertEqual(first['effective_priority'], 19)
        self.assertEqual([(row['rule_id'], row['decides']) for row in first['winning']], [(exact.pk, True)])
        self.assertEqual([row['rule_id'] for row in first['shadowed']], [substring.pk])
        self.assertEqual(first['entry']['entry_type'], 'scheduled_task')
        self.assertEqual(first['entry']['filename'], 'BuilderBeta.exe')

        self.assertEqual(second['status'], '?')
        self.assertEqual(second['winning'], [])
        self.assertIsNone(second['entry'])

    def test_rule_tags_are_listed(self):
        from ..models import RuleTag
        rule = make_rule('evilthing', status='B', match_type='substring')
        rule.tags.add(RuleTag.objects.create(name='RenLoader'))
        result = self.post('api_v1_rule_match', {'lines': ['evilthing here']}).json()['results'][0]
        self.assertEqual(result['winning'][0]['tags'], ['RenLoader'])

    def test_shadowed_can_be_left_out(self):
        make_rule('evilthing', status='B', match_type='substring')
        result = self.post('api_v1_rule_match', {
            'lines': ['evilthing here'], 'include_shadowed': False,
        }).json()['results'][0]
        self.assertNotIn('shadowed', result)

    def test_invalid_lines_are_400(self):
        for lines in (None, [], 'one line', [1], ['x'] * 201, ['x' * 4001]):
            response = self.post('api_v1_rule_match', {'lines': lines})
            self.assertEqual(response.status_code, 400, lines)
