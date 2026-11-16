"""Case correlations in the token API: the `correlation` of analysis lines and
the `correlated_findings` of get_case.

On by default and compact, served from the stored answer like the log page;
like the log page, centralbox is never asked.
"""

from datetime import timedelta
from unittest import mock

from django.utils import timezone

from .. import centralbox
from ..models import (
    CorrelationCache, HashVerdict, InfectionCase, InfectionCaseLog, RuleTag, TagCategory, UploadedLogFileHash,
)
from ..views import llm_api
from .factories import make_uploaded_log, make_user
from .test_case_correlations import EVIL_SHA, FRST, MB_EVIL, MB_SAME, OTHER_LINE, RUN_LINE
from .test_llm_api_v2 import ApiV2Base, cache_analysis

HEADER = FRST.split('\n')[0]


class CorrelationApiBase(ApiV2Base):
    def setUp(self):
        super().setUp()
        # Not the forum user's name, so no upload is put in the case by itself.
        self.case = InfectionCase.objects.create(owner=self.user, username='case-user')
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST, forum_username='bob')
        cache_analysis(self.frst, [(HEADER, '?'), (RUN_LINE, '?'), (OTHER_LINE, 'C')])
        self.link(self.frst)

    def link(self, upload, case=None):
        InfectionCaseLog.objects.create(case=case or self.case, uploaded_log=upload, added_by=self.user)

    def add_log(self, upload_id, content, forum_username='bob', case=None):
        upload = make_uploaded_log(upload_id, log_type='Malwarebytes', content=content, forum_username=forum_username)
        UploadedLogFileHash.rebuild_for(upload)
        if case is not False:
            self.link(upload, case)
        return upload

    def malicious_verdict(self, when=None):
        when = when or timezone.now()
        HashVerdict.objects.update_or_create(sha256=EVIL_SHA, defaults={
            'state': 'known', 'verdict': 'malicious', 'family': 'asyncrat',
            'checked_at': when, 'next_check_at': when + timedelta(days=7),
        })

    def call(self, name, *args, **params):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            response = self.api_get(name, *args, data=params)
        http.assert_not_called()
        request.assert_not_called()
        return response

    def analysis(self, **params):
        response = self.call('api_v1_upload_analysis', 'frst-log', **params)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def line(self, body, text):
        return next(line for line in body['untrusted_lines'] if line['text'] == text)


class AnalysisCorrelationTests(CorrelationApiBase):
    def test_compact_correlation_by_default(self):
        self.malicious_verdict()
        self.add_log('mb-log', MB_SAME)
        body = self.analysis()
        self.assertEqual(body['correlation_scope'], {'scope': 'case', 'untrusted_forum_username': '', 'fresh': True})
        run = self.line(body, RUN_LINE)
        # The rule verdict stays; the correlation is beside it.
        self.assertEqual(run['status'], '?')
        self.assertEqual(set(run['correlation']), {'status', 'note', 'entry_count'})
        self.assertEqual((run['correlation']['status'], run['correlation']['entry_count']), ('B', 1))
        self.assertIn('asyncrat', run['correlation']['note'])
        # Lines nothing is known about carry no key at all.
        self.assertNotIn('correlation', self.line(body, OTHER_LINE))

    def test_full_adds_the_entries(self):
        self.malicious_verdict()
        category = TagCategory.objects.create(name='family test', priority=7)
        RuleTag.objects.create(name='AsyncRAT', match_pattern='asyncrat', match_centralbox=True, category=category)
        self.add_log('mb-log', MB_SAME)
        run = self.line(self.analysis(correlations='full'), RUN_LINE)
        [entry] = run['correlation']['entries']
        self.assertEqual((entry['kind'], entry['upload_id'], entry['status']), ('hash', 'mb-log', 'B'))
        self.assertEqual((entry['sha256'], entry['system']), (EVIL_SHA, 'same'))
        self.assertEqual(entry['centralbox']['verdict'], 'malicious')
        # Centralbox tags stay on the entry; the line's own tags are unchanged.
        self.assertEqual(entry['tags'], ['AsyncRAT'])
        self.assertEqual(run['tags'], [])

    def test_off_leaves_everything_out_and_reads_nothing(self):
        self.add_log('mb-log', MB_SAME)
        with mock.patch.object(llm_api, 'cached_correlations') as cached:
            body = self.analysis(correlations='0')
        cached.assert_not_called()
        self.assertNotIn('correlation_scope', body)
        self.assertNotIn('correlation', self.line(body, RUN_LINE))

    def test_fields_without_correlation_skip_the_lookup(self):
        self.add_log('mb-log', MB_SAME)
        with mock.patch.object(llm_api, 'cached_correlations') as cached:
            body = self.analysis(fields='n,status')
        cached.assert_not_called()
        self.assertEqual(body['untrusted_lines'][1], {'n': 2, 'status': '?'})

    def test_correlation_can_be_picked_with_fields(self):
        self.add_log('mb-log', MB_SAME)
        body = self.analysis(fields='n,correlation')
        self.assertEqual([set(line) for line in body['untrusted_lines']], [{'n'}, {'n', 'correlation'}, {'n'}])

    def test_correlated_keeps_only_lines_with_entries(self):
        self.add_log('mb-log', MB_SAME)
        body = self.analysis(correlated=1)
        self.assertEqual(body['matching_line_count'], 1)
        self.assertEqual([line['text'] for line in body['untrusted_lines']], [RUN_LINE])

    def test_bad_values_are_400(self):
        self.assertEqual(self.call('api_v1_upload_analysis', 'frst-log', correlations='lots').status_code, 400)
        response = self.call('api_v1_upload_analysis', 'frst-log', correlations='off', correlated=1)
        self.assertEqual(response.status_code, 400)

    def test_never_stored_is_computed_once_then_served_from_the_cache(self):
        self.add_log('mb-log', MB_SAME)
        self.assertFalse(CorrelationCache.objects.exists())
        self.analysis()
        self.assertEqual(CorrelationCache.objects.count(), 1)
        with mock.patch.object(llm_api, 'correlations_for_upload') as compute:
            body = self.analysis()
        compute.assert_not_called()
        self.assertEqual(self.line(body, RUN_LINE)['correlation']['entry_count'], 1)

    def test_outdated_answer_is_served_until_fresh_is_asked(self):
        self.add_log('mb-log', MB_SAME)
        self.analysis()
        # A centralbox verdict arriving later outdates the stored answer.
        self.malicious_verdict(when=timezone.now() + timedelta(minutes=5))
        with mock.patch.object(llm_api, 'correlations_for_upload') as compute:
            body = self.analysis()
        compute.assert_not_called()
        self.assertFalse(body['correlation_scope']['fresh'])
        self.assertNotIn('centralbox', self.line(body, RUN_LINE)['correlation']['note'])
        body = self.analysis(correlations_fresh=1)
        self.assertTrue(body['correlation_scope']['fresh'])
        self.assertIn('centralbox: malicious', self.line(body, RUN_LINE)['correlation']['note'])

    def test_a_log_from_another_machine_is_listed_but_sets_no_status(self):
        self.add_log('mb-log', MB_EVIL)
        run = self.line(self.analysis(correlations='full'), RUN_LINE)
        [entry] = run['correlation']['entries']
        self.assertEqual((entry['system'], entry['status']), ('different', 'B'))
        self.assertEqual(run['correlation']['status'], '')

    def test_another_helpers_case_is_not_read(self):
        other_case = InfectionCase.objects.create(owner=make_user('carol'), username='case-user')
        InfectionCaseLog.objects.create(case=other_case, uploaded_log=self.frst, added_by=other_case.owner)
        self.add_log('mb-log', MB_SAME, forum_username='someone-else', case=other_case)
        self.assertNotIn('correlation', self.line(self.analysis(), RUN_LINE))

    def test_without_own_case_the_forum_users_logs_count(self):
        InfectionCaseLog.objects.filter(case=self.case).delete()
        self.add_log('mb-log', MB_SAME, case=False)
        body = self.analysis()
        self.assertEqual(body['correlation_scope']['scope'], 'user')
        self.assertEqual(body['correlation_scope']['untrusted_forum_username'], 'bob')
        self.assertEqual(self.line(body, RUN_LINE)['correlation']['status'], 'B')


class CaseCorrelatedFindingsTests(CorrelationApiBase):
    def test_frst_log_lists_its_findings_and_other_logs_none(self):
        self.malicious_verdict()
        self.add_log('mb-log', MB_SAME)
        response = self.call('api_v1_case', self.case.case_id)
        self.assertEqual(response.status_code, 200, response.content)
        logs = {entry['upload']['upload_id']: entry for entry in response.json()['timeline'] if entry['type'] == 'log'}
        [finding] = logs['frst-log']['correlated_findings']
        self.assertEqual(
            {key: finding[key] for key in ('n', 'text', 'status', 'correlation_status')},
            {'n': 2, 'text': RUN_LINE, 'status': '?', 'correlation_status': 'B'},
        )
        self.assertIn('asyncrat', finding['note'])
        self.assertNotIn('correlated_findings', logs['mb-log'])

    def test_lines_without_a_status_are_not_findings(self):
        self.add_log('mb-log', MB_EVIL)  # another machine: listed in the analysis, no status
        response = self.call('api_v1_case', self.case.case_id)
        log = next(entry for entry in response.json()['timeline'] if entry.get('upload', {}).get('upload_id') == 'frst-log')
        self.assertEqual(log['correlated_findings'], [])
