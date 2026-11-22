"""API version 4: the correlations endpoint (get_correlations) for every log
type and get_case `linked_findings`.

An FRST / Addition log gets what the other logs say about its lines
(forward, as in get_analysis); any other log the FRST / Addition lines that
point at its lines (reverse); a Spor log also the links between its own
lines. The analyzer never runs for it, centralbox is never asked, and the
version 3 answers (get_analysis, correlated_findings) stay as they were.
"""

from datetime import timedelta
from unittest import mock

from django.utils import timezone

from ..correlations import reverse as reverse_module
from ..correlations import spor_self
from ..models import (
    ApiRequestLog, CorrelationCache, InfectionCase, InfectionCaseLog, UploadedLog, UploadedLogAnalysis,
)
from ..views import llm_api
from ..views.api_auth import API_VERSION_HEADER, UPLOAD_READ_ENDPOINTS
from .factories import make_rule, make_uploaded_log, make_user
from .test_case_correlations import MB_SAME, OTHER_LINE, RUN_LINE
from .test_llm_api_correlations import HEADER, CorrelationApiBase
from .test_llm_api_v2 import cache_analysis
from .test_spor_self_links import SPOR_LINKS

RUN_NO = 2  # RUN_LINE in FRST


class LinkedApiBase(CorrelationApiBase):
    def setUp(self):
        super().setUp()
        # The Run line rated malware by the rules: it colours the lines it points at.
        UploadedLogAnalysis.objects.filter(upload=self.frst).delete()
        cache_analysis(self.frst, [(HEADER, '?'), (RUN_LINE, 'B'), (OTHER_LINE, 'C')])
        spor_self._cache.clear()

    def correlations(self, upload_id, expect=200, **params):
        response = self.call('api_v1_upload_correlations', upload_id, **params)
        self.assertEqual(response.status_code, expect, response.content)
        return response.json()

    def add_spor(self, upload_id='spor-log', content=SPOR_LINKS):
        upload = make_uploaded_log(upload_id, log_type='Spor', content=content, forum_username='bob')
        self.link(upload)
        return upload

    def row(self, body, n):
        return next(line for line in body['untrusted_lines'] if line['n'] == n)


class ReverseTests(LinkedApiBase):
    def test_a_scanner_log_line_gets_the_frst_line_pointing_at_it(self):
        self.add_log('mb-log', MB_SAME)
        body = self.correlations('mb-log')
        self.assertEqual(body['direction'], 'reverse')
        self.assertEqual(body['correlation_scope'], {'scope': 'case', 'untrusted_forum_username': '', 'fresh': True})
        [line] = body['untrusted_lines']
        self.assertEqual((line['n'], line['text']), (1, MB_SAME))
        self.assertEqual(set(line['correlation']), {'status', 'note', 'entry_count'})
        self.assertEqual((line['correlation']['status'], line['correlation']['entry_count']), ('B', 1))
        self.assertIn(f'L{RUN_NO}', line['correlation']['note'])
        self.assertNotIn('self_links', line)

    def test_full_and_line_give_the_entries(self):
        self.add_log('mb-log', MB_SAME)
        for params in ({'full': 1}, {'line': 1}):
            [line] = self.correlations('mb-log', **params)['untrusted_lines']
            [entry] = line['correlation']['entries']
            self.assertEqual(
                (entry['kind'], entry['upload_id'], entry['line_no'], entry['text'], entry['line_status']),
                ('reverse', 'frst-log', RUN_NO, RUN_LINE, 'B'),
            )
            self.assertEqual(entry['status'], 'B')
        self.assertEqual(self.correlations('mb-log', line=5)['untrusted_lines'], [])

    def test_an_unrated_frst_line_lists_entries_without_a_status(self):
        UploadedLogAnalysis.objects.filter(upload=self.frst).delete()
        cache_analysis(self.frst, [(HEADER, '?'), (RUN_LINE, '?'), (OTHER_LINE, 'C')])
        self.add_log('mb-log', MB_SAME)
        [line] = self.correlations('mb-log', full=1)['untrusted_lines']
        self.assertEqual((line['correlation']['status'], line['correlation']['note']), ('', ''))
        self.assertEqual([entry['status'] for entry in line['correlation']['entries']], [''])
        self.assertEqual(self.correlations('mb-log', rated=1)['untrusted_lines'], [])

    def test_never_stored_is_computed_once_then_served_from_the_cache(self):
        self.add_log('mb-log', MB_SAME)
        self.assertFalse(CorrelationCache.objects.exists())
        self.correlations('mb-log')
        self.assertEqual(CorrelationCache.objects.count(), 1)
        with mock.patch.object(reverse_module, 'correlations_for_upload') as compute:
            body = self.correlations('mb-log')
        compute.assert_not_called()
        self.assertEqual(body['untrusted_lines'][0]['correlation']['status'], 'B')

    def test_outdated_answer_is_served_until_fresh_is_asked(self):
        self.add_log('mb-log', MB_SAME)
        self.correlations('mb-log')
        # A centralbox verdict arriving later outdates the FRST log's stored answer.
        self.malicious_verdict(when=timezone.now() + timedelta(minutes=5))
        with mock.patch.object(reverse_module, 'correlations_for_upload') as compute:
            body = self.correlations('mb-log')
        compute.assert_not_called()
        self.assertFalse(body['correlation_scope']['fresh'])
        self.assertTrue(self.correlations('mb-log', fresh=1)['correlation_scope']['fresh'])

    def test_a_related_frst_log_without_an_analysis_is_analyzed_first(self):
        # Never opened: its correlations cannot be computed without one.
        UploadedLogAnalysis.objects.filter(upload=self.frst).delete()
        self.add_log('mb-log', MB_SAME)
        [line] = self.correlations('mb-log', full=1)['untrusted_lines']
        self.assertEqual(line['correlation']['entries'][0]['line_no'], RUN_NO)
        self.assertTrue(UploadedLogAnalysis.objects.filter(upload=self.frst).exists())
        # Stored now: the next call computes nothing.
        with mock.patch.object(reverse_module, 'correlations_for_upload') as compute:
            self.correlations('mb-log')
        compute.assert_not_called()

    def test_another_helpers_case_is_not_read(self):
        other_case = InfectionCase.objects.create(owner=make_user('carol'), username='case-user')
        InfectionCaseLog.objects.create(case=other_case, uploaded_log=self.frst, added_by=other_case.owner)
        self.add_log('mb-log', MB_SAME, forum_username='someone-else', case=other_case)
        self.assertEqual(self.correlations('mb-log')['untrusted_lines'], [])


class ForwardTests(LinkedApiBase):
    def test_an_frst_log_gets_what_get_analysis_gives_by_line_number(self):
        self.malicious_verdict()
        self.add_log('mb-log', MB_SAME)
        body = self.correlations('frst-log', full=1)
        self.assertEqual(body['direction'], 'forward')
        [line] = body['untrusted_lines']
        self.assertEqual((line['n'], line['text']), (RUN_NO, RUN_LINE))
        analysis_line = self.line(self.analysis(correlations='full'), RUN_LINE)
        self.assertEqual(line['correlation'], analysis_line['correlation'])
        self.assertEqual(line['correlation']['status'], 'B')

    def test_computing_the_answer_serves_the_analysis_first(self):
        UploadedLogAnalysis.objects.filter(upload=self.frst).delete()
        self.malicious_verdict()
        self.add_log('mb-log', MB_SAME)
        [line] = self.correlations('frst-log')['untrusted_lines']
        self.assertEqual((line['n'], line['correlation']['status']), (RUN_NO, 'B'))


class SporSelfLinkTests(LinkedApiBase):
    def setUp(self):
        super().setUp()
        self.spor = self.add_spor()
        self.codes = spor_self.compute('spor-log', SPOR_LINKS).codes
        spor_self._cache.clear()

    def numbers(self, body):
        return [line['n'] for line in body['untrusted_lines']]

    def test_marked_lists_the_lines_with_a_status_or_a_marker(self):
        with mock.patch.object(llm_api, 'get_or_compute_upload_analysis') as analyze:
            body = self.correlations('spor-log')
        analyze.assert_not_called()
        self.assertEqual(body['direction'], 'reverse')
        self.assertEqual(self.numbers(body), sorted(int(no) for no, code in self.codes.items() if code))
        rated = [no for no, code in self.codes.items() if code in ('B', 'P', '!')]
        self.assertTrue(rated)
        line = self.row(body, int(rated[0]))
        self.assertEqual(set(line['self_links']), {'status', 'notable', 'entry_count'})
        self.assertEqual(line['self_links']['status'], self.codes[rated[0]])
        self.assertTrue(line['self_links']['notable'])
        self.assertEqual(line['text'], SPOR_LINKS.split('\n')[int(rated[0]) - 1].strip())

    def test_all_off_and_rated(self):
        self.assertEqual(self.numbers(self.correlations('spor-log', self_links='all')),
                         sorted(int(no) for no in self.codes))
        self.assertEqual(self.correlations('spor-log', self_links='off')['untrusted_lines'], [])
        self.assertEqual(self.numbers(self.correlations('spor-log', rated=1)),
                         sorted(int(no) for no, code in self.codes.items() if code in ('B', 'P', '!')))

    def test_one_line_gives_its_entries_with_their_status(self):
        malware = next(no for no, code in self.codes.items() if code == 'B')
        [line] = self.correlations('spor-log', line=malware)['untrusted_lines']
        entries = line['self_links']['entries']
        self.assertEqual(len(entries), line['self_links']['entry_count'])
        self.assertIn('B', [entry['status'] for entry in entries])
        # A linked line without a marker still answers when asked by number.
        plain = next((no for no, code in self.codes.items() if not code), None)
        if plain is not None:
            [line] = self.correlations('spor-log', line=plain)['untrusted_lines']
            self.assertFalse(line['self_links']['notable'])

    def test_a_stored_centralbox_result_is_shown_but_never_rates_a_link(self):
        from ..models import HashVerdict

        links = spor_self.compute('spor-log', SPOR_LINKS)
        # A line linking a FILES hash through a link that may rate (the same
        # file), yet rates nothing from the log alone.
        no, sha = next(
            (no, entry['sha256']) for no in links.codes for entry in links.entries(no)
            if entry.get('kind') == 'file_info' and entry.get('sha256') and spor_self.rates(entry)
            and not spor_self.rating_status(entry)
        )
        HashVerdict.objects.create(sha256=sha, state='known', verdict='malicious', family='testrat',
                                   checked_at=timezone.now(), next_check_at=timezone.now() + timedelta(days=7))
        line = self.correlations('spor-log', line=no)['untrusted_lines'][0]
        entry = next(entry for entry in line['self_links']['entries'] if entry.get('sha256') == sha)
        self.assertEqual(entry['centralbox']['verdict'], 'malicious')
        # Statuses come from the log alone: the entry agrees with the line's.
        self.assertEqual(entry['status'], '')
        self.assertEqual(line['self_links']['status'], links.codes[no] if links.codes[no] != 'm' else '')

    def test_extra_units_only_when_the_log_was_not_read_yet(self):
        with mock.patch.object(llm_api, 'charge_api_units', return_value=True) as charge:
            self.correlations('spor-log')
        self.assertIn(mock.call(mock.ANY, llm_api.SPOR_SELF_EXTRA_UNITS), charge.call_args_list)
        with mock.patch.object(llm_api, 'charge_api_units', return_value=True) as charge:
            self.correlations('spor-log')
        self.assertNotIn(mock.call(mock.ANY, llm_api.SPOR_SELF_EXTRA_UNITS), charge.call_args_list)

    def test_over_the_budget_is_429(self):
        with mock.patch.object(llm_api, 'charge_api_units', return_value=False):
            self.correlations('spor-log', expect=429)


class EndpointTests(LinkedApiBase):
    def test_unknown_and_trashed_uploads_are_404(self):
        self.correlations('no-such-log', expect=404)
        self.add_log('mb-log', MB_SAME)
        UploadedLog.objects.filter(upload_id='mb-log').move_to_trash()
        self.correlations('mb-log', expect=404)

    def test_bad_values_are_400(self):
        for params in ({'self_links': 'some'}, {'line': 'x'}, {'line': 0}, {'limit': 'many'}, {'full': 'maybe'}):
            self.correlations('frst-log', expect=400, **params)

    def test_paging(self):
        self.add_spor()
        body = self.correlations('spor-log', self_links='all', limit=2, offset=1)
        everything = self.correlations('spor-log', self_links='all')
        self.assertEqual(body['matching_line_count'], everything['matching_line_count'])
        self.assertEqual(body['untrusted_lines'], everything['untrusted_lines'][1:3])

    def test_counts_as_an_upload_read_and_names_version_4(self):
        self.assertIn('api_v1_upload_correlations', UPLOAD_READ_ENDPOINTS)
        response = self.call('api_v1_upload_correlations', 'frst-log')
        # At least 4: the MCP's get_correlations needs version 4 (later versions only add).
        self.assertGreaterEqual(int(response[API_VERSION_HEADER]), 4)
        self.assertTrue(ApiRequestLog.objects.filter(endpoint='api_v1_upload_correlations', target='frst-log').exists())


class CaseLinkedFindingsTests(LinkedApiBase):
    def timeline_logs(self):
        response = self.call('api_v1_case', self.case.case_id)
        self.assertEqual(response.status_code, 200, response.content)
        return {entry['upload']['upload_id']: entry for entry in response.json()['timeline'] if entry['type'] == 'log'}

    def test_other_logs_get_linked_findings_and_frst_logs_keep_theirs(self):
        self.malicious_verdict()
        self.add_log('mb-log', MB_SAME)
        logs = self.timeline_logs()
        [finding] = logs['mb-log']['linked_findings']
        self.assertEqual(
            {key: finding[key] for key in ('n', 'text', 'source', 'status')},
            {'n': 1, 'text': MB_SAME, 'source': 'frst', 'status': 'B'},
        )
        self.assertIn(f'L{RUN_NO}', finding['note'])
        self.assertEqual(logs['mb-log']['linked_findings_total'], 1)
        self.assertNotIn('correlated_findings', logs['mb-log'])
        self.assertNotIn('linked_findings', logs['frst-log'])
        [correlated] = logs['frst-log']['correlated_findings']
        self.assertEqual((correlated['n'], correlated['correlation_status']), (RUN_NO, 'B'))

    def test_a_spor_log_lists_its_own_rated_lines(self):
        self.add_spor()
        codes = spor_self.compute('spor-log', SPOR_LINKS).codes
        spor = self.timeline_logs()['spor-log']
        rated = sorted(int(no) for no, code in codes.items() if code in ('B', 'P', '!'))
        self.assertEqual([finding['n'] for finding in spor['linked_findings']], rated)
        self.assertEqual({finding['source'] for finding in spor['linked_findings']}, {'spor'})
        for finding in spor['linked_findings']:
            self.assertEqual(finding['status'], codes[str(finding['n'])])
            self.assertRegex(finding['note'], r'^L\d+')

    def test_a_log_before_its_never_analyzed_frst_log_still_gets_the_frst_findings(self):
        # The FRST log's verdict from a real rule, analyzed by nobody yet, and the
        # scanner log earlier in the timeline, so it is read first.
        make_rule(RUN_LINE)
        UploadedLogAnalysis.objects.filter(upload=self.frst).delete()
        mb = self.add_log('mb-log', MB_SAME)
        InfectionCaseLog.objects.filter(uploaded_log=mb).update(added_at=timezone.now() - timedelta(days=1))
        UploadedLog.objects.filter(pk=mb.pk).update(created_at=timezone.now() - timedelta(days=1))
        timeline = self.call('api_v1_case', self.case.case_id).json()['timeline']
        order = [entry['upload']['upload_id'] for entry in timeline if entry['type'] == 'log']
        self.assertEqual(order, ['mb-log', 'frst-log'])
        [finding] = timeline[0]['linked_findings']
        self.assertEqual((finding['n'], finding['source'], finding['status']), (1, 'frst', 'B'))

    def test_over_the_budget_the_case_is_served_without_linked_findings(self):
        self.add_log('mb-log', MB_SAME)
        # The FRST log's own answer is stored, so only the reverse answer costs units.
        self.analysis()
        real = llm_api.charge_api_units

        def charge(request, units):
            return False if units == llm_api.CORRELATION_RECOMPUTE_EXTRA_UNITS else real(request, units)

        missing = {'scope': '', 'name': '', 'fresh': False, 'missing': True, 'lines': {}, 'texts': {}}
        with mock.patch.object(llm_api, 'charge_api_units', side_effect=charge), \
                mock.patch.object(llm_api, 'reverse_correlations', return_value=missing):
            logs = self.timeline_logs()
        self.assertNotIn('linked_findings', logs['mb-log'])
        self.assertEqual(logs['mb-log']['linked_findings_unavailable'], llm_api.LINKED_FINDINGS_UNAVAILABLE)
        self.assertEqual(logs['frst-log']['correlated_findings'][0]['n'], RUN_NO)

    def test_findings_are_capped_with_the_total(self):
        self.add_spor()
        with mock.patch.object(llm_api, 'LINKED_FINDINGS_MAX', 1):
            spor = self.timeline_logs()['spor-log']
        self.assertEqual(len(spor['linked_findings']), 1)
        self.assertGreater(spor['linked_findings_total'], 1)
