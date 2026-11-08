"""Version 2 additions to the token API: line search, slices, compact analysis, scopes, duplicates.

Every addition is opt-in: a request without the new parameters gets the same
response as in version 1, so MCP servers other helpers already run keep working.
"""

import json
from datetime import datetime, timedelta

from django.urls import reverse
from django.utils import timezone

from ..models import UploadedLog, UploadedLogAnalysis
from ..views.api_auth import API_VERSION, API_VERSION_HEADER
from .factories import make_uploaded_log
from .test_llm_api import ApiTestBase, fake_analysis

TASK_LINE = (
    r'Task: {9ADF6FEE} - System32\Tasks\Updater => '
    r'C:\Users\Bob\AppData\Roaming\BuilderBeta.exe [213708 2026-07-07] () [File not signed]'
)


def cache_analysis(uploaded_log, lines, rule_set_key='shared'):
    """Store a cached analysis whose non-blank lines get the given statuses, in order."""
    payload = fake_analysis(lines)
    for index, entry in enumerate(payload['lines']):
        entry['rule_ids'] = [100 + index]
    UploadedLogAnalysis.objects.create(
        upload=uploaded_log, rule_set_key=rule_set_key, payload=payload,
        source_content_hash=uploaded_log.content_hash,
    )


def set_created(upload_id, when):
    UploadedLog.objects.filter(upload_id=upload_id).update(created_at=when)


class ApiV2Base(ApiTestBase):
    def api_post(self, name, body, *args):
        return self.client.post(
            reverse(name, args=args), json.dumps(body), content_type='application/json',
            secure=True, HTTP_AUTHORIZATION=f'Bearer {self.raw}',
        )

    def search(self, **params):
        response = self.api_get('api_v1_search', data=params)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()


class VersionAndCompatibilityTests(ApiV2Base):
    def test_every_response_names_the_api_version(self):
        response = self.api_get('api_v1_uploads')
        self.assertEqual(response[API_VERSION_HEADER], str(API_VERSION))

    def test_default_search_keeps_its_version_1_shape(self):
        make_uploaded_log('amber-falcon', content='line one\nC:\\evil\\payload.exe here\n')
        body = self.search(q='payload.exe')
        self.assertTrue({'truncated', 'limit', 'matches'} <= set(body))
        self.assertFalse(body['truncated'])
        match = body['matches'][0]
        self.assertEqual(match['first_hit'], {'line_number': 2, 'untrusted_text': 'C:\\evil\\payload.exe here'})
        self.assertNotIn('verdicts_from', match)
        self.assertNotIn('totals', body)

    def test_default_upload_and_analysis_keep_their_version_1_shape(self):
        make_uploaded_log('amber-falcon', content='first\nsecond\n')
        body = self.api_get('api_v1_upload', 'amber-falcon').json()
        self.assertEqual(body['untrusted_content'], 'first\nsecond\n')
        self.assertNotIn('untrusted_lines', body)
        body = self.api_get('api_v1_upload_analysis', 'amber-falcon').json()
        self.assertTrue({'summary', 'warnings', 'rule_tags', 'status_legend', 'untrusted_lines'} <= set(body))
        self.assertIn('reasons', body['untrusted_lines'][0])


class LineSearchTests(ApiV2Base):
    def test_all_hits_per_log_with_the_total(self):
        make_uploaded_log('amber-falcon', content='evil a\nclean\nevil b\nevil c\n')
        match = self.search(q='evil', lines_per_log=2)['matches'][0]
        self.assertEqual(match['hit_count'], 3)
        self.assertEqual([hit['line_number'] for hit in match['hits']], [1, 3])
        self.assertEqual(match['first_hit']['line_number'], 1)

    def test_case_sensitive_search(self):
        make_uploaded_log('amber-falcon', content='run Evil.EXE\n')
        self.assertEqual(len(self.search(q='evil.exe')['matches']), 1)
        self.assertEqual(self.search(q='evil.exe', case_sensitive=1)['matches'], [])
        self.assertEqual(len(self.search(q='Evil.EXE', case_sensitive=1)['matches']), 1)
        self.assertEqual(self.search(q=r'[a-z]{4}\.exe', regex=1, case_sensitive=1)['matches'], [])
        self.assertEqual(len(self.search(q=r'[A-Z]{4}\.exe', regex=1, case_sensitive=1)['matches']), 0)
        self.assertEqual(len(self.search(q=r'E[a-z]{3}\.EXE', regex=1, case_sensitive=1)['matches']), 1)

    def test_status_filter_reads_the_cached_verdicts(self):
        analyzed = make_uploaded_log('amber-falcon', content='evil a\n\nevil b\nevil c\n')
        cache_analysis(analyzed, [('evil a', 'B'), ('evil b', '?'), ('evil c', 'P')])
        make_uploaded_log('brave-otter', content='evil never analyzed\n')

        body = self.search(q='evil', statuses='?,P', lines_per_log=10)
        [match] = body['matches']
        self.assertEqual(match['upload_id'], 'amber-falcon')
        self.assertEqual(match['hit_count'], 2)
        self.assertEqual(
            [(hit['line_number'], hit['status'], hit['rule_ids']) for hit in match['hits']],
            [(3, '?', [101]), (4, 'P', [102])],
        )
        self.assertEqual(match['verdicts_from'], 'shared')
        self.assertEqual(body['unanalyzed_count'], 1)

    def test_with_verdicts_annotates_without_filtering(self):
        analyzed = make_uploaded_log('amber-falcon', content='evil a\nevil b\n')
        cache_analysis(analyzed, [('evil a', 'B'), ('evil b', 'C')])
        make_uploaded_log('brave-otter', content='evil c\n')
        body = self.search(q='evil', with_verdicts=1, lines_per_log=5)
        by_id = {match['upload_id']: match for match in body['matches']}
        self.assertEqual([hit['status'] for hit in by_id['amber-falcon']['hits']], ['B', 'C'])
        self.assertEqual(by_id['brave-otter']['hits'][0]['status'], None)
        self.assertIsNone(by_id['brave-otter']['verdicts_from'])

    def test_unknown_status_is_400(self):
        self.assertEqual(self.api_get('api_v1_search', data={'q': 'x', 'statuses': 'X'}).status_code, 400)

    def test_long_query_by_post(self):
        make_uploaded_log('amber-falcon', content='vendor-' + 'a' * 1500 + '\n')
        query = 'vendor-' + 'a' * 1500
        response = self.api_post('api_v1_search', {'q': query})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['matches']), 1)
        self.assertEqual(self.api_post('api_v1_search', {'q': 'a' * 2001}).status_code, 400)

    def test_post_takes_json_values(self):
        make_uploaded_log('amber-falcon', content='Evil\n', log_type='FRST')
        response = self.api_post('api_v1_search', {
            'q': 'Evil', 'case_sensitive': True, 'lines_per_log': 3, 'type': ['FRST'], 'statuses': [],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()['matches']), 1)

    def test_offset_paging_and_totals(self):
        for index in range(3):
            make_uploaded_log(f'log-{index}', content=f'needle {index}\nneedle again\n', forum_username=f'user{index % 2}')
        first = self.search(q='needle', limit=1)
        self.assertTrue(first['truncated'])
        self.assertEqual(first['next_offset'], 1)
        second = self.search(q='needle', limit=1, offset=1)
        self.assertNotEqual(first['matches'][0]['upload_id'], second['matches'][0]['upload_id'])
        last = self.search(q='needle', limit=1, offset=2)
        self.assertFalse(last['truncated'])
        self.assertIsNone(last['next_offset'])

        totals = self.search(q='needle', limit=1, count_all=1)['totals']
        self.assertEqual(totals, {'logs': 3, 'lines': 6, 'distinct_usernames': 2, 'complete': True})

    def test_components_filter(self):
        make_uploaded_log('amber-falcon', content='header\n' + TASK_LINE + '\n')
        make_uploaded_log('brave-otter', content='BuilderBeta.exe mentioned in plain text\n')

        body = self.search(components=json.dumps({'filename': 'builderbeta.exe'}))
        self.assertEqual([match['upload_id'] for match in body['matches']], ['amber-falcon'])
        self.assertEqual(body['matches'][0]['first_hit']['line_number'], 2)

        # Paths compare normalized, like rules: another user's profile folder still matches.
        path = r'C:\Users\Someone\AppData\Roaming\BuilderBeta.exe'
        body = self.search(components=json.dumps({'filepath': path, 'entry_type': 'scheduled_task'}))
        self.assertEqual(len(body['matches']), 1)
        body = self.search(components=json.dumps({'filename': 'BuilderBeta.exe', 'entry_type': 'runkey'}))
        self.assertEqual(body['matches'], [])

    def test_components_combine_with_the_query(self):
        make_uploaded_log('amber-falcon', content=TASK_LINE + '\n')
        body = self.search(q='Updater', components=json.dumps({'filename': 'BuilderBeta.exe'}))
        self.assertEqual(len(body['matches']), 1)
        body = self.search(q='nothing-like-this', components=json.dumps({'filename': 'BuilderBeta.exe'}))
        self.assertEqual(body['matches'], [])

    def test_unknown_component_is_400(self):
        response = self.api_get('api_v1_search', data={'components': json.dumps({'colour': 'red'})})
        self.assertEqual(response.status_code, 400)
        response = self.api_get('api_v1_search', data={'components': 'not json'})
        self.assertEqual(response.status_code, 400)

    def test_exclude_type_and_dates(self):
        make_uploaded_log('the-frst', content='needle\n', log_type='FRST')
        make_uploaded_log('the-fixlog', content='needle\n', log_type='Fixlog')
        set_created('the-fixlog', timezone.now() - timedelta(days=10))
        body = self.search(q='needle', exclude_type='Fixlog')
        self.assertEqual([match['upload_id'] for match in body['matches']], ['the-frst'])
        since = (timezone.localdate() - timedelta(days=1)).isoformat()
        body = self.search(q='needle', created_after=since)
        self.assertEqual([match['upload_id'] for match in body['matches']], ['the-frst'])
        body = self.search(q='needle', created_before=(timezone.localdate() - timedelta(days=5)).isoformat())
        self.assertEqual([match['upload_id'] for match in body['matches']], ['the-fixlog'])

    def test_dedupe_in_search(self):
        make_uploaded_log('first-copy', content='needle\n')
        make_uploaded_log('second-copy', content='needle\n')
        body = self.search(q='needle', dedupe=1)
        self.assertEqual(len(body['matches']), 1)
        self.assertEqual(body['duplicates_hidden'], 1)

    def test_tags_only_search_lists_tagged_lines(self):
        from ..models import ClassificationRule, RuleTag
        tag = RuleTag.objects.create(name='RenLoader')
        rule = ClassificationRule.objects.create(source_text='evil b', status='B', match_type='exact')
        rule.tags.add(tag)
        log = make_uploaded_log('amber-falcon', content='evil a\nevil b\n')
        payload = fake_analysis([('evil a', 'C'), ('evil b', 'B')])
        payload['lines'][1]['rule_ids'] = [rule.pk]
        UploadedLogAnalysis.objects.create(
            upload=log, rule_set_key='shared', payload=payload, source_content_hash=log.content_hash,
        )
        body = self.search(tags='RenLoader', lines_per_log=5)
        [match] = body['matches']
        self.assertEqual(match['first_hit']['line_number'], 2)
        self.assertEqual(match['hit_count'], 1)


class UploadSliceTests(ApiV2Base):
    def setUp(self):
        super().setUp()
        content = '\n'.join(f'line {number}' for number in range(1, 11)) + '\nDetected: Trojan.X\n'
        make_uploaded_log('amber-falcon', content=content)

    def test_line_range(self):
        body = self.api_get('api_v1_upload', 'amber-falcon', data={'start_line': 3, 'max_lines': 2}).json()
        self.assertEqual(body['untrusted_lines'], [{'n': 3, 'text': 'line 3'}, {'n': 4, 'text': 'line 4'}])
        self.assertEqual(body['next_line'], 5)
        self.assertEqual(body['line_count'], 11)
        self.assertNotIn('untrusted_content', body)

    def test_matching_lines_with_context(self):
        body = self.api_get('api_v1_upload', 'amber-falcon', data={'match': 'trojan', 'context': 1}).json()
        self.assertEqual([line['n'] for line in body['untrusted_lines']], [10, 11])
        self.assertEqual(body['matching_line_count'], 1)
        self.assertIsNone(body['next_line'])

    def test_regex_match(self):
        body = self.api_get('api_v1_upload', 'amber-falcon', data={'match': r'line [2-3]$', 'regex': 1}).json()
        self.assertEqual([line['n'] for line in body['untrusted_lines']], [2, 3])

    def test_bad_regex_is_400(self):
        response = self.api_get('api_v1_upload', 'amber-falcon', data={'match': '(?=x)', 'regex': 1})
        self.assertEqual(response.status_code, 400)


class CompactAnalysisTests(ApiV2Base):
    def setUp(self):
        super().setUp()
        self.log = make_uploaded_log('amber-falcon', content='first\nsecond\n')
        cache_analysis(self.log, [('first', 'B'), ('second', 'C')])

    def test_fields_pick_line_keys(self):
        body = self.api_get('api_v1_upload_analysis', 'amber-falcon', data={'fields': 'n,status,rule_ids'}).json()
        self.assertEqual(body['untrusted_lines'], [
            {'n': 1, 'status': 'B', 'rule_ids': [100]},
            {'n': 2, 'status': 'C', 'rule_ids': [101]},
        ])

    def test_unknown_field_is_400(self):
        response = self.api_get('api_v1_upload_analysis', 'amber-falcon', data={'fields': 'n,colour'})
        self.assertEqual(response.status_code, 400)

    def test_summary_can_be_left_out(self):
        body = self.api_get('api_v1_upload_analysis', 'amber-falcon', data={'summary': '0'}).json()
        for key in ('summary', 'warnings', 'rule_tags', 'status_legend'):
            self.assertNotIn(key, body)
        self.assertEqual(body['matching_line_count'], 2)


class UploadScopeTests(ApiV2Base):
    def test_type_lists_and_exclusions(self):
        make_uploaded_log('the-frst', log_type='FRST')
        make_uploaded_log('the-addition', log_type='Addition')
        make_uploaded_log('the-fixlog', log_type='Fixlog')

        def ids(**params):
            return sorted(u['upload_id'] for u in self.api_get('api_v1_uploads', data=params).json()['uploads'])

        self.assertEqual(ids(type='FRST,Addition'), ['the-addition', 'the-frst'])
        self.assertEqual(ids(exclude_type='Fixlog'), ['the-addition', 'the-frst'])

    def test_created_dates_are_inclusive_days(self):
        make_uploaded_log('older')
        make_uploaded_log('newer')
        moment = timezone.make_aware(datetime(2026, 11, 5, 23, 30))
        set_created('older', moment - timedelta(days=2))
        set_created('newer', moment)

        def ids(**params):
            return [u['upload_id'] for u in self.api_get('api_v1_uploads', data=params).json()['uploads']]

        self.assertEqual(ids(created_after='2026-11-05'), ['newer'])
        self.assertEqual(ids(created_before='2026-11-05'), ['newer', 'older'])
        self.assertEqual(ids(created_before='2026-11-04'), ['older'])
        self.assertEqual(ids(created_after='2026-11-05T23:00'), ['newer'])

    def test_bad_date_is_400(self):
        response = self.api_get('api_v1_uploads', data={'created_after': 'last week'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('created_after', response.json()['error'])


class DuplicateHintTests(ApiV2Base):
    def scan(self, upload_id, log_type, *, username='JohnDoe', content=None, when=None):
        make_uploaded_log(
            upload_id, forum_username=username, log_type=log_type,
            content=content or f'{upload_id} {log_type}',
        )
        UploadedLog.objects.filter(upload_id=upload_id).update(
            scan_date=when or timezone.make_aware(datetime(2026, 11, 1, 10, 0)),
        )

    def listing(self, **params):
        body = self.api_get('api_v1_uploads', data=params).json()
        return body, {upload['upload_id']: upload for upload in body['uploads']}

    def test_identical_content_points_to_the_oldest_copy(self):
        make_uploaded_log('first-copy', content='same text', forum_username='a')
        make_uploaded_log('second-copy', content='same text', forum_username='b')
        set_created('first-copy', timezone.now() - timedelta(hours=1))
        _body, by_id = self.listing()
        self.assertEqual(by_id['second-copy']['duplicate_of'], {'upload_id': 'first-copy', 'reason': 'same_content'})
        self.assertEqual(by_id['first-copy']['duplicates'], ['second-copy'])
        self.assertIsNone(by_id['first-copy']['duplicate_of'])

    def test_merged_log_is_the_canonical_copy_of_its_parts(self):
        self.scan('pasted-frst', 'FRST')
        self.scan('merged-logs', 'FRST&Addition')
        _body, by_id = self.listing()
        self.assertEqual(
            by_id['pasted-frst']['duplicate_of'],
            {'upload_id': 'merged-logs', 'reason': 'same_user_and_scan_date'},
        )
        self.assertEqual(by_id['merged-logs']['duplicates'], ['pasted-frst'])

    def test_frst_and_addition_of_one_run_are_not_copies(self):
        self.scan('the-frst', 'FRST')
        self.scan('the-addition', 'Addition')
        _body, by_id = self.listing()
        self.assertIsNone(by_id['the-frst']['duplicate_of'])
        self.assertIsNone(by_id['the-addition']['duplicate_of'])

    def test_other_user_or_scan_date_is_not_a_copy(self):
        self.scan('johns', 'FRST')
        self.scan('janes', 'FRST', username='JaneDoe')
        self.scan('later', 'FRST', when=timezone.make_aware(datetime(2026, 11, 2, 10, 0)))
        _body, by_id = self.listing()
        self.assertTrue(all(upload['duplicate_of'] is None for upload in by_id.values()))

    def test_dedupe_hides_copies_and_pages_the_rest(self):
        self.scan('pasted-frst', 'FRST')
        self.scan('merged-logs', 'FRST&Addition')
        self.scan('other-scan', 'FRST', username='JaneDoe')
        body, by_id = self.listing(dedupe=1)
        self.assertEqual(set(by_id), {'merged-logs', 'other-scan'})
        self.assertEqual(body['total'], 2)
        self.assertEqual(body['duplicates_hidden'], 1)
        body, by_id = self.listing(dedupe=1, limit=1, offset=1)
        self.assertEqual(len(by_id), 1)

    def test_case_timeline_uploads_carry_the_hints(self):
        from ..models import InfectionCase, InfectionCaseLog
        self.scan('pasted-frst', 'FRST')
        self.scan('merged-logs', 'FRST&Addition')
        case = InfectionCase.objects.create(owner=self.user, username='JohnDoe')
        InfectionCaseLog.objects.create(case=case, uploaded_log=UploadedLog.objects.get(upload_id='pasted-frst'))
        body = self.api_get('api_v1_case', case.case_id).json()
        upload = next(entry['upload'] for entry in body['timeline'] if entry['type'] == 'log')
        self.assertEqual(upload['duplicate_of']['upload_id'], 'merged-logs')
