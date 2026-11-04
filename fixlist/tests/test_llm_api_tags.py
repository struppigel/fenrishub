"""Tests for rule tags in the token API: searching logs by tag, the tag filter
on an analysis, and the speeches recommended for a log or one of its lines.

Cached analyses are written by hand, so the analyzer never runs.
"""

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..models import RuleTag, Speech, UploadedLog, UploadedLogAnalysis
from .factories import make_rule, make_user
from .test_llm_api import ApiTestBase


def _line(text, rule_ids=()):
    return {'line': text, 'dominant_status': 'B' if rule_ids else '?', 'rule_ids': list(rule_ids)}


def _payload(lines=(), warnings=(), wholelog_rule_ids=()):
    return {
        'format': ANALYSIS_PAYLOAD_FORMAT,
        'lines': list(lines),
        'summary': {},
        'warnings': list(warnings),
        'wholelog_rule_ids': list(wholelog_rule_ids),
    }


class ApiTagTestBase(ApiTestBase):
    def setUp(self):
        super().setUp()
        self.miner_rule = make_rule('C:\\miner.exe')
        self.adware_rule = make_rule('C:\\adware.exe')
        self.miner = RuleTag.objects.create(name='Coin Miner')
        self.adware = RuleTag.objects.create(name='adware')
        self.miner_rule.tags.add(self.miner)
        self.adware_rule.tags.add(self.adware)

    def _log(self, upload_id, content='Scan result of Farbar Recovery Scan Tool', lines=None, **payload):
        log = UploadedLog.objects.create(
            upload_id=upload_id, forum_username='poster', original_filename=f'{upload_id}.txt',
            content=content, log_type='FRST',
        )
        if lines is not None or payload:
            UploadedLogAnalysis.objects.create(
                upload=log, rule_set_key='shared', source_content_hash=log.content_hash,
                payload=_payload(lines=lines or (), **payload),
            )
        return log

    def _ids(self, response, key):
        return sorted(entry['upload_id'] for entry in response.json()[key])


class ApiUploadsTagFilterTests(ApiTagTestBase):

    def test_filters_by_tag_name_ignoring_case_and_by_id(self):
        self._log('tagged', lines=[_line('x', [self.miner_rule.pk])])
        self._log('untagged', lines=[_line('x')])

        by_name = self.api_get('api_v1_uploads', data={'tags': 'coin miner'})
        by_id = self.api_get('api_v1_uploads', data={'tags': str(self.miner.pk)})

        self.assertEqual(self._ids(by_name, 'uploads'), ['tagged'])
        self.assertEqual(self._ids(by_id, 'uploads'), ['tagged'])
        self.assertEqual(by_name.json()['total'], 1)

    def test_every_tag_must_be_present(self):
        self._log('both', lines=[_line('x', [self.miner_rule.pk]), _line('y', [self.adware_rule.pk])])
        self._log('only-miner', lines=[_line('x', [self.miner_rule.pk])])

        response = self.api_get('api_v1_uploads', data={'tags': 'coin miner, adware'})

        self.assertEqual(self._ids(response, 'uploads'), ['both'])

    def test_unknown_tag_is_an_error_naming_it(self):
        response = self.api_get('api_v1_uploads', data={'tags': 'adware,nosuchtag'})

        self.assertEqual(response.status_code, 400)
        self.assertIn('nosuchtag', response.json()['error'])

    def test_reports_logs_without_an_analysis(self):
        self._log('never-analyzed')

        response = self.api_get('api_v1_uploads', data={'tags': 'adware'})

        self.assertEqual(response.json()['tag_unanalyzed_count'], 1)

    def test_without_tags_the_response_is_unchanged(self):
        self._log('plain')

        response = self.api_get('api_v1_uploads')

        self.assertNotIn('tag_unanalyzed_count', response.json())
        self.assertEqual(self._ids(response, 'uploads'), ['plain'])


class ApiSearchTagFilterTests(ApiTagTestBase):

    def test_tags_only_search_shows_the_tagged_line(self):
        content = 'Scan result of Farbar Recovery Scan Tool\n\nR1 C:\\miner.exe\n'
        self._log('tagged', content=content, lines=[
            _line('Scan result of Farbar Recovery Scan Tool'),
            _line('R1 C:\\miner.exe', [self.miner_rule.pk]),
        ])
        self._log('untagged', content=content + 'x', lines=[_line('R1 C:\\miner.exe')])

        response = self.api_get('api_v1_search', data={'tags': 'coin miner'})

        self.assertEqual(response.status_code, 200)
        matches = response.json()['matches']
        self.assertEqual([match['upload_id'] for match in matches], ['tagged'])
        self.assertEqual(matches[0]['first_hit'], {'line_number': 3, 'untrusted_text': 'R1 C:\\miner.exe'})
        self.assertEqual(response.json()['tag_unanalyzed_count'], 0)

    def test_query_and_tags_combine(self):
        self._log('both', content='needle line', lines=[_line('needle line', [self.miner_rule.pk])])
        self._log('text-only', content='needle again', lines=[_line('needle again')])
        self._log('tag-only', content='haystack', lines=[_line('haystack', [self.miner_rule.pk])])

        response = self.api_get('api_v1_search', data={'q': 'needle', 'tags': 'coin miner'})

        self.assertEqual(self._ids(response, 'matches'), ['both'])

    def test_needs_a_query_or_tags(self):
        response = self.api_get('api_v1_search')

        self.assertEqual(response.status_code, 400)
        self.assertIn('q or tags', response.json()['error'])


class ApiAnalysisTagFilterTests(ApiTagTestBase):

    def test_tags_filter_keeps_tagged_lines_and_lines_name_their_tags(self):
        content = 'R1 C:\\miner.exe\nR2 C:\\adware.exe\nR3 clean'
        self._log('lines', content=content, lines=[
            _line('R1 C:\\miner.exe', [self.miner_rule.pk]),
            _line('R2 C:\\adware.exe', [self.adware_rule.pk]),
            _line('R3 clean'),
        ])

        response = self.api_get('api_v1_upload_analysis', 'lines', data={'tags': 'adware'})

        self.assertEqual(response.status_code, 200)
        lines = response.json()['untrusted_lines']
        self.assertEqual([(line['n'], line['tags']) for line in lines], [(2, ['adware'])])
        self.assertEqual(response.json()['matching_line_count'], 1)

    def test_lines_carry_tag_names_without_a_filter(self):
        self._log('names', content='R1 C:\\miner.exe', lines=[_line('R1 C:\\miner.exe', [self.miner_rule.pk])])

        response = self.api_get('api_v1_upload_analysis', 'names')

        self.assertEqual(response.json()['untrusted_lines'][0]['tags'], ['Coin Miner'])


class ApiUploadSpeechesTests(ApiTagTestBase):

    def setUp(self):
        super().setUp()
        self.other = make_user('bob')
        # The caller's own selected speech for miners.
        self.own_miner = Speech.objects.create(owner=self.user, name='mining reply', content='Remove the miner.')
        self.own_miner.trigger_tags.add(self.miner)
        self.own_miner.analyzer_users.add(self.user)
        # Another helper's shared speeches: one for a tag the caller covers, one for a tag they do not.
        self.shared_miner = Speech.objects.create(owner=self.other, name='their miner reply', content='x', is_shared=True)
        self.shared_miner.trigger_tags.add(self.miner)
        self.shared_adware = Speech.objects.create(owner=self.other, name='their adware reply', content='y', is_shared=True)
        self.shared_adware.trigger_tags.add(self.adware)
        # Not shared and not selected: never offered.
        self.private_adware = Speech.objects.create(owner=self.other, name='private adware reply', content='z')
        self.private_adware.trigger_tags.add(self.adware)

        self._log('infected', content='R1 C:\\miner.exe\n\nR2 C:\\adware.exe', lines=[
            _line('R1 C:\\miner.exe', [self.miner_rule.pk]),
            _line('R2 C:\\adware.exe', [self.adware_rule.pk]),
        ])

    def _names(self, response, key):
        return [speech['name'] for speech in response.json()[key]]

    def test_log_level_suggests_own_speeches_and_falls_back_for_uncovered_tags(self):
        response = self.api_get('api_v1_upload_speeches', 'infected')

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(self._names(response, 'suggested'), ['mining reply'])
        self.assertEqual(self._names(response, 'shared_fallback'), ['their adware reply'])
        self.assertEqual(body['suggested'][0]['for_tag_ids'], [self.miner.pk])
        self.assertEqual(sorted(tag['name'] for tag in body['tags']), ['Coin Miner', 'adware'])
        self.assertIn('{HELPERNAME}', body['placeholders'])
        self.assertIsNone(body['line_number'])

    def test_line_level_uses_that_lines_tags_only(self):
        miner_line = self.api_get('api_v1_upload_speeches', 'infected', data={'line': 1})
        adware_line = self.api_get('api_v1_upload_speeches', 'infected', data={'line': 3})

        self.assertEqual(self._names(miner_line, 'suggested'), ['mining reply'])
        self.assertEqual(miner_line.json()['shared_fallback'], [])
        self.assertEqual(miner_line.json()['untrusted_line_text'], 'R1 C:\\miner.exe')
        self.assertEqual(self._names(adware_line, 'suggested'), [])
        self.assertEqual(self._names(adware_line, 'shared_fallback'), ['their adware reply'])

    def test_blank_or_missing_line_is_an_error(self):
        blank = self.api_get('api_v1_upload_speeches', 'infected', data={'line': 2})
        past_end = self.api_get('api_v1_upload_speeches', 'infected', data={'line': 99})

        self.assertEqual(blank.status_code, 400)
        self.assertEqual(past_end.status_code, 400)

    def test_unknown_upload_is_not_found(self):
        response = self.api_get('api_v1_upload_speeches', 'no-such-log')

        self.assertEqual(response.status_code, 404)
