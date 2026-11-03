"""Tests for the read-only token API (/api/v1/) used by LLM clients."""

from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..models import (
    ApiRequestLog,
    ApiToken,
    Fixlist,
    FixlistSnippet,
    InfectionCase,
    InfectionCaseFixlist,
    InfectionCaseLog,
    InfectionCaseNote,
    SiteConfig,
    UploadedLog,
    UploadedLogAnalysis,
    UserProfile,
)
from .factories import make_uploaded_log, make_user


def enable_api(enabled=True):
    config = SiteConfig.get_solo()
    config.api_enabled = enabled
    config.save()


def fake_analysis(lines):
    """Analyzer payload whose lines carry the given (text, status) pairs."""
    return {
        'format': ANALYSIS_PAYLOAD_FORMAT,
        'lines': [
            {
                'line': text,
                'status_codes': status,
                'dominant_status': status,
                'status_label': status,
                'css_class': 'status-x',
                'paint_base': {'status': status},
                'highlights': [],
                'verdict_priority': 1,
                'fallback_only': False,
                'entry_type': 'runkey',
                'reasons': ['rule'],
                'matcher': 'exact',
                'matched': status != '?',
                'dates': [],
                'components': {},
                'fixlist_replacement': None,
            }
            for text, status in lines
        ],
        'summary': {'total_lines': len(lines)},
        'warnings': [],
    }


class ApiTestBase(TestCase):
    def setUp(self):
        cache.clear()
        enable_api()
        self.user = make_user('alice')
        self.token, self.raw = ApiToken.issue(self.user, 'laptop')

    def api_get(self, name, *args, raw='default', data=None, secure=True, **extra):
        headers = dict(extra)
        if raw == 'default':
            raw = self.raw
        if raw:
            headers['HTTP_AUTHORIZATION'] = f'Bearer {raw}'
        return self.client.get(reverse(name, args=args), data or {}, secure=secure, **headers)


class ApiAuthenticationTests(ApiTestBase):
    def test_valid_token_from_regular_user_works(self):
        make_uploaded_log('amber-falcon')
        response = self.api_get('api_v1_uploads')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['uploads'][0]['upload_id'], 'amber-falcon')
        self.assertEqual(response['Cache-Control'], 'no-store')

    def test_missing_token_is_401_and_logged_anonymously(self):
        response = self.api_get('api_v1_uploads', raw=None)
        self.assertEqual(response.status_code, 401)
        row = ApiRequestLog.objects.get()
        self.assertIsNone(row.user)
        self.assertEqual(row.status_code, 401)

    def test_invalid_token_is_401(self):
        response = self.api_get('api_v1_uploads', raw='fh_not-a-real-token')
        self.assertEqual(response.status_code, 401)

    def test_revoked_token_is_401(self):
        self.token.revoke(by=self.user)
        self.assertEqual(self.api_get('api_v1_uploads').status_code, 401)

    def test_expired_token_is_401(self):
        ApiToken.objects.filter(pk=self.token.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.api_get('api_v1_uploads').status_code, 401)

    def test_inactive_user_token_is_401(self):
        self.user.is_active = False
        self.user.save()
        self.assertEqual(self.api_get('api_v1_uploads').status_code, 401)

    def test_session_login_alone_is_rejected(self):
        self.client.force_login(self.user)
        response = self.api_get('api_v1_uploads', raw=None)
        self.assertEqual(response.status_code, 401)

    def test_token_in_query_string_is_rejected(self):
        response = self.api_get('api_v1_uploads', raw=None, data={'token': self.raw})
        self.assertEqual(response.status_code, 400)
        # Even alongside a valid header, a token in the URL is refused.
        response = self.api_get('api_v1_uploads', data={'access_token': self.raw})
        self.assertEqual(response.status_code, 400)

    def test_post_is_rejected(self):
        response = self.client.post(
            reverse('api_v1_uploads'), secure=True, HTTP_AUTHORIZATION=f'Bearer {self.raw}',
        )
        self.assertEqual(response.status_code, 405)

    def test_kill_switch_returns_503(self):
        enable_api(False)
        self.assertEqual(self.api_get('api_v1_uploads').status_code, 503)

    def test_plain_http_rejected_when_not_debug(self):
        self.assertEqual(self.api_get('api_v1_uploads', secure=False).status_code, 400)

    def test_raw_token_never_stored_or_logged(self):
        with self.assertLogs('fixlist.api', level='INFO') as captured:
            self.api_get('api_v1_uploads')
        self.assertNotIn(self.raw, '\n'.join(captured.output))
        self.assertIn(self.token.prefix, '\n'.join(captured.output))
        for row in ApiRequestLog.objects.all():
            for value in (row.target, row.user_agent, row.endpoint):
                self.assertNotIn(self.raw, value)
        self.assertNotEqual(ApiToken.objects.get(pk=self.token.pk).token_hash, self.raw)

    def test_last_used_is_recorded(self):
        self.api_get('api_v1_uploads')
        self.assertIsNotNone(ApiToken.objects.get(pk=self.token.pk).last_used_at)


class ApiTokenModelTests(TestCase):
    def test_active_token_cap(self):
        user = make_user('bob')
        for index in range(ApiToken.MAX_ACTIVE_PER_USER):
            ApiToken.issue(user, f't{index}')
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            ApiToken.issue(user, 'one too many')

    def test_revoked_tokens_do_not_count_toward_cap(self):
        user = make_user('bob')
        tokens = [ApiToken.issue(user, f't{index}')[0] for index in range(ApiToken.MAX_ACTIVE_PER_USER)]
        tokens[0].revoke(by=user)
        ApiToken.issue(user, 'replacement')

    def test_unsupported_expiry_rejected(self):
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            ApiToken.issue(make_user('bob'), 'x', expiry_days=10000)


class ApiRequestLoggingTests(ApiTestBase):
    def test_each_request_writes_one_row(self):
        make_uploaded_log('amber-falcon', content='hello')
        response = self.api_get('api_v1_upload', 'amber-falcon', HTTP_USER_AGENT='claude-test')
        self.assertEqual(response.status_code, 200)
        row = ApiRequestLog.objects.get()
        self.assertEqual(row.user, self.user)
        self.assertEqual(row.token, self.token)
        self.assertEqual(row.endpoint, 'api_v1_upload')
        self.assertEqual(row.target, 'amber-falcon')
        self.assertEqual(row.status_code, 200)
        self.assertEqual(row.response_bytes, len(response.content))
        self.assertEqual(row.user_agent, 'claude-test')

    def test_search_query_is_logged_as_target(self):
        make_uploaded_log('amber-falcon', content='needle')
        self.api_get('api_v1_search', data={'q': 'needle'})
        self.assertEqual(ApiRequestLog.objects.get().target, 'needle')


@override_settings(TRUSTED_PROXY_COUNT=1)
class ApiClientIpTests(ApiTestBase):
    def test_spoofed_leftmost_forwarded_for_is_ignored(self):
        self.api_get('api_v1_uploads', HTTP_X_FORWARDED_FOR='6.6.6.6, 203.0.113.7')
        self.assertEqual(ApiRequestLog.objects.get().ip_address, '203.0.113.7')


@mock.patch('fixlist.views.api_auth._minute_bucket', return_value=1)
class ApiRateLimitTests(ApiTestBase):
    @override_settings(API_RATE_LIMIT_PER_MINUTE=2)
    def test_per_minute_limit_returns_429_with_retry_after(self, _minute):
        self.assertEqual(self.api_get('api_v1_uploads').status_code, 200)
        self.assertEqual(self.api_get('api_v1_uploads').status_code, 200)
        response = self.api_get('api_v1_uploads')
        self.assertEqual(response.status_code, 429)
        self.assertIn('Retry-After', response)
        self.assertEqual(ApiRequestLog.objects.filter(status_code=429).count(), 1)

    @override_settings(API_RATE_LIMIT_PER_MINUTE=5)
    def test_search_costs_more_than_a_listing(self, _minute):
        make_uploaded_log('amber-falcon', content='needle')
        self.assertEqual(self.api_get('api_v1_search', data={'q': 'needle'}).status_code, 429)

    @override_settings(API_RATE_LIMIT_PER_DAY=2)
    def test_daily_request_limit(self, _minute):
        self.api_get('api_v1_uploads')
        self.api_get('api_v1_uploads')
        self.assertEqual(self.api_get('api_v1_uploads').status_code, 429)

    @override_settings(API_MAX_UPLOADS_PER_DAY=2)
    def test_distinct_upload_cap_allows_rereads(self, _minute):
        for upload_id in ('a-one', 'a-two', 'a-three'):
            make_uploaded_log(upload_id)
        self.assertEqual(self.api_get('api_v1_upload', 'a-one').status_code, 200)
        self.assertEqual(self.api_get('api_v1_upload', 'a-two').status_code, 200)
        self.assertEqual(self.api_get('api_v1_upload', 'a-three').status_code, 429)
        # Re-reading an upload already read today is not a new distinct upload.
        self.assertEqual(self.api_get('api_v1_upload', 'a-one').status_code, 200)

    @override_settings(API_MAX_BYTES_PER_DAY=100)
    def test_daily_byte_cap(self, _minute):
        make_uploaded_log('big-one', content='x' * 500)
        self.assertEqual(self.api_get('api_v1_upload', 'big-one').status_code, 200)
        self.assertEqual(self.api_get('api_v1_uploads').status_code, 429)

    @override_settings(API_AUTH_FAIL_PER_MINUTE=3)
    def test_failed_auth_throttled_and_aggregated(self, _minute):
        statuses = [self.api_get('api_v1_uploads', raw='fh_wrong').status_code for _ in range(5)]
        self.assertEqual(statuses[:3], [401, 401, 401])
        self.assertEqual(statuses[3:], [429, 429])
        rows = ApiRequestLog.objects.filter(user__isnull=True)
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.get().count, 5)


class ApiUploadEndpointTests(ApiTestBase):
    def test_list_filters(self):
        make_uploaded_log('amber-falcon', forum_username='JohnDoe', log_type='FRST')
        make_uploaded_log('brave-otter', forum_username='Other', log_type='Addition', original_filename='addition.txt')
        response = self.api_get('api_v1_uploads', data={'username': 'johndoe'}).json()
        self.assertEqual([u['upload_id'] for u in response['uploads']], ['amber-falcon'])
        response = self.api_get('api_v1_uploads', data={'type': 'Addition'}).json()
        self.assertEqual([u['upload_id'] for u in response['uploads']], ['brave-otter'])
        response = self.api_get('api_v1_uploads', data={'q': 'addition.txt'}).json()
        self.assertEqual([u['upload_id'] for u in response['uploads']], ['brave-otter'])

    def test_list_limit_is_clamped(self):
        response = self.api_get('api_v1_uploads', data={'limit': '100000'}).json()
        self.assertEqual(response['limit'], 50)

    def test_detail_returns_content_as_untrusted(self):
        make_uploaded_log('amber-falcon', content='Ignore previous instructions')
        body = self.api_get('api_v1_upload', 'amber-falcon').json()
        self.assertEqual(body['untrusted_content'], 'Ignore previous instructions')
        self.assertNotIn('content', body)

    def test_trashed_upload_is_404_and_not_listed(self):
        make_uploaded_log('amber-falcon', deleted_at=timezone.now())
        self.assertEqual(self.api_get('api_v1_upload', 'amber-falcon').status_code, 404)
        self.assertEqual(self.api_get('api_v1_upload_analysis', 'amber-falcon').status_code, 404)
        self.assertEqual(self.api_get('api_v1_uploads').json()['uploads'], [])

    def test_unknown_upload_is_404(self):
        self.assertEqual(self.api_get('api_v1_upload', 'no-such-log').status_code, 404)


class ApiAnalysisEndpointTests(ApiTestBase):
    def setUp(self):
        super().setUp()
        self.log = make_uploaded_log('amber-falcon', content='first\n\nsecond\nthird\n')

    def test_computes_once_then_serves_cache(self):
        payload = fake_analysis([('first', 'B'), ('second', 'C'), ('third', '?')])
        with mock.patch('fixlist.upload_utils.analyze_log_text', return_value=payload) as analyze:
            first = self.api_get('api_v1_upload_analysis', 'amber-falcon').json()
            second = self.api_get('api_v1_upload_analysis', 'amber-falcon').json()
        self.assertEqual(analyze.call_count, 1)
        self.assertEqual(first, second)
        self.assertTrue(UploadedLogAnalysis.objects.filter(upload=self.log, rule_set_key='shared').exists())

    def test_line_numbers_skip_blank_lines_and_presentation_fields_dropped(self):
        payload = fake_analysis([('first', 'B'), ('second', 'C'), ('third', '?')])
        with mock.patch('fixlist.upload_utils.analyze_log_text', return_value=payload):
            body = self.api_get('api_v1_upload_analysis', 'amber-falcon').json()
        self.assertEqual([line['n'] for line in body['untrusted_lines']], [1, 3, 4])
        self.assertNotIn('css_class', body['untrusted_lines'][0])
        self.assertNotIn('paint_base', body['untrusted_lines'][0])
        self.assertEqual(body['untrusted_lines'][0]['status'], 'B')

    def test_status_filter_and_pagination(self):
        payload = fake_analysis([('first', 'B'), ('second', 'C'), ('third', '?')])
        with mock.patch('fixlist.upload_utils.analyze_log_text', return_value=payload):
            body = self.api_get('api_v1_upload_analysis', 'amber-falcon', data={'status': 'B,?'}).json()
            self.assertEqual([line['text'] for line in body['untrusted_lines']], ['first', 'third'])
            self.assertEqual(body['matching_line_count'], 2)
            body = self.api_get(
                'api_v1_upload_analysis', 'amber-falcon', data={'status': 'B,?', 'offset': 1, 'limit': 1},
            ).json()
            self.assertEqual([line['text'] for line in body['untrusted_lines']], ['third'])

    def test_unknown_status_code_is_400(self):
        response = self.api_get('api_v1_upload_analysis', 'amber-falcon', data={'status': 'X'})
        self.assertEqual(response.status_code, 400)

    def test_real_analyzer_run(self):
        body = self.api_get('api_v1_upload_analysis', 'amber-falcon').json()
        self.assertEqual(len(body['untrusted_lines']), 3)
        self.assertEqual(body['rule_set'], 'shared')

    def test_uses_callers_private_rule_set_only(self):
        UserProfile.objects.create(user=self.user, rule_set_mode='private')
        other = make_user('bob')
        UploadedLogAnalysis.objects.create(
            upload=self.log,
            rule_set_key=f'private:{other.id}',
            payload=fake_analysis([('first', 'P')]),
            source_content_hash=self.log.content_hash,
        )
        payload = fake_analysis([('first', 'B'), ('second', 'C'), ('third', '?')])
        with mock.patch('fixlist.upload_utils.analyze_log_text', return_value=payload) as analyze:
            body = self.api_get('api_v1_upload_analysis', 'amber-falcon').json()
        analyze.assert_called_once_with(self.log.content, f'private:{self.user.id}')
        self.assertEqual(body['rule_set'], 'private')
        self.assertEqual(body['untrusted_lines'][0]['status'], 'B')

    def test_never_updates_upload_listing_stats(self):
        payload = fake_analysis([('first', 'B'), ('second', 'C'), ('third', '?')])
        with mock.patch('fixlist.upload_utils.analyze_log_text', return_value=payload):
            self.api_get('api_v1_upload_analysis', 'amber-falcon')
        self.assertEqual(UploadedLog.objects.get(pk=self.log.pk).count_malware, 0)


class ApiSearchEndpointTests(ApiTestBase):
    def test_substring_search_returns_first_hit(self):
        make_uploaded_log('amber-falcon', content='line one\nC:\\evil\\payload.exe here\n')
        make_uploaded_log('brave-otter', content='nothing to see')
        body = self.api_get('api_v1_search', data={'q': 'payload.exe'}).json()
        self.assertEqual([m['upload_id'] for m in body['matches']], ['amber-falcon'])
        self.assertEqual(body['matches'][0]['first_hit']['line_number'], 2)
        self.assertIn('payload.exe', body['matches'][0]['first_hit']['untrusted_text'])

    def test_simple_regex_search(self):
        make_uploaded_log('amber-falcon', content='task: updater123.exe')
        body = self.api_get('api_v1_search', data={'q': r'updater\d+\.exe', 'regex': '1'}).json()
        self.assertEqual([m['upload_id'] for m in body['matches']], ['amber-falcon'])

    def test_missing_or_oversized_query_is_400(self):
        self.assertEqual(self.api_get('api_v1_search').status_code, 400)
        self.assertEqual(self.api_get('api_v1_search', data={'q': 'x' * 501}).status_code, 400)


class ApiCaseVisibilityTests(ApiTestBase):
    def setUp(self):
        super().setUp()
        self.other = make_user('bob')
        self.log = make_uploaded_log('amber-falcon', forum_username='JohnDoe')
        self.own_case = InfectionCase.objects.create(owner=self.user, username='JohnDoe')
        self.other_case = InfectionCase.objects.create(owner=self.other, username='JohnDoe')
        InfectionCaseLog.objects.create(case=self.own_case, uploaded_log=self.log)
        InfectionCaseLog.objects.create(case=self.other_case, uploaded_log=self.log)

    def test_user_lists_only_own_cases(self):
        body = self.api_get('api_v1_user', 'johndoe').json()
        self.assertEqual([c['case_id'] for c in body['own_cases']], [self.own_case.case_id])
        self.assertEqual([u['upload_id'] for u in body['uploads']], ['amber-falcon'])

    def test_upload_metadata_hides_other_owners_case_ids(self):
        body = self.api_get('api_v1_upload', 'amber-falcon').json()
        self.assertEqual(body['own_case_ids'], [self.own_case.case_id])

    def test_case_by_id_readable_like_in_browser(self):
        fixlist = Fixlist.objects.create(owner=self.other, username='JohnDoe', content='Start::\nEnd::', internal_note='SECRET-NOTE')
        # Creating the fixlist may already auto-link it to bob's open case.
        InfectionCaseFixlist.objects.get_or_create(case=self.other_case, fixlist=fixlist)
        InfectionCaseNote.objects.create(case=self.other_case, content='checked startup', created_by=self.other)
        body = self.api_get('api_v1_case', self.other_case.case_id).json()
        self.assertFalse(body['is_own_case'])
        types = [entry['type'] for entry in body['timeline']]
        self.assertIn('log', types)
        self.assertIn('fixlist', types)
        self.assertIn('note', types)
        self.assertNotIn('SECRET-NOTE', str(body))
        # The other owner's case id is not leaked through the log metadata.
        log_entry = next(entry for entry in body['timeline'] if entry['type'] == 'log')
        self.assertEqual(log_entry['upload']['own_case_ids'], [self.own_case.case_id])

    def test_deleted_case_is_404(self):
        self.other_case.deleted_at = timezone.now()
        self.other_case.save()
        self.assertEqual(self.api_get('api_v1_case', self.other_case.case_id).status_code, 404)


class ApiSnippetEndpointTests(ApiTestBase):
    def setUp(self):
        super().setUp()
        self.other = make_user('bob')
        self.own = FixlistSnippet.objects.create(owner=self.user, name='mine', content='EmptyTemp:', category='cleanup')
        self.shared = FixlistSnippet.objects.create(
            owner=self.other, name='Remove Edge policy', content='HKLM\\SOFTWARE\\Policies', is_shared=True,
        )
        self.private = FixlistSnippet.objects.create(owner=self.other, name='bob private', content='secret')

    def test_lists_own_and_shared_only(self):
        body = self.api_get('api_v1_snippets').json()
        self.assertEqual({s['snippet_id'] for s in body['snippets']}, {self.own.pk, self.shared.pk})
        self.assertNotIn('bob private', str(body))

    def test_search_by_name_and_category(self):
        body = self.api_get('api_v1_snippets', data={'q': 'edge policy'}).json()
        self.assertEqual([s['snippet_id'] for s in body['snippets']], [self.shared.pk])
        self.assertEqual(body['snippets'][0]['content'], 'HKLM\\SOFTWARE\\Policies')
        body = self.api_get('api_v1_snippets', data={'category': 'cleanup'}).json()
        self.assertEqual([s['snippet_id'] for s in body['snippets']], [self.own.pk])

    def test_detail_respects_visibility(self):
        self.assertEqual(self.api_get('api_v1_snippet', self.shared.pk).status_code, 200)
        self.assertEqual(self.api_get('api_v1_snippet', self.private.pk).status_code, 404)

    def test_snippet_request_logged_with_target(self):
        self.api_get('api_v1_snippet', self.own.pk)
        self.assertEqual(ApiRequestLog.objects.get().target, str(self.own.pk))


class ApiTokensPageTests(TestCase):
    def setUp(self):
        self.user = make_user('alice')
        self.client.force_login(self.user)

    def test_create_shows_raw_token_once_without_cookie(self):
        response = self.client.post(reverse('api_tokens'), {'action': 'create', 'name': 'laptop', 'expiry_days': '90'})
        self.assertEqual(response.status_code, 200)
        raw = response.context['new_token_raw']
        self.assertTrue(raw.startswith('fh_'))
        self.assertContains(response, raw)
        self.assertEqual(response['Cache-Control'], 'no-store')
        for morsel in response.cookies.values():
            self.assertNotIn(raw, morsel.value)
        self.assertNotContains(self.client.get(reverse('api_tokens')), raw)
        token = ApiToken.objects.get(user=self.user)
        self.assertEqual(token.token_hash, ApiToken.hash_raw(raw))

    def test_cannot_revoke_another_users_token(self):
        other_token, _ = ApiToken.issue(make_user('bob'), 'theirs')
        self.client.post(reverse('api_tokens'), {'action': 'revoke', 'token_id': other_token.pk})
        self.assertIsNone(ApiToken.objects.get(pk=other_token.pk).revoked_at)

    def test_revoke_own_token(self):
        token, _ = ApiToken.issue(self.user, 'mine')
        self.client.post(reverse('api_tokens'), {'action': 'revoke', 'token_id': token.pk})
        token.refresh_from_db()
        self.assertIsNotNone(token.revoked_at)
        self.assertEqual(token.revoked_by, self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse('api_tokens'))
        self.assertEqual(response.status_code, 302)
