"""centralbox client (fixlist/centralbox.py): FenrisHub must keep working,
and store nothing wrong, whatever centralbox does. No test reaches the network:
`_http_get` is mocked, or `urlopen` is mocked behind the explicit opt-in."""

import io
import json
import urllib.error
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from .. import centralbox
from ..models import CentralboxUsageMinute, HashVerdict, SiteConfig

H1 = 'a1' * 32
H2 = 'b2' * 32
H3 = 'c3' * 32


def status_answer(sha, verdict='malicious', family='asyncrat', score=100, analysed=True, **extra):
    data = {'ok': True, 'analysed': analysed, 'hash': sha, 'htype': 'SHA256', 'in_progress': False}
    if analysed:
        data.update({'sha256': sha, 'verdict': verdict, 'family': family, 'score': score})
    data.update(extra)
    return data


def verdict_answer(sha, **extra):
    data = {
        'ok': True, 'hash': sha, 'family': 'asyncrat', 'malware_type': 'stealer',
        'score': 100, 'threat_score': 97,
        'counts': {'malicious': 5, 'suspicious': 1, 'not_found': 3, 'bogus': 9},
        'providers': [
            {'source': 'Triage', 'status': 'malicious', 'link': 'https://tria.ge/260910-je9qdazelg'},
            {'source': 'ANY.RUN', 'status': 'malicious', 'link': 'http://insecure.example/x'},
            {'source': 'Evil', 'status': 'malicious', 'link': 'javascript:alert(1)'},
            {'source': 'Jotti', 'status': 'not_found', 'link': 'https://jotti.example/'},
            {'source': '<b>x</b>', 'status': 'malicious', 'link': 'https://x.example/'},
        ],
    }
    data.update(extra)
    return data


@override_settings(CENTRALBOX_API_KEY='cbt_test')
class CentralboxClientTests(TestCase):
    def setUp(self):
        cache.clear()
        centralbox._consecutive_failures = 0
        SiteConfig.get_solo()

    def answers(self, mapping):
        """Mock _http_get with {path: answer or exception}."""
        def fake(path):
            value = mapping[path]
            if isinstance(value, Exception):
                raise value
            return value
        return mock.patch.object(centralbox, '_http_get', side_effect=fake)

    def test_malicious_hash_is_stored_with_validated_details(self):
        with self.answers({f'/status/{H1}': status_answer(H1), f'/lookup/{H1}/verdict': verdict_answer(H1)}) as http:
            result = centralbox.check_hashes([H1.upper()])
        self.assertEqual(http.call_count, 2)
        self.assertTrue(result['available'])
        self.assertEqual(result['pending'], 0)
        stored = HashVerdict.objects.get(sha256=H1)
        self.assertEqual((stored.state, stored.verdict, stored.family), ('known', 'malicious', 'asyncrat'))
        self.assertEqual(stored.malware_type, 'stealer')
        self.assertEqual(stored.threat_score, 97)
        self.assertEqual(stored.provider_counts, {'malicious': 5, 'suspicious': 1, 'not_found': 3})
        self.assertEqual(stored.links, [{'source': 'Triage', 'status': 'malicious', 'url': 'https://tria.ge/260910-je9qdazelg'}])
        self.assertEqual(result['verdicts'][H1]['report_url'], f'https://centralbox.dev/analysis/{H1}')

    def test_unknown_hash_is_stored_as_unknown_without_a_second_call(self):
        with self.answers({f'/status/{H1}': status_answer(H1, analysed=False)}) as http:
            result = centralbox.check_hashes([H1])
        self.assertEqual(http.call_count, 1)
        self.assertEqual(result['verdicts'][H1]['state'], 'unknown')
        self.assertEqual(HashVerdict.objects.get(sha256=H1).verdict, '')

    def test_clean_hash_needs_no_verdict_call(self):
        with self.answers({f'/status/{H1}': status_answer(H1, verdict='clean', family=None)}) as http:
            centralbox.check_hashes([H1])
        self.assertEqual(http.call_count, 1)
        self.assertEqual(HashVerdict.objects.get(sha256=H1).verdict, 'clean')

    def test_fresh_verdicts_are_not_looked_up_again(self):
        now = timezone.now()
        HashVerdict.objects.create(sha256=H1, state='known', verdict='clean', checked_at=now,
                                   next_check_at=now + timedelta(days=1))
        with self.answers({}) as http:
            result = centralbox.check_hashes([H1])
        http.assert_not_called()
        self.assertEqual(result['verdicts'][H1]['verdict'], 'clean')

    def test_nothing_is_sent_without_a_key_or_with_the_switch_off(self):
        with self.answers({}) as http:
            with override_settings(CENTRALBOX_API_KEY=''):
                result = centralbox.check_hashes([H1])
                self.assertFalse(result['available'])
            SiteConfig.objects.filter(pk=1).update(centralbox_enabled=False)
            result = centralbox.check_hashes([H1])
        http.assert_not_called()
        self.assertFalse(result['available'])
        self.assertEqual(result['pending'], 0)

    def test_stale_verdicts_are_still_returned_when_centralbox_fails(self):
        past = timezone.now() - timedelta(days=30)
        HashVerdict.objects.create(sha256=H1, state='known', verdict='malicious', family='lumma',
                                   checked_at=past, next_check_at=past)
        with self.answers({f'/status/{H1}': centralbox._Failure('network', 'down')}):
            result = centralbox.check_hashes([H1])
        self.assertEqual(result['verdicts'][H1]['family'], 'lumma')
        self.assertEqual(result['verdicts'][H1]['checked_at'], past.date().isoformat())

    def test_garbage_answers_are_never_stored(self):
        bad_answers = [
            status_answer(H1, verdict='totally-evil'),
            status_answer(H1, verdict=None),
            dict(status_answer(H1), sha256=H2),          # answer for another hash
            dict(status_answer(H1), ok=False),
            {'ok': True},                                # no analysed flag
        ]
        for answer in bad_answers:
            centralbox._consecutive_failures = 0
            SiteConfig.objects.filter(pk=1).update(centralbox_paused_until=None)
            with self.answers({f'/status/{H1}': answer}):
                centralbox.check_hashes([H1])
            self.assertFalse(HashVerdict.objects.filter(sha256=H1).exists(), answer)

    def test_unsafe_labels_are_dropped(self):
        answer = status_answer(H1, family='<script>alert(1)</script>', score='100')
        with self.answers({f'/status/{H1}': answer, f'/lookup/{H1}/verdict': verdict_answer(H1, malware_type=7, threat_score=500)}):
            centralbox.check_hashes([H1])
        stored = HashVerdict.objects.get(sha256=H1)
        self.assertEqual((stored.family, stored.score, stored.malware_type, stored.threat_score), ('', None, '', None))

    def test_a_failing_details_call_keeps_the_verdict(self):
        with self.answers({f'/status/{H1}': status_answer(H1),
                           f'/lookup/{H1}/verdict': centralbox._Failure('server', 'HTTP 500')}):
            result = centralbox.check_hashes([H1])
        self.assertEqual(result['verdicts'][H1]['verdict'], 'malicious')
        self.assertEqual(HashVerdict.objects.get(sha256=H1).links, [])

    def test_three_failures_in_a_row_pause_all_lookups(self):
        failing = {f'/status/{h}': centralbox._Failure('network', 'timed out') for h in (H1, H2, H3)}
        with self.assertLogs('fixlist.centralbox', level='WARNING'):
            for sha in (H1, H2, H3):
                with self.answers(failing):
                    centralbox.check_hashes([sha])
        config = SiteConfig.get_solo()
        self.assertIsNotNone(config.centralbox_paused_until)
        self.assertGreater(config.centralbox_paused_until, timezone.now() + timedelta(minutes=9))
        self.assertFalse(centralbox.is_available())
        with self.answers({}) as http:
            result = centralbox.check_hashes([H1])
        http.assert_not_called()
        self.assertFalse(result['available'])

    def test_a_run_stops_at_the_first_failure(self):
        with self.answers({f'/status/{H1}': centralbox._Failure('network', 'down')}) as http:
            centralbox.check_hashes([H1, H2, H3])
        self.assertEqual(http.call_count, 1)

    def test_a_rejected_key_pauses_for_hours(self):
        with self.answers({f'/status/{H1}': centralbox._Failure('auth', 'HTTP 403')}):
            with self.assertLogs('fixlist.centralbox', level='ERROR'):
                centralbox.check_hashes([H1])
        paused = SiteConfig.get_solo().centralbox_paused_until
        self.assertGreater(paused, timezone.now() + timedelta(hours=5))

    def test_rate_limit_pauses_for_retry_after(self):
        with self.answers({f'/status/{H1}': centralbox._Failure('rate', 'HTTP 429', retry_after='120')}):
            with self.assertLogs('fixlist.centralbox', level='WARNING'):
                centralbox.check_hashes([H1])
        paused = SiteConfig.get_solo().centralbox_paused_until
        self.assertLess(abs((paused - timezone.now()).total_seconds() - 120), 10)

    @override_settings(CENTRALBOX_CALLS_PER_MINUTE=1)
    @mock.patch.object(centralbox, 'current_minute', lambda: 29_000_000)  # no minute boundary midway
    def test_the_shared_minute_budget_is_respected(self):
        answers = {f'/status/{h}': status_answer(h, analysed=False) for h in (H1, H2)}
        with self.answers(answers) as http:
            result = centralbox.check_hashes([H1, H2])
        self.assertEqual(http.call_count, 1)
        self.assertEqual(result['pending'], 1)
        self.assertEqual(CentralboxUsageMinute.objects.get().calls, 1)

    def test_max_calls_limits_a_run(self):
        answers = {f'/status/{h}': status_answer(h, analysed=False) for h in (H1, H2, H3)}
        with self.answers(answers) as http:
            centralbox.check_hashes([H1, H2, H3], max_calls=2)
        self.assertEqual(http.call_count, 2)

    def test_invalid_hashes_are_ignored(self):
        with self.answers({}) as http:
            result = centralbox.check_hashes(['nothex', 'a' * 63, None, ''])
        http.assert_not_called()
        self.assertEqual(result['verdicts'], {})

    def test_unexpected_errors_never_escape(self):
        with mock.patch.object(centralbox, '_lookup_one', side_effect=RuntimeError('boom')):
            with self.assertLogs('fixlist.centralbox', level='ERROR'):
                result = centralbox.check_hashes([H1])
        self.assertEqual(result['verdicts'], {})

    def test_background_checks_never_start_under_tests(self):
        self.assertFalse(centralbox.schedule_uploads_check([1, 2]))


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@override_settings(CENTRALBOX_API_KEY='cbt_test')
class CentralboxHttpTests(TestCase):
    """The real _http_get, with urlopen mocked."""

    def test_under_tests_no_request_is_made_without_the_opt_in(self):
        with mock.patch('fixlist.centralbox.urllib.request.urlopen') as urlopen:
            with self.assertRaises(centralbox._Failure):
                centralbox._http_get(f'/status/{H1}')
        urlopen.assert_not_called()

    @override_settings(CENTRALBOX_ALLOW_HTTP_IN_TESTS=True)
    def test_request_shape_and_timeout(self):
        body = json.dumps(status_answer(H1)).encode()
        with mock.patch('fixlist.centralbox.urllib.request.urlopen', return_value=FakeResponse(body)) as urlopen:
            data = centralbox._http_get(f'/status/{H1}')
        self.assertEqual(data['verdict'], 'malicious')
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, f'https://centralbox.dev/api/v1/status/{H1}')
        self.assertEqual(request.get_header('Authorization'), 'Bearer cbt_test')
        self.assertLessEqual(urlopen.call_args.kwargs['timeout'], 10)

    @override_settings(CENTRALBOX_ALLOW_HTTP_IN_TESTS=True)
    def test_failures_are_classified(self):
        def http_error(code, headers=None):
            return urllib.error.HTTPError('u', code, 'x', headers or {}, None)

        cases = [
            (http_error(500), 'server'),
            (http_error(401), 'auth'),
            (http_error(429, {'Retry-After': '30'}), 'rate'),
            (urllib.error.URLError('dns'), 'network'),
            (TimeoutError(), 'network'),
        ]
        for exc, kind in cases:
            with mock.patch('fixlist.centralbox.urllib.request.urlopen', side_effect=exc):
                with self.assertRaises(centralbox._Failure) as caught:
                    centralbox._http_get('/status/x')
            self.assertEqual(caught.exception.kind, kind)
        with mock.patch('fixlist.centralbox.urllib.request.urlopen', side_effect=http_error(404)):
            self.assertIsNone(centralbox._http_get('/lookup/x'))

    @override_settings(CENTRALBOX_ALLOW_HTTP_IN_TESTS=True)
    def test_bad_bodies_are_rejected(self):
        bodies = [b'<html>maintenance</html>', b'[1, 2]', b'\xff\xfe',
                  b'{"a": "' + b'x' * (centralbox.MAX_RESPONSE_BYTES + 10) + b'"}']
        for body in bodies:
            with mock.patch('fixlist.centralbox.urllib.request.urlopen', return_value=FakeResponse(body)):
                with self.assertRaises(centralbox._Failure) as caught:
                    centralbox._http_get('/status/x')
            self.assertEqual(caught.exception.kind, 'bad')


class PlaceholderNameTests(TestCase):
    """centralbox's "Unknown" family / malware type is no name: labels then say "malicious"."""

    def test_placeholders_are_stored_as_no_name(self):
        sha = 'ab' * 32
        status = centralbox._parse_status({'ok': True, 'analysed': True, 'sha256': sha,
                                           'verdict': 'malicious', 'family': 'Unknown', 'score': 90}, sha)
        self.assertEqual(status['family'], '')
        details = centralbox._parse_verdict_details({'ok': True, 'hash': sha, 'malware_type': 'unknown'}, sha)
        self.assertEqual(details['malware_type'], '')
        for name in ('None', 'null'):
            self.assertEqual(centralbox._label(name), '', name)
        # Not a valid name at all ('/' is not allowed), placeholder or not.
        self.assertEqual(centralbox._label('N/A'), '')
        self.assertEqual(centralbox._label('AsyncRAT'), 'AsyncRAT')
        self.assertEqual(centralbox._label('unknown-loader'), 'unknown-loader')
