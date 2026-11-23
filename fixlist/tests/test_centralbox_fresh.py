"""Fresh centralbox lookups (centralbox.start_fresh_lookup / poll_fresh_lookup):
any helper, always with the server key, once per hash per cooldown and at most
CENTRALBOX_FRESH_LOOKUPS_PER_MINUTE across Fenris. No test reaches the
network: `_request` is mocked."""

import json
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .. import centralbox
from ..models import CentralboxFreshLookup, HashVerdict, SiteConfig, UploadedLogFileHash
from .factories import make_uploaded_log, make_user
from .test_log_highlighting import MALWAREBYTES

SHA = '033bb9eef12e0e23adb36c9788edaa342704362512a8113d6aaeec3e01bf83ad'
SERVER_KEY = 'cbt_server'


def fake_request(answers, calls):
    """A `_request` stand-in: answers[(method, path)] is a dict or an exception."""
    def fake(method, path, key, body=None):
        calls.append((method, path, key, body))
        value = answers[(method, path)]
        if isinstance(value, Exception):
            raise value
        return value
    return fake


@override_settings(CENTRALBOX_API_KEY=SERVER_KEY)
class FreshLookupTests(TestCase):
    def setUp(self):
        cache.clear()
        centralbox._consecutive_failures = 0
        self.user = make_user()
        self.other = make_user('bob')
        self.client.force_login(self.user)
        self.upload = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MALWAREBYTES, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.upload)
        self.url = reverse('centralbox_fresh_start_api')

    def start(self, sha=SHA, upload_id='mb-log'):
        return self.client.post(self.url, json.dumps({'sha256': sha, 'upload_id': upload_id}),
                                content_type='application/json')

    def test_any_helper_starts_with_the_server_key_and_force_only_for_known_hashes(self):
        calls = []
        answers = {('POST', '/lookup'): {'ok': True, 'status': 'running', 'hash': SHA}}
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, calls)):
            body = self.start().json()
        self.assertEqual(body['state'], 'running')
        self.assertEqual(calls, [('POST', '/lookup', SERVER_KEY, {'hash': SHA, 'force': False, 'notify': False})])
        row = CentralboxFreshLookup.objects.get(sha256=SHA)
        self.assertEqual(row.requested_by, self.user)

        # A known hash is re-analysed (force) once the cooldown is over.
        now = timezone.now()
        HashVerdict.objects.create(sha256=SHA, state='known', verdict='clean', checked_at=now, next_check_at=now)
        CentralboxFreshLookup.objects.update(requested_at=now - timedelta(hours=25))
        calls.clear()
        self.client.force_login(self.other)
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, calls)):
            self.assertEqual(self.start().status_code, 200)
        self.assertTrue(calls[0][3]['force'])
        self.assertEqual(CentralboxFreshLookup.objects.get(sha256=SHA).requested_by, self.other)

    def test_nothing_is_sent_without_a_server_key_or_while_switched_off(self):
        with override_settings(CENTRALBOX_API_KEY=''), mock.patch.object(centralbox, '_request') as request:
            self.assertEqual(self.start().status_code, 503)
        request.assert_not_called()
        SiteConfig.get_solo()
        SiteConfig.objects.filter(pk=1).update(centralbox_enabled=False)
        with mock.patch.object(centralbox, '_request') as request:
            self.assertEqual(self.start().status_code, 503)
        request.assert_not_called()
        self.assertFalse(CentralboxFreshLookup.objects.exists())

    def test_the_hash_must_be_in_the_log(self):
        self.assertEqual(self.start(sha='e' * 64).status_code, 404)

    def test_cooldown_applies_to_everyone(self):
        answers = {('POST', '/lookup'): {'ok': True, 'status': 'running'}}
        calls = []
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, calls)):
            self.assertEqual(self.start().status_code, 200)
            self.client.force_login(self.other)
            second = self.start()
        self.assertEqual(second.status_code, 429)
        self.assertIn('alice', second.json()['message'])
        self.assertEqual(len(calls), 1)

    @override_settings(CENTRALBOX_FRESH_LOOKUPS_PER_MINUTE=2)
    @mock.patch.object(centralbox, 'current_minute', lambda: 29_000_000)  # no minute boundary midway
    def test_fresh_lookups_per_minute_are_capped(self):
        shas = [f'{n:064x}' for n in range(1, 4)]
        upload = make_uploaded_log('many-log', log_type='Malwarebytes', forum_username='nobody', content='\n'.join(
            f'Trojan.Test, C:\\X\\f{n}.exe, Quarantined, 8322, 1457763, 1.0.116571, , ame, , {"a" * 32}, {sha}'
            for n, sha in enumerate(shas)
        ))
        UploadedLogFileHash.rebuild_for(upload)
        calls = []
        answers = {('POST', '/lookup'): {'ok': True, 'status': 'running'}}
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, calls)):
            statuses = [self.start(sha, 'many-log').status_code for sha in shas]
        self.assertEqual(statuses, [200, 200, 429])
        self.assertEqual(len(calls), 2)
        # The refused hash keeps no cooldown slot.
        self.assertFalse(CentralboxFreshLookup.objects.filter(sha256=shas[2]).exists())
        # Reads have their own budget.
        self.assertTrue(centralbox.take_budget())

    def test_a_failed_start_releases_the_hash(self):
        for failure, status in ((centralbox._Failure('network', 'down'), 503),
                                (centralbox._Failure('rate', 'HTTP 429', retry_after='90'), 429)):
            with mock.patch.object(centralbox, '_request', side_effect=failure):
                response = self.start()
            self.assertEqual(response.status_code, status, failure.kind)
            self.assertFalse(CentralboxFreshLookup.objects.exists(), failure.kind)
            SiteConfig.objects.filter(pk=1).update(centralbox_paused_until=None)
        self.assertIn('90 s', response.json()['message'])

    def test_a_rejected_server_key_pauses_all_lookups(self):
        with mock.patch.object(centralbox, '_request', side_effect=centralbox._Failure('auth', 'HTTP 401')):
            self.assertEqual(self.start().status_code, 503)
        self.assertIsNotNone(SiteConfig.get_solo().centralbox_paused_until)
        self.assertFalse(centralbox.is_available())
        with mock.patch.object(centralbox, '_request') as request:
            self.assertEqual(self.start().status_code, 503)
        request.assert_not_called()

    def test_polling_stores_the_result_when_centralbox_is_done(self):
        CentralboxFreshLookup.objects.create(sha256=SHA, requested_by=self.user, requested_at=timezone.now())
        status_url = reverse('centralbox_fresh_status_api', args=[SHA])
        running = {('GET', f'/status/{SHA}'): {'ok': True, 'analysed': False, 'lookup': 'running', 'in_progress': True}}
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(running, [])):
            self.assertEqual(self.client.get(status_url).json()['state'], 'running')
        cache.clear()
        done = {
            ('GET', f'/status/{SHA}'): {'ok': True, 'analysed': True, 'lookup': 'done', 'sha256': SHA,
                                       'verdict': 'malicious', 'family': 'asyncrat', 'score': 100},
            ('GET', f'/lookup/{SHA}/verdict'): {'ok': True, 'hash': SHA, 'malware_type': 'stealer', 'threat_score': 99},
        }
        calls = []
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(done, calls)):
            body = self.client.get(status_url).json()
        self.assertEqual(body['state'], 'done')
        self.assertEqual((body['verdict']['family'], body['verdict']['malware_type']), ('asyncrat', 'stealer'))
        self.assertTrue(all(call[2] == SERVER_KEY for call in calls))
        # Finished: answered from the database.
        with mock.patch.object(centralbox, '_request') as request:
            self.assertEqual(self.client.get(status_url).json()['state'], 'done')
        request.assert_not_called()

    def test_polling_not_found_stores_unknown(self):
        CentralboxFreshLookup.objects.create(sha256=SHA, requested_by=self.user, requested_at=timezone.now())
        answers = {('GET', f'/status/{SHA}'): {'ok': True, 'analysed': False, 'lookup': 'not_found'}}
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, [])):
            body = self.client.get(reverse('centralbox_fresh_status_api', args=[SHA])).json()
        self.assertEqual(body['state'], 'not_found')
        self.assertEqual(HashVerdict.objects.get(sha256=SHA).state, 'unknown')

    def test_polling_is_throttled_per_hash(self):
        CentralboxFreshLookup.objects.create(sha256=SHA, requested_by=self.user, requested_at=timezone.now())
        calls = []
        running = {('GET', f'/status/{SHA}'): {'ok': True, 'analysed': False, 'lookup': 'running'}}
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(running, calls)):
            for _ in range(3):
                centralbox.poll_fresh_lookup(SHA)
        self.assertEqual(len(calls), 1)

    def test_page_offers_fresh_lookups_with_the_server_key(self):
        page = self.client.get(reverse('view_uploaded_log', args=['mb-log'])).content.decode()
        self.assertIn('"can_fresh_lookup": true', page)
        self.assertNotIn(SERVER_KEY, page)
        with override_settings(CENTRALBOX_API_KEY=''):
            page = self.client.get(reverse('view_uploaded_log', args=['mb-log'])).content.decode()
        self.assertIn('"can_fresh_lookup": false', page)

    def test_profile_has_no_centralbox_key_field(self):
        page = self.client.get(reverse('profile')).content.decode()
        self.assertNotIn('centralbox_key', page)


@override_settings(CENTRALBOX_API_KEY=SERVER_KEY)
class ManualCheckTests(TestCase):
    """"check this hash" always asks with the server key."""

    def setUp(self):
        cache.clear()
        centralbox._consecutive_failures = 0
        self.user = make_user()
        self.client.force_login(self.user)
        self.upload = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MALWAREBYTES, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.upload)

    def test_uses_the_server_key(self):
        answer = {'ok': True, 'analysed': True, 'sha256': SHA, 'verdict': 'clean', 'family': None}
        with mock.patch.object(centralbox, '_request', return_value=answer) as request:
            body = self.client.post(reverse('centralbox_hash_check_api'),
                                    json.dumps({'sha256': SHA, 'upload_id': 'mb-log'}),
                                    content_type='application/json').json()
        request.assert_called_once_with('GET', f'/status/{SHA}', SERVER_KEY)
        self.assertTrue(body['available'])
        self.assertEqual(body['verdict']['verdict'], 'clean')
        self.assertNotIn('note', body)

    def test_analyzer_gets_the_lookup_urls_for_correlated_hashes(self):
        page = self.client.get(reverse('log_analyzer')).content.decode()
        self.assertIn(f'centralboxHashCheckUrl: "{reverse("centralbox_hash_check_api")}"', page)
        self.assertIn(f'centralboxFreshStartUrl: "{reverse("centralbox_fresh_start_api")}"', page)
        self.assertIn(reverse('centralbox_fresh_status_api', args=['0' * 64]), page)
