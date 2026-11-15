"""Fresh centralbox lookups with a helper's own key (centralbox.start_fresh_lookup /
poll_fresh_lookup), the encrypted key in the profile and the cooldown per hash.
No test reaches the network: `_request` is mocked."""

import json
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .. import centralbox
from ..models import CentralboxFreshLookup, HashVerdict, SiteConfig, UploadedLogFileHash, UserProfile
from ..secret_box import decrypt, encrypt
from .factories import make_uploaded_log, make_user
from .test_log_highlighting import MALWAREBYTES

SHA = '033bb9eef12e0e23adb36c9788edaa342704362512a8113d6aaeec3e01bf83ad'
KEY = 'cbt_0123456789abcdef_SecretPartOfTheKey'


def give_key(user, key=KEY, status=UserProfile.CENTRALBOX_KEY_OK):
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.centralbox_key_encrypted = encrypt(key)
    profile.centralbox_key_hint = key[:8]
    profile.centralbox_key_status = status
    profile.save()
    return profile


def fake_request(answers, calls):
    """A `_request` stand-in: answers[(method, path)] is a dict or an exception."""
    def fake(method, path, key, body=None):
        calls.append((method, path, key, body))
        value = answers[(method, path)]
        if isinstance(value, Exception):
            raise value
        return value
    return fake


class SecretBoxTests(TestCase):
    def test_round_trip_and_wrong_secret(self):
        token = encrypt(KEY)
        self.assertNotIn(KEY, token)
        self.assertEqual(decrypt(token), KEY)
        with override_settings(SECRET_KEY='another-secret'):
            self.assertIsNone(decrypt(token))
        self.assertIsNone(decrypt(''))
        self.assertIsNone(decrypt('garbage'))


class ProfileKeyTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)

    def post(self, **fields):
        data = {'frst_fix_message': '', 'analyzer_fixlist_template': '', 'rule_set_mode': 'shared', **fields}
        return self.client.post(reverse('profile'), data)

    def test_a_good_key_is_stored_encrypted_and_never_shown(self):
        with mock.patch.object(centralbox, '_request', return_value={'ok': True, 'scopes': ['lookup']}) as request:
            self.post(centralbox_key=KEY)
        request.assert_called_once_with('GET', '/ping', KEY)
        profile = UserProfile.objects.get(user=self.user)
        self.assertNotIn(KEY, profile.centralbox_key_encrypted)
        self.assertEqual(profile.centralbox_key(), KEY)
        self.assertEqual(profile.centralbox_key_status, UserProfile.CENTRALBOX_KEY_OK)
        page = self.client.get(reverse('profile')).content.decode()
        self.assertNotIn(KEY, page)
        self.assertNotIn('SecretPartOfTheKey', page)
        self.assertIn('accepted by centralbox', page)

    def test_rejected_and_unreachable_keys(self):
        with mock.patch.object(centralbox, '_request', side_effect=centralbox._Failure('auth', 'HTTP 401')):
            self.post(centralbox_key=KEY)
        self.assertEqual(UserProfile.objects.get(user=self.user).centralbox_key_status, 'rejected')
        with mock.patch.object(centralbox, '_request', side_effect=centralbox._Failure('network', 'down')):
            self.post(centralbox_key=KEY)
        self.assertEqual(UserProfile.objects.get(user=self.user).centralbox_key_status, 'unverified')

    def test_empty_field_keeps_the_key_and_bad_format_is_refused(self):
        give_key(self.user)
        with mock.patch.object(centralbox, '_request') as request:
            self.post(centralbox_key='')
            self.post(centralbox_key='not-a-key')
        request.assert_not_called()
        self.assertEqual(UserProfile.objects.get(user=self.user).centralbox_key(), KEY)

    def test_remove(self):
        give_key(self.user)
        self.post(centralbox_key_remove='on')
        profile = UserProfile.objects.get(user=self.user)
        self.assertEqual((profile.centralbox_key_encrypted, profile.centralbox_key()), ('', None))


@override_settings(CENTRALBOX_API_KEY='cbt_server')
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

    def test_without_a_personal_key_nothing_is_sent(self):
        with mock.patch.object(centralbox, '_request') as request:
            response = self.start()
        request.assert_not_called()
        self.assertEqual(response.status_code, 403)
        self.assertIn('profile', response.json()['message'])
        self.assertFalse(CentralboxFreshLookup.objects.exists())

    def test_the_hash_must_be_in_the_log(self):
        give_key(self.user)
        self.assertEqual(self.start(sha='e' * 64).status_code, 404)

    def test_start_uses_the_helpers_key_and_force_only_for_known_hashes(self):
        give_key(self.user)
        calls = []
        answers = {('POST', '/lookup'): {'ok': True, 'status': 'running', 'hash': SHA}}
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, calls)):
            body = self.start().json()
        self.assertEqual(body['state'], 'running')
        self.assertEqual(calls, [('POST', '/lookup', KEY, {'hash': SHA, 'force': False, 'notify': False})])
        row = CentralboxFreshLookup.objects.get(sha256=SHA)
        self.assertEqual(row.requested_by, self.user)

        # A known hash is re-analysed (force) once the cooldown is over.
        now = timezone.now()
        HashVerdict.objects.create(sha256=SHA, state='known', verdict='clean', checked_at=now, next_check_at=now)
        CentralboxFreshLookup.objects.update(requested_at=now - timedelta(hours=25))
        calls.clear()
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, calls)):
            self.start()
        self.assertTrue(calls[0][3]['force'])

    def test_cooldown_applies_to_everyone(self):
        give_key(self.user)
        give_key(self.other, key='cbt_bobsownkey_123456')
        answers = {('POST', '/lookup'): {'ok': True, 'status': 'running'}}
        calls = []
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, calls)):
            self.assertEqual(self.start().status_code, 200)
            self.client.force_login(self.other)
            second = self.start()
        self.assertEqual(second.status_code, 429)
        self.assertIn('alice', second.json()['message'])
        self.assertEqual(len(calls), 1)

    def test_a_failed_start_releases_the_hash_and_pauses_nobody_for_a_key_problem(self):
        profile = give_key(self.user)
        for failure, status in ((centralbox._Failure('network', 'down'), 503),
                                (centralbox._Failure('rate', 'HTTP 429', retry_after='90'), 429),
                                (centralbox._Failure('auth', 'HTTP 401'), 403)):
            with mock.patch.object(centralbox, '_request', side_effect=failure):
                response = self.start()
            self.assertEqual(response.status_code, status, failure.kind)
            self.assertFalse(CentralboxFreshLookup.objects.exists(), failure.kind)
            cache.clear()  # the key's wait after the 429 is over
        profile.refresh_from_db()
        self.assertEqual(profile.centralbox_key_status, UserProfile.CENTRALBOX_KEY_REJECTED)
        self.assertIsNone(SiteConfig.get_solo().centralbox_paused_until)
        # A rejected key cannot start lookups any more.
        with mock.patch.object(centralbox, '_request') as request:
            self.assertEqual(self.start().status_code, 403)
        request.assert_not_called()

    def test_polling_stores_the_result_when_centralbox_is_done(self):
        give_key(self.user)
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
        self.assertTrue(all(call[2] == KEY for call in calls))
        # Finished: answered from the database.
        with mock.patch.object(centralbox, '_request') as request:
            self.assertEqual(self.client.get(status_url).json()['state'], 'done')
        request.assert_not_called()

    def test_polling_not_found_stores_unknown(self):
        give_key(self.user)
        CentralboxFreshLookup.objects.create(sha256=SHA, requested_by=self.user, requested_at=timezone.now())
        answers = {('GET', f'/status/{SHA}'): {'ok': True, 'analysed': False, 'lookup': 'not_found'}}
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, [])):
            body = self.client.get(reverse('centralbox_fresh_status_api', args=[SHA])).json()
        self.assertEqual(body['state'], 'not_found')
        self.assertEqual(HashVerdict.objects.get(sha256=SHA).state, 'unknown')

    def test_polling_is_throttled_per_hash(self):
        give_key(self.user)
        CentralboxFreshLookup.objects.create(sha256=SHA, requested_by=self.user, requested_at=timezone.now())
        calls = []
        running = {('GET', f'/status/{SHA}'): {'ok': True, 'analysed': False, 'lookup': 'running'}}
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(running, calls)):
            for _ in range(3):
                centralbox.poll_fresh_lookup(SHA)
        self.assertEqual(len(calls), 1)

    def test_page_offers_fresh_lookups_only_with_a_key(self):
        page = self.client.get(reverse('view_uploaded_log', args=['mb-log'])).content.decode()
        self.assertIn('"can_fresh_lookup": false', page)
        give_key(self.user)
        page = self.client.get(reverse('view_uploaded_log', args=['mb-log'])).content.decode()
        self.assertIn('"can_fresh_lookup": true', page)
        self.assertNotIn(KEY, page)


@override_settings(CENTRALBOX_API_KEY='cbt_server')
class HelperKeyRateLimitTests(TestCase):
    """A helper's own key has no Fenris-side per-minute limit; only
    centralbox's own 429 holds it back, for the Retry-After it names."""

    def setUp(self):
        cache.clear()
        centralbox._consecutive_failures = 0
        self.user = make_user()
        self.client.force_login(self.user)
        give_key(self.user)
        self.url = reverse('centralbox_fresh_start_api')

    def start(self, sha):
        return self.client.post(self.url, json.dumps({'sha256': sha, 'upload_id': 'many-log'}),
                                content_type='application/json')

    def make_log(self, count):
        shas = [f'{n:064x}' for n in range(1, count + 1)]
        upload = make_uploaded_log('many-log', log_type='Malwarebytes', forum_username='nobody', content='\n'.join(
            f'Trojan.Test, C:\\X\\f{n}.exe, Quarantined, 8322, 1457763, 1.0.116571, , ame, , {"a" * 32}, {sha}'
            for n, sha in enumerate(shas)
        ))
        UploadedLogFileHash.rebuild_for(upload)
        return shas

    def test_no_local_limit_per_minute(self):
        shas = self.make_log(16)
        calls = []
        answers = {('POST', '/lookup'): {'ok': True, 'status': 'running'}}
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, calls)):
            statuses = [self.start(sha).status_code for sha in shas]
        self.assertEqual(statuses, [200] * 16)
        self.assertEqual(len(calls), 16)

    def test_a_429_holds_only_that_key_back_for_retry_after(self):
        first, second = self.make_log(2)
        with mock.patch.object(centralbox, '_request',
                               side_effect=centralbox._Failure('rate', 'HTTP 429', retry_after='30')):
            response = self.start(first)
        self.assertEqual(response.status_code, 429)
        self.assertIn('30 s', response.json()['message'])
        self.assertIsNone(SiteConfig.get_solo().centralbox_paused_until)
        # Refused without asking centralbox, naming the wait.
        with mock.patch.object(centralbox, '_request') as request:
            response = self.start(second)
        request.assert_not_called()
        self.assertEqual(response.status_code, 429)
        self.assertRegex(response.json()['message'], r'try again in (29|30) s')
        self.assertFalse(CentralboxFreshLookup.objects.exists())
        # The server key is not affected.
        self.assertEqual(centralbox.key_paused_seconds(''), 0)
        # Once the wait is over, requests go out again.
        cache.clear()
        answers = {('POST', '/lookup'): {'ok': True, 'status': 'running'}}
        calls = []
        with mock.patch.object(centralbox, '_request', side_effect=fake_request(answers, calls)):
            self.assertEqual(self.start(second).status_code, 200)
        self.assertEqual(len(calls), 1)

    def test_manual_check_with_a_waiting_key_says_how_long(self):
        (sha,) = self.make_log(1)
        centralbox.pause_key(centralbox.key_id_of(KEY), 45)
        with mock.patch.object(centralbox, '_request') as request:
            body = self.client.post(reverse('centralbox_hash_check_api'),
                                    json.dumps({'sha256': sha, 'upload_id': 'many-log'}),
                                    content_type='application/json').json()
        request.assert_not_called()
        self.assertIsNone(body['verdict'])
        self.assertRegex(body['note'], r'try again in (44|45) s')

    def test_a_poll_with_a_waiting_key_just_reports_running(self):
        (sha,) = self.make_log(1)
        CentralboxFreshLookup.objects.create(sha256=sha, requested_by=self.user, requested_at=timezone.now())
        centralbox.pause_key(centralbox.key_id_of(KEY), 45)
        with mock.patch.object(centralbox, '_request') as request:
            self.assertEqual(centralbox.poll_fresh_lookup(sha)['state'], 'running')
        request.assert_not_called()


class ManualCheckKeyTests(TestCase):
    """"check this hash" asks with the helper's own key when they have one."""

    def setUp(self):
        cache.clear()
        centralbox._consecutive_failures = 0
        self.user = make_user()
        self.client.force_login(self.user)
        self.upload = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MALWAREBYTES, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.upload)

    def check(self):
        return self.client.post(reverse('centralbox_hash_check_api'),
                                json.dumps({'sha256': SHA, 'upload_id': 'mb-log'}),
                                content_type='application/json')

    def test_uses_the_helpers_key_even_without_a_server_key(self):
        give_key(self.user)
        answer = {'ok': True, 'analysed': True, 'sha256': SHA, 'verdict': 'clean', 'family': None}
        with mock.patch.object(centralbox, '_request', return_value=answer) as request, \
                mock.patch.object(centralbox, '_http_get') as server:
            body = self.check().json()
        server.assert_not_called()
        request.assert_called_once_with('GET', f'/status/{SHA}', KEY)
        self.assertTrue(body['available'])
        self.assertEqual(body['verdict']['verdict'], 'clean')

    @override_settings(CENTRALBOX_API_KEY='cbt_server')
    def test_without_a_helper_key_the_server_key_is_used(self):
        answer = {'ok': True, 'analysed': False, 'hash': SHA}
        with mock.patch.object(centralbox, '_http_get', return_value=answer) as server:
            self.check()
        server.assert_called_once_with(f'/status/{SHA}')

    def test_a_rejected_helper_key_is_marked_and_pauses_nobody(self):
        profile = give_key(self.user)
        with mock.patch.object(centralbox, '_request', side_effect=centralbox._Failure('auth', 'HTTP 401')):
            self.check()
        profile.refresh_from_db()
        self.assertEqual(profile.centralbox_key_status, UserProfile.CENTRALBOX_KEY_REJECTED)
        self.assertIsNone(SiteConfig.get_solo().centralbox_paused_until)
