"""centralbox on the log page and in the analyzer (fixlist/views/centralbox.py).

The pages must look and work the same with centralbox down or off; the
suggestions endpoint must never call centralbox."""

import json
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .. import centralbox
from ..models import HashVerdict, InfectionCase, InfectionCaseLog, SiteConfig, UploadedLogFileHash
from .factories import make_uploaded_log, make_user
from .test_log_highlighting import MALWAREBYTES

MB_SHA = '033bb9eef12e0e23adb36c9788edaa342704362512a8113d6aaeec3e01bf83ad'
EVIL_SHA = 'e5' * 32

MB_EVIL = '\n'.join([
    'Malwarebytes',
    'www.malwarebytes.com',
    '',
    '-Log Details-',
    '',
    '-Scan Summary-',
    'File: 1',
    ('Trojan.AsyncRAT, C:\\USERS\\BOB\\APPDATA\\ROAMING\\EVIL\\evil.exe, Quarantined, 8322, 1457763, '
     f'1.0.116571, , ame, , DB731DE38A5471A744FB09C633CD557F, {EVIL_SHA.upper()}'),
    '',
    '(end)',
])

FRST_RUN_LINE = ('HKU\\S-1-5-21-1-2-3-1001\\...\\Run: [evil] => C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe '
                 '[12345 2026-01-01] () [File not signed]')
FRST_OTHER_LINE = 'HKLM\\...\\Run: [ok] => C:\\Program Files\\Ok\\ok.exe [100 2026-01-01] (Ok Inc.) [File not signed]'
FRST_LOG = '\n'.join([
    'Scan result of Farbar Recovery Scan Tool (FRST) (x64) Version: 01-11-2026',
    '==================== Registry (Whitelisted) ===================',
    FRST_RUN_LINE,
    FRST_OTHER_LINE,
])


def store_verdict(sha, verdict='malicious', family='asyncrat', state='known', days_old=0):
    checked = timezone.now() - timedelta(days=days_old)
    return HashVerdict.objects.create(
        sha256=sha, state=state, verdict=verdict if state == 'known' else '', family=family,
        threat_score=97, checked_at=checked, next_check_at=checked + timedelta(days=7),
    )


def page_data(response):
    html = response.content.decode()
    start = html.index('id="centralboxData"')
    start = html.index('>', start) + 1
    end = html.index('</script>', start)
    return json.loads(html[start:end])


class LogPageTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = make_user()
        self.client.force_login(self.user)
        self.upload = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MALWAREBYTES,
                                        forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.upload)

    def test_page_renders_without_centralbox_and_without_network(self):
        with mock.patch.object(centralbox, '_http_get') as http:
            response = self.client.get(reverse('view_uploaded_log', args=['mb-log']))
        http.assert_not_called()
        self.assertEqual(response.status_code, 200)
        data = page_data(response)
        self.assertFalse(data['available'])
        self.assertEqual([row['sha256'] for row in data['auto']], [MB_SHA])
        self.assertTrue(data['auto'][0]['flag'])
        self.assertEqual(data['verdicts'], {})
        # The hash token itself is untouched; markers are drawn client-side.
        self.assertContains(response, f'<span class="hl-hash">{MB_SHA.upper()}</span>', html=False)

    def test_stored_verdicts_are_shown_even_when_centralbox_is_off(self):
        store_verdict(MB_SHA, family='lumma', days_old=40)
        SiteConfig.objects.filter(pk=1).update(centralbox_enabled=False)
        response = self.client.get(reverse('view_uploaded_log', args=['mb-log']))
        verdict = page_data(response)['verdicts'][MB_SHA]
        self.assertEqual((verdict['verdict'], verdict['family']), ('malicious', 'lumma'))
        self.assertEqual(verdict['checked_at'], (timezone.now() - timedelta(days=40)).date().isoformat())

    def test_logs_without_hashes_get_no_data(self):
        make_uploaded_log('eset-log', log_type='ESET', content='05-11-2026 11:16:09\n', forum_username='nobody')
        response = self.client.get(reverse('view_uploaded_log', args=['eset-log']))
        self.assertNotContains(response, 'id="centralboxData"')

    def test_check_endpoint_answers_unavailable_without_a_key(self):
        with mock.patch.object(centralbox, '_http_get') as http:
            response = self.client.post(reverse('centralbox_upload_check_api', args=['mb-log']))
        http.assert_not_called()
        self.assertEqual(response.json(), {'available': False, 'verdicts': {}, 'pending': 0})

    @override_settings(CENTRALBOX_API_KEY='cbt_test')
    def test_check_endpoint_looks_up_missing_hashes(self):
        answer = {'ok': True, 'analysed': False, 'hash': MB_SHA}
        with mock.patch.object(centralbox, '_http_get', return_value=answer) as http:
            response = self.client.post(reverse('centralbox_upload_check_api', args=['mb-log']))
        http.assert_called_once_with(f'/status/{MB_SHA}')
        body = response.json()
        self.assertTrue(body['available'])
        self.assertEqual(body['verdicts'][MB_SHA]['state'], 'unknown')

    @override_settings(CENTRALBOX_API_KEY='cbt_test')
    def test_check_endpoint_survives_a_dead_centralbox(self):
        with mock.patch.object(centralbox, '_http_get', side_effect=centralbox._Failure('network', 'down')):
            response = self.client.post(reverse('centralbox_upload_check_api', args=['mb-log']))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['verdicts'], {})

    @override_settings(CENTRALBOX_API_KEY='cbt_test')
    def test_manual_check_only_for_hashes_in_the_log(self):
        url = reverse('centralbox_hash_check_api')
        bad = self.client.post(url, json.dumps({'sha256': 'xyz', 'upload_id': 'mb-log'}), content_type='application/json')
        self.assertEqual(bad.status_code, 400)
        other = self.client.post(url, json.dumps({'sha256': EVIL_SHA, 'upload_id': 'mb-log'}), content_type='application/json')
        self.assertEqual(other.status_code, 404)
        answer = {'ok': True, 'analysed': True, 'sha256': MB_SHA, 'verdict': 'clean', 'family': None}
        with mock.patch.object(centralbox, '_http_get', return_value=answer):
            ok = self.client.post(url, json.dumps({'sha256': MB_SHA.upper(), 'upload_id': 'mb-log'}),
                                  content_type='application/json')
        self.assertEqual(ok.json()['verdict']['verdict'], 'clean')

    @override_settings(CENTRALBOX_API_KEY='cbt_test')
    def test_manual_check_again_asks_centralbox_despite_a_fresh_answer(self):
        # Stored as "not in centralbox" a minute ago; someone has since submitted it.
        store_verdict(MB_SHA, state='unknown')
        url = reverse('centralbox_hash_check_api')
        payload = json.dumps({'sha256': MB_SHA, 'upload_id': 'mb-log'})
        answer = {'ok': True, 'analysed': True, 'sha256': MB_SHA, 'verdict': 'clean', 'family': None}
        with mock.patch.object(centralbox, '_http_get', return_value=answer) as http:
            first = self.client.post(url, payload, content_type='application/json')
            second = self.client.post(url, payload, content_type='application/json')
        self.assertEqual(first.json()['verdict']['verdict'], 'clean')
        self.assertEqual(second.json()['verdict']['verdict'], 'clean')
        # The second click inside the cooldown is answered from the database.
        http.assert_called_once_with(f'/status/{MB_SHA}')

    def test_page_check_does_not_re_ask_for_fresh_answers(self):
        store_verdict(MB_SHA, state='unknown')
        with override_settings(CENTRALBOX_API_KEY='cbt_test'):
            with mock.patch.object(centralbox, '_http_get') as http:
                self.client.post(reverse('centralbox_upload_check_api', args=['mb-log']))
        http.assert_not_called()

    def test_endpoints_need_a_login(self):
        self.client.logout()
        response = self.client.post(reverse('centralbox_upload_check_api', args=['mb-log']))
        self.assertEqual(response.status_code, 302)


class CaseSuggestionTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = make_user()
        self.client.force_login(self.user)
        self.case = InfectionCase.objects.create(owner=self.user, username='bob')
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST_LOG, forum_username='nobody')
        self.mb = make_uploaded_log('mb-evil', log_type='Malwarebytes', content=MB_EVIL, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.mb)
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=self.frst, added_by=self.user)
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=self.mb, added_by=self.user)
        self.url = reverse('centralbox_suggestions_api')

    def get(self, upload_id='frst-log'):
        with mock.patch.object(centralbox, '_http_get') as http:
            response = self.client.get(self.url, {'upload_id': upload_id})
        http.assert_not_called()
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_frst_line_matches_a_malicious_scanner_hash_in_the_same_case(self):
        store_verdict(EVIL_SHA)
        body = self.get()
        self.assertEqual(len(body['suggestions']), 1)
        suggestion = body['suggestions'][0]
        # Uppercase Malwarebytes path, mixed-case FRST path, different user name.
        self.assertEqual(suggestion['line'], FRST_RUN_LINE)
        self.assertEqual(suggestion['sha256'], EVIL_SHA)
        self.assertEqual(suggestion['family'], 'asyncrat')
        self.assertEqual(suggestion['source']['upload_id'], 'mb-evil')
        self.assertEqual(suggestion['source']['detection'], 'Trojan.AsyncRAT')

    def test_no_suggestion_without_a_malicious_verdict(self):
        self.assertEqual(self.get()['suggestions'], [])
        self.assertEqual(self.get()['pending'], 1)
        store_verdict(EVIL_SHA, verdict='clean')
        self.assertEqual(self.get()['suggestions'], [])

    def test_logs_outside_the_case_are_not_used(self):
        store_verdict(EVIL_SHA)
        InfectionCaseLog.objects.filter(uploaded_log=self.mb).delete()
        self.assertEqual(self.get()['suggestions'], [])

    def test_deleted_cases_and_logs_are_not_used(self):
        store_verdict(EVIL_SHA)
        self.mb.deleted_at = timezone.now()
        self.mb.save(update_fields=['deleted_at'])
        self.assertEqual(self.get()['suggestions'], [])

    def test_non_frst_or_unknown_uploads_get_nothing(self):
        store_verdict(EVIL_SHA)
        self.assertEqual(self.get('mb-evil')['suggestions'], [])
        self.assertEqual(self.get('no-such-log')['suggestions'], [])
        self.assertEqual(self.client.get(self.url).json()['suggestions'], [])


class MauSummaryTests(TestCase):
    """MAU summary box: files whose hash has a real centralbox verdict, at the path line."""

    def test_verdicts_are_listed_and_unknown_hashes_are_not(self):
        from .test_file_hashes import H1, H2, H3, MAU_FILES
        from .test_log_highlighting import MAU_REPORT

        from ..models import LogTypeDetectionRule

        # The page re-checks the type: with the report header and a rule it stays MAU.
        LogTypeDetectionRule.objects.create(
            name='MAU', log_type='MAU', pattern=r'MAU Log|Malicious App Uninstaller',
            scope=LogTypeDetectionRule.SCOPE_START,
        )
        content = MAU_REPORT + '\n' + MAU_FILES
        user = make_user()
        self.client.force_login(user)
        mau = make_uploaded_log('mau-log', log_type='MAU', content=content, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(mau)
        now = timezone.now()
        HashVerdict.objects.create(sha256=H1, state='known', verdict='malicious', family='asyncrat',
                                   checked_at=now, next_check_at=now + timedelta(days=7))
        HashVerdict.objects.create(sha256=H2, state='known', verdict='clean',
                                   checked_at=now, next_check_at=now + timedelta(days=7))
        HashVerdict.objects.create(sha256=H3, state='unknown', checked_at=now, next_check_at=now + timedelta(days=1))
        with mock.patch.object(centralbox, '_http_get') as http:
            response = self.client.get(reverse('view_uploaded_log', args=['mau-log']))
        http.assert_not_called()
        lines = content.split('\n')
        items = [(item.line_no, item.severity, item.name, item.target)
                 for item in response.context['highlight'].summary if item.name == 'SHA-256']
        self.assertEqual(items, [
            (lines.index(f'  SHA256: {H1}'), 'b', 'SHA-256',
             'c:\\users\\bob\\appdata\\local\\via\\via chrome runtime\\.gitattributes'),
            (lines.index(f'  SHA256: {H2}'), 'c', 'SHA-256', 'c:\\users\\bob\\appdata\\local\\via\\x.cfg'),
        ])
        self.assertTrue(response.context['highlight'].summary_title.endswith('and centralbox results'))
        self.assertTrue(all(row['flag'] for row in response.context['centralbox']['auto']))
