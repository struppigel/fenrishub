"""Trojan Killer MD5s: local MD5 -> SHA256 pairs (Malwarebytes, Fixlog File:),
manual MD5 checks and MD5 fresh lookups, and the marks they give a Trojan
Killer log. No test reaches the network: `_request` / `_http_get` are mocked."""

import json
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .. import centralbox
from ..file_hashes import extract_file_hashes
from ..models import (
    CentralboxFreshLookup, HashAlias, HashVerdict, RuleTag, TagCategory, UploadedLogFileHash,
)
from ..rule_sets import SHARED_RULE_SET_KEY
from ..tagging import found_tags_by_upload
from ..views.centralbox import page_hash_context
from .factories import make_uploaded_log, make_user
from .test_centralbox_fresh import give_key
from .test_file_hashes import FIXLOG_FILE_BLOCK, H1
from .test_log_highlighting import MALWAREBYTES, TROJAN_KILLER

TK_MD5 = '1fc1854f81e865ebd44de80a721101cd'          # AutoClicker.exe in TROJAN_KILLER
MB_MD5 = 'db731de38a5471a744fb09c633cd557f'          # the Malwarebytes detection's MD5
MB_SHA = '033bb9eef12e0e23adb36c9788edaa342704362512a8113d6aaeec3e01bf83ad'
SECTION_MD5 = '5fb2b0113160191c180840a0eb6e43e9'


def store(sha, verdict='malicious', family='asyncrat'):
    now = timezone.now()
    return HashVerdict.objects.create(sha256=sha, state='known', verdict=verdict, family=family,
                                      checked_at=now, next_check_at=now + timedelta(days=7))


class Md5ExtractionTests(TestCase):
    def test_trojan_killer_file_md5s_without_section_hashes(self):
        rows = extract_file_hashes('Trojan Killer', TROJAN_KILLER)
        md5s = {row.md5 for row in rows}
        self.assertIn(TK_MD5, md5s)
        self.assertNotIn(SECTION_MD5, md5s)
        row = next(row for row in rows if row.md5 == TK_MD5)
        self.assertEqual((row.sha256, row.auto, row.source), ('', False, 'trojan_killer'))
        self.assertEqual(row.detection, 'Trojan.Win32.Downloader.cl')
        self.assertEqual(row.path, 'C:\\Program Files\\AutoClicker\\AutoClicker.exe')
        self.assertIn('----- C:\\Program Files\\AutoClicker', TROJAN_KILLER.split('\n')[row.anchor_line_no - 1])

    def test_malwarebytes_and_fixlog_rows_pair_md5_and_sha256(self):
        mb = extract_file_hashes('Malwarebytes', MALWAREBYTES)[0]
        self.assertEqual((mb.md5, mb.sha256), (MB_MD5, MB_SHA))
        fixlog = {row.sha256: row for row in extract_file_hashes('Fixlog', FIXLOG_FILE_BLOCK)}
        self.assertEqual(fixlog[H1].md5, '86d48a8d73cd817a3bd55c699311294a')


class TrojanKillerMarksTests(TestCase):
    def setUp(self):
        cache.clear()
        centralbox._consecutive_failures = 0
        self.user = make_user()
        self.client.force_login(self.user)
        self.tk = make_uploaded_log('tk-log', log_type='Trojan Killer', content=TROJAN_KILLER, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.tk)

    def pair(self, md5=TK_MD5, sha=MB_SHA):
        """The same file seen in a Malwarebytes log with both hashes."""
        other = make_uploaded_log(f'mb-{md5[:6]}', log_type='Malwarebytes', content='x', forum_username='nobody')
        UploadedLogFileHash.objects.create(upload=other, sha256=sha, md5=md5, line_no=1, anchor_line_no=1,
                                           source='malwarebytes', auto=True)

    def test_md5_resolves_through_a_pair_seen_in_another_log(self):
        self.pair()
        store(MB_SHA)
        self.assertEqual(centralbox.resolve_md5s([TK_MD5.upper()]), {TK_MD5: MB_SHA})
        context = page_hash_context(self.tk, self.user)
        self.assertEqual(context['md5_map'], {TK_MD5: MB_SHA})
        self.assertEqual(context['verdicts'][MB_SHA]['family'], 'asyncrat')
        self.assertIn(TK_MD5, {row['md5'] for row in context['md5_rows']})

    def test_unknown_md5s_and_no_section_md5_rows(self):
        now = timezone.now()
        HashAlias.objects.create(md5=TK_MD5, sha256='', checked_at=now, next_check_at=now + timedelta(hours=1))
        context = page_hash_context(self.tk, self.user)
        self.assertIn(TK_MD5, context['md5_unknown'])
        self.assertNotIn(SECTION_MD5, {row['md5'] for row in context['md5_rows']})

    def test_tags_and_tag_search_work_through_md5s(self):
        self.pair()
        store(MB_SHA, family='autoclicker')
        category = TagCategory.objects.create(name='md5 test', priority=5)
        RuleTag.objects.create(name='AutoClicker', match_pattern='autoclicker', match_centralbox=True, category=category)
        found = found_tags_by_upload([self.tk.pk], SHARED_RULE_SET_KEY)[self.tk.pk]
        self.assertEqual([tag['name'] for tag in found], ['AutoClicker'])

    @override_settings(CENTRALBOX_API_KEY='cbt_server')
    def test_manual_md5_check_learns_the_sha256(self):
        answer = {'ok': True, 'analysed': True, 'hash': TK_MD5, 'htype': 'MD5', 'sha256': MB_SHA,
                  'verdict': 'clean', 'family': None, 'score': 10}
        with mock.patch.object(centralbox, '_http_get', return_value=answer) as http:
            response = self.client.post(reverse('centralbox_hash_check_api'),
                                        json.dumps({'sha256': TK_MD5, 'upload_id': 'tk-log'}),
                                        content_type='application/json')
        http.assert_called_once_with(f'/status/{TK_MD5}')
        body = response.json()
        self.assertEqual((body['sha256'], body['verdict']['verdict']), (MB_SHA, 'clean'))
        self.assertEqual(HashAlias.objects.get(md5=TK_MD5).sha256, MB_SHA)
        self.assertEqual(centralbox.resolve_md5s([TK_MD5]), {TK_MD5: MB_SHA})

    @override_settings(CENTRALBOX_API_KEY='cbt_server')
    def test_manual_md5_check_records_unknown(self):
        with mock.patch.object(centralbox, '_http_get', return_value={'ok': True, 'analysed': False, 'hash': TK_MD5}):
            body = self.client.post(reverse('centralbox_hash_check_api'),
                                    json.dumps({'sha256': TK_MD5, 'upload_id': 'tk-log'}),
                                    content_type='application/json').json()
        self.assertTrue(body['unknown'])
        self.assertEqual(HashAlias.objects.get(md5=TK_MD5).sha256, '')

    def test_section_md5s_and_foreign_md5s_are_refused(self):
        for md5 in (SECTION_MD5, 'a' * 32):
            response = self.client.post(reverse('centralbox_hash_check_api'),
                                        json.dumps({'sha256': md5, 'upload_id': 'tk-log'}),
                                        content_type='application/json')
            self.assertEqual(response.status_code, 404, md5)

    @override_settings(CENTRALBOX_API_KEY='cbt_server')
    def test_md5_fresh_lookup_with_the_helpers_key(self):
        give_key(self.user)
        calls = []

        def fake(method, path, key, body=None):
            calls.append((method, path, body))
            if method == 'POST':
                return {'ok': True, 'status': 'running', 'hash': TK_MD5}
            if path == f'/status/{TK_MD5}':
                return {'ok': True, 'analysed': True, 'lookup': 'done', 'hash': TK_MD5, 'sha256': MB_SHA,
                        'verdict': 'malicious', 'family': 'lumma', 'score': 100}
            if path == f'/lookup/{MB_SHA}/verdict':
                return {'ok': True, 'hash': MB_SHA, 'malware_type': 'stealer', 'threat_score': 95}
            raise AssertionError(path)

        with mock.patch.object(centralbox, '_request', side_effect=fake):
            start = self.client.post(reverse('centralbox_fresh_start_api'),
                                     json.dumps({'sha256': TK_MD5, 'upload_id': 'tk-log'}),
                                     content_type='application/json').json()
            self.assertEqual(start['state'], 'running')
            done = self.client.get(reverse('centralbox_fresh_status_api', args=[TK_MD5])).json()
        self.assertEqual(calls[0], ('POST', '/lookup', {'hash': TK_MD5, 'force': False, 'notify': False}))
        self.assertEqual(done['state'], 'done')
        self.assertEqual((done['verdict']['sha256'], done['verdict']['family']), (MB_SHA, 'lumma'))
        self.assertEqual(HashAlias.objects.get(md5=TK_MD5).sha256, MB_SHA)
        self.assertEqual(CentralboxFreshLookup.objects.get(sha256=TK_MD5).state, 'done')
        # The cooldown holds for the MD5 too.
        with mock.patch.object(centralbox, '_request') as request:
            again = self.client.post(reverse('centralbox_fresh_start_api'),
                                     json.dumps({'sha256': TK_MD5, 'upload_id': 'tk-log'}),
                                     content_type='application/json')
        self.assertEqual(again.status_code, 429)
        request.assert_not_called()
