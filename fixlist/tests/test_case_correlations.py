"""Case correlations for FRST / Addition lines (fixlist/case_correlations.py),
the Fixlog result parser, and File: / centralbox entries in the Fixlog summary.
Nothing here may call centralbox."""

from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .. import centralbox
from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..case_correlations import correlations_for_upload
from ..models import (
    HashVerdict, InfectionCase, InfectionCaseLog, UploadedLog, UploadedLogAnalysis, UploadedLogFileHash,
    count_fixlog_results, iter_fixlog_results,
)
from .factories import make_uploaded_log, make_user
from .test_file_hashes import FIXLOG_FILE_BLOCK, H1

EVIL_SHA = 'e5' * 32
EVIL_MD5 = 'd4' * 16
RUN_LINE = ('HKU\\S-1-5-21-1-2-3-1001\\...\\Run: [evil] => C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe '
            '[12345 2026-01-01] () [File not signed]')
OTHER_LINE = 'HKLM\\...\\Run: [ok] => C:\\Program Files\\Ok\\ok.exe [100 2026-01-01] (Ok Inc.) [File not signed]'
FRST = '\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)', RUN_LINE, OTHER_LINE])

# The same malware on the same machine as FRST (profile Bob).
MB_SAME = ('Trojan.AsyncRAT, C:\\USERS\\BOB\\APPDATA\\ROAMING\\EVIL\\evil.exe, Quarantined, 8322, 1457763, '
           f'1.0.116571, , ame, , {EVIL_MD5.upper()}, {EVIL_SHA.upper()}')
MB_EVIL = ('Trojan.AsyncRAT, C:\\USERS\\ALICE\\APPDATA\\ROAMING\\EVIL\\evil.exe, Quarantined, 8322, 1457763, '
           f'1.0.116571, , ame, , {EVIL_MD5.upper()}, {EVIL_SHA.upper()}')
ESET = ('05-11-2026 11:16:09\n'
        'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe\ta variant of Win64/Kryptik.GHM trojan\tcleaned by deleting')
FIXLOG = '\n'.join([
    'Fix result of Farbar Recovery Scan Tool (x64) Version: 01-11-2026',
    'fixlist content:',
    '*****************',
    'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe',
    '*****************',
    'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe => moved successfully',
    '"HKLM\\Software\\Evil" => removed successfully',
    'C:\\Gone\\x.exe => not found',
])


def cache_analysis(upload, lines):
    payload = {'format': ANALYSIS_PAYLOAD_FORMAT, 'lines': [
        {'line': text, 'dominant_status': '?', 'components': {}} for text in lines
    ], 'summary': {}, 'warnings': []}
    UploadedLogAnalysis.objects.create(upload=upload, rule_set_key='shared', payload=payload,
                                       source_content_hash=upload.content_hash)


class FixlogResultTests(TestCase):
    def test_echoed_fixlist_is_skipped_and_line_numbers_match_the_page(self):
        results = list(iter_fixlog_results(FIXLOG))
        self.assertEqual([line_no for line_no, *_ in results], [6, 7, 8])
        self.assertEqual(results[0][1:], ('C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe', 'moved successfully'))
        self.assertEqual(count_fixlog_results(FIXLOG), {'total': 3, 'success': 2, 'not_found': 1, 'error': 0})


class CaseCorrelationTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.case = InfectionCase.objects.create(owner=self.user, username='bob')
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST, forum_username='nobody')
        cache_analysis(self.frst, [RUN_LINE, OTHER_LINE])
        self.link(self.frst)

    def link(self, upload):
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=upload, added_by=self.user)

    def add_log(self, upload_id, log_type, content):
        upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(upload)
        self.link(upload)
        return upload

    def get(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            response = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-log'})
        http.assert_not_called()
        request.assert_not_called()
        return response.json()['correlations']

    def test_all_sources_are_listed_under_the_line_of_the_same_file(self):
        now = timezone.now()
        HashVerdict.objects.create(sha256=EVIL_SHA, state='known', verdict='malicious', family='asyncrat',
                                   checked_at=now, next_check_at=now + timedelta(days=7))
        self.add_log('mb-log', 'Malwarebytes', MB_EVIL)
        self.add_log('eset-log', 'ESET', ESET)
        self.add_log('fix-log', 'Fixlog', FIXLOG)
        found = self.get()
        self.assertEqual(list(found), [RUN_LINE])
        kinds = {(item['kind'], item['upload_id']) for item in found[RUN_LINE]}
        self.assertEqual(kinds, {('hash', 'mb-log'), ('detection', 'eset-log'), ('fixlog', 'fix-log')})
        mb = next(item for item in found[RUN_LINE] if item['kind'] == 'hash')
        self.assertEqual((mb['sha256'], mb['md5'], mb['detection']), (EVIL_SHA, EVIL_MD5, 'Trojan.AsyncRAT'))
        self.assertEqual(mb['centralbox']['family'], 'asyncrat')
        fix = next(item for item in found[RUN_LINE] if item['kind'] == 'fixlog')
        self.assertEqual((fix['result'], fix['line_no']), ('moved successfully', 6))

    def test_trojan_killer_md5_resolves_through_a_pair(self):
        other = self.add_log('pair-log', 'Malwarebytes', MB_EVIL)
        InfectionCaseLog.objects.filter(uploaded_log=other).delete()  # the pair is outside the case
        tk = self.add_log('tk-log', 'Trojan Killer', '\n'.join([
            'Gridinsoft Trojan Killer Portable v.2.3.57',
            '----- C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe ---- General Threat',
            '\tTrojan.Win32.Agent.x',
            f'\tMD5: {EVIL_MD5.upper()}:1234',
        ]))
        self.assertTrue(UploadedLogFileHash.objects.filter(upload=tk, md5=EVIL_MD5).exists())
        item = self.get()[RUN_LINE][0]
        self.assertEqual((item['upload_id'], item['md5'], item['sha256']), ('tk-log', EVIL_MD5, EVIL_SHA))
        self.assertIsNone(item['centralbox'])

    def test_a_bare_hash_for_the_path_counts_even_if_never_checked(self):
        listing = self.add_log('folder-log', 'Fixlog', '\n'.join([
            '========================= Folder: C:\\Users\\Bob\\AppData\\Roaming\\evil ========================',
            f'  [{EVIL_SHA}] 03/08/2026 - 03/08/2026 - 1 MB - Signer: - C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe',
        ]))
        self.assertTrue(UploadedLogFileHash.objects.filter(upload=listing, source='fixlog_folder').exists())
        (item,) = self.get()[RUN_LINE]
        self.assertEqual((item['kind'], item['sha256'], item['centralbox'], item['detection']),
                         ('hash', EVIL_SHA, None, ''))
        body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-log'}).json()
        self.assertEqual(body['statuses'][RUN_LINE], '')  # a hash alone has no status: grey marker
        now = timezone.now()
        HashVerdict.objects.create(sha256=EVIL_SHA, state='unknown', checked_at=now, next_check_at=now)
        self.assertEqual(self.get()[RUN_LINE][0]['centralbox']['state'], 'unknown')

    def test_hitmanpro_results_in_a_fixlog_correlate_by_their_path(self):
        self.add_log('fix-hmp', 'Fixlog', '\n'.join([
            'Fix result of Farbar Recovery Scan Tool (x64) Version: 01-11-2026',
            'Malware _____________________________________________________________________',
            '',
            '   C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe',
            '      Size . . . . . . . : 4 110 654 bytes',
            f'      SHA-256  . . . . . : {EVIL_SHA.upper()}',
            '    > SurfRight  . . . . : Mal/Generic-S',
        ]))
        (item,) = self.get()[RUN_LINE]
        self.assertEqual((item['kind'], item['sha256'], item['detection'], item['anchor_line_no']),
                         ('hash', EVIL_SHA, 'Mal/Generic-S', 4))

    def test_a_folder_block_md5_counts_too(self):
        self.add_log('folder-md5', 'Fixlog', '\n'.join([
            '========================= Folder: C:\\Users\\Bob\\AppData\\Roaming\\evil ========================',
            f'2026-11-11 17:32 - 2026-11-11 17:32 - 000000312 ____A [{EVIL_MD5.upper()}] () '
            'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe',
            '====== End of Folder: ======',
        ]))
        (item,) = self.get()[RUN_LINE]
        self.assertEqual((item['md5'], item['sha256'], item['centralbox']), (EVIL_MD5, '', None))

    def test_nothing_without_case_cache_or_frst_type(self):
        self.add_log('fix-log', 'Fixlog', FIXLOG)
        UploadedLogAnalysis.objects.filter(upload=self.frst).delete()
        self.assertEqual(self.get(), {})  # nothing computed (or cached) without an analysis
        cache_analysis(self.frst, [RUN_LINE])
        self.assertIn(RUN_LINE, self.get())
        self.case.deleted_at = timezone.now()
        self.case.save(update_fields=['deleted_at'])
        # A deleted case no longer counts: the forum user's logs are used instead.
        body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-log'}).json()
        self.assertEqual(body['scope'], 'user')
        UploadedLog.objects.exclude(pk=self.frst.pk).update(forum_username='someone else')
        self.assertEqual(self.get(), {})
        fixlog = make_uploaded_log('other-fix', log_type='Fixlog', content=FIXLOG, forum_username='nobody')
        self.assertEqual(correlations_for_upload(fixlog, self.user)['lines'], {})

    def test_a_detected_folder_covers_the_files_inside_it(self):
        # An upload with the clean log first and the scan log after it.
        self.add_log('adw-log', 'AdwCleaner', '\n'.join([
            '# Mode: Clean',
            '***** [ Folders ] *****',
            'Deleted       C:\\Users\\Bob\\AppData\\Roaming\\evil',
            '# Mode: Scan',
            '***** [ Folders ] *****',
            'PUP.Optional.Legacy             C:\\Users\\Bob\\AppData\\Roaming\\evil',
        ]))
        # A fixlist result for the folder says nothing about the files in it.
        self.add_log('fix-folder', 'Fixlog', '\n'.join([
            'Fix result of Farbar Recovery Scan Tool (x64) Version: 01-11-2026',
            'C:\\Users\\Bob\\AppData\\Roaming\\evil => moved successfully',
        ]))
        found = self.get()
        self.assertEqual(list(found), [RUN_LINE])
        (item,) = found[RUN_LINE]
        self.assertEqual((item['kind'], item['upload_id'], item['detection'], item['in_folder']),
                         ('detection', 'adw-log', 'PUP.Optional.Legacy', True))
        body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-log'}).json()
        self.assertEqual(body['statuses'][RUN_LINE], 'P')
        self.assertEqual(body['notes'][RUN_LINE], 'PUP.Optional.Legacy · in detected folder · AdwCleaner')

    def test_needs_a_login(self):
        self.client.logout()
        response = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-log'})
        self.assertEqual(response.status_code, 302)


class FixlogSummaryTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.fixlog = make_uploaded_log('fix-files', log_type='Fixlog', content=FIXLOG_FILE_BLOCK, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.fixlog)

    def summary(self):
        response = self.client.get(reverse('view_uploaded_log', args=['fix-files']))
        return response.context['highlight'].summary

    def test_file_entries_and_checked_hashes_are_in_the_summary(self):
        lines = FIXLOG_FILE_BLOCK.split('\n')
        items = {item.line_no: item for item in self.summary() if item.name in ('File:', 'SHA-256')}
        files = [item for item in items.values() if item.name == 'File:']
        self.assertEqual({lines[item.line_no - 1].strip() for item in files},
                         {'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe', 'C:\\Temp\\b.dll [symlink -> C:\\Other\\b.dll]'})
        self.assertFalse(any(item.name == 'SHA-256' for item in items.values()))
        # A folder-listing hash someone checked joins the summary, coloured by its verdict.
        folder_sha = next(row.sha256 for row in UploadedLogFileHash.objects.filter(upload=self.fixlog, source='fixlog_folder'))
        now = timezone.now()
        HashVerdict.objects.create(sha256=folder_sha, state='known', verdict='malicious', family='x',
                                   checked_at=now, next_check_at=now + timedelta(days=1))
        checked = [item for item in self.summary() if item.name == 'SHA-256']
        self.assertEqual(len(checked), 1)
        self.assertEqual(checked[0].severity, 'b')
        self.assertIn(H1, [row.sha256 for row in UploadedLogFileHash.objects.filter(upload=self.fixlog)])


class CorrelationScopeTests(TestCase):
    """Own cases first; without one, the other logs of the same forum user."""

    def setUp(self):
        self.user = make_user()
        self.other_helper = make_user('bob')
        self.client.force_login(self.user)
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST, forum_username='Victim')
        cache_analysis(self.frst, [RUN_LINE, OTHER_LINE])
        self.fixlog = make_uploaded_log('fix-log', log_type='Fixlog', content=FIXLOG, forum_username='victim')

    def get(self):
        return self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-log'}).json()

    def test_without_own_case_the_forum_users_logs_count(self):
        body = self.get()
        self.assertEqual((body['scope'], body['name']), ('user', 'Victim'))
        self.assertIn(RUN_LINE, body['correlations'])

    def test_another_helpers_case_does_not_count(self):
        case = InfectionCase.objects.create(owner=self.other_helper, username='Victim', auto_assign_new_items=False)
        InfectionCaseLog.objects.create(case=case, uploaded_log=self.frst)
        other = make_uploaded_log('other-fix', log_type='Fixlog', content=FIXLOG, forum_username='someone else')
        InfectionCaseLog.objects.create(case=case, uploaded_log=other)
        body = self.get()
        self.assertEqual(body['scope'], 'user')
        self.assertEqual({item['upload_id'] for item in body['correlations'][RUN_LINE]}, {'fix-log'})

    def test_own_case_wins_over_the_forum_user(self):
        case = InfectionCase.objects.create(owner=self.user, username='Victim', auto_assign_new_items=False)
        InfectionCaseLog.objects.create(case=case, uploaded_log=self.frst)
        body = self.get()
        self.assertEqual(body['scope'], 'case')
        self.assertEqual(body['correlations'], {})  # the case holds no other log

    def test_no_forum_user_no_correlations(self):
        UploadedLog.objects.filter(pk=self.frst.pk).update(forum_username='')
        self.assertEqual(self.get()['correlations'], {})

    def test_suggestion_chip_uses_the_same_logs(self):
        now = timezone.now()
        mb = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MB_EVIL, forum_username='victim')
        UploadedLogFileHash.rebuild_for(mb)
        HashVerdict.objects.create(sha256=EVIL_SHA, state='known', verdict='malicious', family='asyncrat',
                                   checked_at=now, next_check_at=now + timedelta(days=7))
        body = self.client.get(reverse('centralbox_suggestions_api'), {'upload_id': 'frst-log'}).json()
        self.assertEqual([item['line'] for item in body['suggestions']], [RUN_LINE])


class SameSystemTests(TestCase):
    def test_signals_and_verdicts(self):
        from ..case_correlations import same_system, system_signals

        frst = 'Ran by Bob (administrator) on DESKTOP-ONE (ASUS) (01-11-2026 10:00:00)\nC:\\Users\\Bob\\x.exe'
        hmp_same = '   Computer name . . . . : DESKTOP-ONE\n'
        hmp_other = '   Computer name . . . . : LAPTOP-TWO\n'
        mb_profiles = 'Trojan.X, C:\\USERS\\BOB\\APPDATA\\x.exe, Quarantined'
        mb_other = 'Trojan.X, C:\\Users\\Alice\\AppData\\x.exe, Quarantined'
        nothing = 'no paths here'
        self.assertEqual(system_signals(frst), ({'desktop-one'}, {'bob'}))
        self.assertEqual(system_signals('C:\\Users\\Public\\x C:\\Users\\username\\y'), (set(), set()))
        self.assertEqual(same_system(system_signals(frst), system_signals(hmp_same)), 'same')
        self.assertEqual(same_system(system_signals(frst), system_signals(hmp_other)), 'different')
        self.assertEqual(same_system(system_signals(frst), system_signals(mb_profiles)), 'same')
        self.assertEqual(same_system(system_signals(frst), system_signals(mb_other)), 'different')
        self.assertEqual(same_system(system_signals(frst), system_signals(nothing)), 'unknown')

    def test_entries_carry_system_and_severity(self):
        user = make_user()
        self.client.force_login(user)
        frst_content = 'Ran by Bob (administrator) on DESKTOP-ONE (ASUS) (x)\n' + FRST
        frst = make_uploaded_log('frst-sys', log_type='FRST', content=frst_content, forum_username='victim')
        cache_analysis(frst, [RUN_LINE])
        make_uploaded_log('eset-sys', log_type='ESET', content=ESET, forum_username='victim')
        body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-sys'}).json()
        item = body['correlations'][RUN_LINE][0]
        self.assertEqual((item['kind'], item['system'], item['severity']), ('detection', 'same', 'b'))


class CorrelationStatusTests(TestCase):
    def test_line_verdict_precedence(self):
        from ..case_correlations import correlation_status, entry_status

        b = {'kind': 'detection', 'severity': 'b', 'system': 'same'}
        p = {'kind': 'detection', 'severity': 'p', 'system': 'same'}
        g = {'kind': 'detection', 'severity': 'g', 'system': 'unknown'}
        clean = {'kind': 'hash', 'severity': 'g', 'centralbox': {'verdict': 'clean'}, 'system': 'same'}
        malicious = {'kind': 'hash', 'severity': '', 'centralbox': {'verdict': 'malicious'}, 'system': 'same'}
        fixlog = {'kind': 'fixlog', 'result': 'moved successfully', 'system': 'same'}
        other_system = {'kind': 'detection', 'severity': 'b', 'system': 'different'}
        self.assertEqual(entry_status(clean), 'C')  # C outranks G
        self.assertEqual(correlation_status([p, g]), 'P')
        self.assertEqual(correlation_status([g, b]), 'B')
        self.assertEqual(correlation_status([clean]), 'C')
        self.assertEqual(correlation_status([g]), 'G')
        self.assertEqual(correlation_status([malicious, p]), 'B')
        self.assertEqual(correlation_status([fixlog]), '')
        self.assertEqual(correlation_status([other_system, g]), 'G')


class CorrelationCacheTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.case = InfectionCase.objects.create(owner=self.user, username='bob', auto_assign_new_items=False)
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST, forum_username='nobody')
        cache_analysis(self.frst, [RUN_LINE, OTHER_LINE])
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=self.frst)
        self.mb = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MB_SAME, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.mb)
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=self.mb)

    def run_counted(self):
        from ..correlations import forward as case_correlations

        with mock.patch.object(case_correlations, '_compute', wraps=case_correlations._compute) as compute:
            result = correlations_for_upload(self.frst, self.user)
        return result, compute.call_count

    def test_second_call_is_served_from_the_cache(self):
        first, computed = self.run_counted()
        self.assertEqual(computed, 1)
        self.assertIn(RUN_LINE, first['lines'])
        second, computed = self.run_counted()
        self.assertEqual(computed, 0)
        self.assertEqual(second['lines'].keys(), first['lines'].keys())

    def test_changes_recompute(self):
        self.run_counted()
        now = timezone.now()
        HashVerdict.objects.create(sha256=EVIL_SHA, state='known', verdict='malicious', family='asyncrat',
                                   checked_at=now, next_check_at=now + timedelta(days=7))
        result, computed = self.run_counted()
        self.assertEqual(computed, 1)
        self.assertEqual(result['statuses'][RUN_LINE], 'B')
        fix = make_uploaded_log('fix-log', log_type='Fixlog', content=FIXLOG, forum_username='nobody')
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=fix)
        self.assertEqual(self.run_counted()[1], 1)
        UploadedLog.objects.filter(pk=fix.pk).update(content_hash='changed')
        self.assertEqual(self.run_counted()[1], 1)
        self.assertEqual(self.run_counted()[1], 0)

    def test_each_viewer_scope_has_its_own_entry(self):
        from ..models import CorrelationCache

        self.run_counted()
        other = make_user('carol')
        correlations_for_upload(self.frst, other)  # no case of carol's: the forum user's logs
        self.assertEqual(set(CorrelationCache.objects.values_list('scope_key', flat=True)),
                         {f'case:{self.user.pk}', 'user'})

    def test_nothing_is_stored_without_an_analysis(self):
        from ..models import CorrelationCache

        UploadedLogAnalysis.objects.filter(upload=self.frst).delete()
        self.assertEqual(correlations_for_upload(self.frst, self.user)['lines'], {})
        self.assertFalse(CorrelationCache.objects.exists())


class LogViewCorrelationTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.case = InfectionCase.objects.create(owner=self.user, username='bob', auto_assign_new_items=False)
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST, forum_username='nobody')
        cache_analysis(self.frst, [RUN_LINE, OTHER_LINE])
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=self.frst)
        mb = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MB_SAME, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(mb)
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=mb)
        now = timezone.now()
        HashVerdict.objects.create(sha256=EVIL_SHA, state='known', verdict='malicious', family='asyncrat',
                                   checked_at=now, next_check_at=now + timedelta(days=7))

    def page(self, warm=True):
        # The page only shows stored correlations; the endpoint (or this) computes them.
        if warm:
            correlations_for_upload(self.frst, self.user)
        with mock.patch('fixlist.views.uploads.highlight_log', wraps=__import__(
                'fixlist.log_highlighting', fromlist=['highlight_log']).highlight_log):
            return self.client.get(reverse('view_uploaded_log', args=['frst-log']))

    def test_b_correlation_in_page_data_and_summary(self):
        response = self.page()
        html = response.content.decode()
        self.assertIn('id="correlationData"', html)
        run_line_no = FRST.split('\n').index(RUN_LINE) + 1
        summary = [item for item in response.context['highlight'].summary if item.correlation]
        self.assertEqual([(item.line_no, item.name, item.severity, item.status, item.correlation_added)
                          for item in summary],
                         [(run_line_no, RUN_LINE, 'b', 'B', True)])
        # Verdict, family and log type only: never log ids.
        self.assertEqual(summary[0].correlation, 'correlated: asyncrat · centralbox: malicious · Malwarebytes')
        self.assertIn('<span class="hl-jump-cor">correlated: asyncrat', html)
        self.assertIn(f'<li data-line="{run_line_no}" data-cor-added>', html)
        # Its name is the line's syntax tokens, like the rule-verdict entries.
        self.assertTrue(summary[0].name_html)
        self.assertIn('<span class="hl-jump-name hl-sev-b"><span class="hl-jump-tokens">', html)
        self.assertTrue(response.context['correlations']['fresh'])
        # The line itself carries no extra text (the marker is CSS only).
        self.assertNotIn('ⓘ', html.split('id="uploadedContent"', 1)[1].split('</div>', 1)[0])

    def test_every_coloured_correlation_is_in_the_summary(self):
        pup_sha = 'f6' * 32
        pup = make_uploaded_log('mb-pup', log_type='Malwarebytes', forum_username='nobody', content=(
            'PUP.Optional.OkTool, C:\\PROGRAM FILES\\OK\\ok.exe, Quarantined, 8322, 1457763, '
            f'1.0.116571, , ame, , {"a" * 32}, {pup_sha}'))
        UploadedLogFileHash.rebuild_for(pup)
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=pup)
        response = self.page()
        other_line_no = FRST.split('\n').index(OTHER_LINE) + 1
        items = {item.line_no: item for item in response.context['highlight'].summary if item.correlation}
        self.assertEqual((items[other_line_no].severity, items[other_line_no].status, items[other_line_no].name),
                         ('p', 'P', OTHER_LINE))
        self.assertEqual(items[other_line_no].correlation, 'correlated: PUP.Optional.OkTool · Malwarebytes')

    def test_a_line_listed_by_its_rule_verdict_gets_the_correlation_added(self):
        from ..log_highlighting import SummaryItem
        from ..views.centralbox import page_correlation_context

        run_line_no = FRST.split('\n').index(RUN_LINE) + 1
        highlight = mock.Mock()
        highlight.summary = [SummaryItem(run_line_no, 'p', RUN_LINE, 'target', status='P')]
        correlations_for_upload(self.frst, self.user)
        page_correlation_context(self.frst, self.user, highlight)
        self.assertEqual(len(highlight.summary), 1)
        item = highlight.summary[0]
        self.assertEqual((item.status, item.name, item.target), ('P', RUN_LINE, 'target'))
        self.assertEqual(item.correlation, 'correlated: asyncrat · centralbox: malicious · Malwarebytes')
        self.assertFalse(item.correlation_added)

    def test_grey_correlations_stay_out_of_the_summary(self):
        HashVerdict.objects.filter(sha256=EVIL_SHA).delete()
        InfectionCaseLog.objects.exclude(uploaded_log=self.frst).delete()
        UploadedLog.objects.exclude(pk=self.frst.pk).update(forum_username='someone else')
        fix = make_uploaded_log('fix-grey', log_type='Fixlog', content=FIXLOG, forum_username='other')
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=fix)
        response = self.page()
        self.assertIn('id="correlationData"', response.content.decode())
        self.assertFalse([item for item in response.context['highlight'].summary if item.correlation])

    def test_no_data_without_related_logs(self):
        InfectionCaseLog.objects.exclude(uploaded_log=self.frst).delete()
        UploadedLog.objects.exclude(pk=self.frst.pk).update(forum_username='someone else')
        self.assertNotIn('id="correlationData"', self.page().content.decode())


class LogViewNeverWaitsTests(TestCase):
    """The log page shows stored correlations only; when they are outdated or
    missing it says so (`fresh` false) and the page script asks the endpoint."""

    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.case = InfectionCase.objects.create(owner=self.user, username='bob', auto_assign_new_items=False)
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST, forum_username='nobody')
        cache_analysis(self.frst, [RUN_LINE, OTHER_LINE])
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=self.frst)
        mb = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MB_SAME, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(mb)
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=mb)
        now = timezone.now()
        HashVerdict.objects.create(sha256=EVIL_SHA, state='known', verdict='malicious', family='asyncrat',
                                   checked_at=now, next_check_at=now + timedelta(days=7))
        self.run_line_no = FRST.split('\n').index(RUN_LINE) + 1

    def page_without_computing(self):
        from ..correlations import forward as case_correlations

        with mock.patch.object(case_correlations, '_compute', side_effect=AssertionError('computed during render')):
            return self.client.get(reverse('view_uploaded_log', args=['frst-log']))

    def test_nothing_stored_yet_renders_at_once_and_asks_for_a_refresh(self):
        response = self.page_without_computing()
        context = response.context['correlations']
        self.assertFalse(context['fresh'])
        self.assertEqual(context['lines'], {})
        self.assertEqual(context['refresh_url'], reverse('case_correlations_api') + '?upload_id=frst-log')
        self.assertIn('id="correlationData"', response.content.decode())
        self.assertFalse([item for item in response.context['highlight'].summary if item.correlation])

    def test_outdated_answer_is_shown_and_marked_not_fresh(self):
        correlations_for_upload(self.frst, self.user)
        # A new verdict changes the signature: the stored answer is outdated.
        HashVerdict.objects.filter(sha256=EVIL_SHA).update(checked_at=timezone.now() + timedelta(seconds=5))
        response = self.page_without_computing()
        context = response.context['correlations']
        self.assertFalse(context['fresh'])
        self.assertEqual(context['lines'][str(self.run_line_no)]['status'], 'B')
        self.assertTrue([item for item in response.context['highlight'].summary if item.correlation])

    def test_endpoint_computes_with_notes_and_the_next_page_is_fresh(self):
        answer = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-log'}).json()
        self.assertEqual(answer['statuses'][RUN_LINE], 'B')
        self.assertEqual(answer['notes'], {RUN_LINE: 'asyncrat · centralbox: malicious · Malwarebytes'})
        context = self.page_without_computing().context['correlations']
        self.assertTrue(context['fresh'])
        self.assertEqual(context['lines'][str(self.run_line_no)]['status'], 'B')

    def test_nothing_to_correlate_needs_no_refresh(self):
        InfectionCaseLog.objects.exclude(uploaded_log=self.frst).delete()
        UploadedLog.objects.exclude(pk=self.frst.pk).update(forum_username='someone else')
        response = self.page_without_computing()
        self.assertEqual(response.context['correlations'], {})
        self.assertNotIn('id="correlationData"', response.content.decode())


CELESTIAL = 'C:\\Users\\Bob\\Downloads\\Celestial-Setup-6.2.2.exe'
CELESTIAL_LINE = (f'2026-05-23 16:10 - 2026-05-23 16:10 - 012345678 _____ (Celestial) {CELESTIAL}')
DEFENDER_BLOCKS = '\n'.join([
    'Fix result of Farbar Recovery Scan Tool (x64) Version: 10-11-2026',
    "========= Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'} =========",
    '',
    # Newest first: the action taken (1117) before the detection (1116).
    'Time     : 5/23/2026 4:20:25 PM',
    'ID       : 1117',
    'Threat   : Trojan:Win32/Malgent!MSR',
    'Severity : Severe',
    f'Path     : file:_{CELESTIAL}',
    'Process  : C:\\Windows\\explorer.exe',
    'Action   : Quarantine',
    '',
    'Time     : 5/23/2026 4:20:20 PM',
    'ID       : 1116',
    'Threat   : Trojan:Win32/Malgent!MSR',
    'Severity : Severe',
    f'Path     : file:_{CELESTIAL}',
    'Process  : C:\\Windows\\explorer.exe',
    'Action   : Not Applicable',
    '',
    'Time     : 5/23/2026 4:00:00 PM',
    'ID       : 1116',
    'Threat   : HackTool:Win32/Patcher',
    'Severity : High',
    'Path     : containerfile:_C:\\Users\\Bob\\Downloads\\Skedule.rar; \r',
    '           file:_C:\\Users\\Bob\\Downloads\\Skedule.rar->Schedule I\\Custom.dll\r',
    'Process  : Unknown',
    'Action   : Remove',
    '',
    'Time     : 5/23/2026 3:00:00 PM',
    'ID       : 1116',
    'Threat   : PUA:Win32/Presenoker',
    'Severity : Low',
    # Wrapped mid-word by PowerShell; a URL and a process entry follow.
    'Path     : webfile:_C:\\Users\\Bob\\OneDrive\\Deskto',
    '           p\\Lichii.exe|https://example.com/x?a=1|pid:3,ProcessStart:1; process:_pid:3,ProcessStart:1',
    'Process  : C:\\Windows\\explorer.exe',
    'Action   : Quarantine',
    '',
    'Time     : 5/23/2026 2:00:00 PM',
    'ID       : 1116',
    'Threat   : Behavior:Win32/Execution',
    'Path     : behavior:_process: C:\\Windows\\x.exe, pid:1; regkey:_HKLM\\Software\\X',
    'Action   : Not Applicable',
])


class DefenderDetectionTests(TestCase):
    def test_parser_finds_the_files_with_threat_and_action(self):
        from ..case_correlations import defender_severity, iter_defender_detections

        found = sorted(iter_defender_detections(DEFENDER_BLOCKS), key=lambda item: item[0])
        lines = DEFENDER_BLOCKS.split('\n')
        self.assertEqual([(threat, action, path) for _line, threat, action, path in found], [
            ('Trojan:Win32/Malgent!MSR', 'Quarantine', CELESTIAL),
            ('HackTool:Win32/Patcher', 'Remove', 'C:\\Users\\Bob\\Downloads\\Skedule.rar'),
            ('PUA:Win32/Presenoker', 'Quarantine', 'C:\\Users\\Bob\\OneDrive\\Desktop\\Lichii.exe'),
        ])
        # The Threat line of the event whose action is kept.
        self.assertEqual(lines[found[0][0] - 1], 'Threat   : Trojan:Win32/Malgent!MSR')
        self.assertEqual(lines[found[0][0] + 3], 'Action   : Quarantine')
        self.assertEqual([defender_severity(threat) for _l, threat, _a, _p in found], ['b', 'g', 'p'])

    def test_frst_line_correlates_with_the_defender_detection(self):
        user = make_user()
        self.client.force_login(user)
        case = InfectionCase.objects.create(owner=user, username='bob', auto_assign_new_items=False)
        frst = make_uploaded_log('frst-def', log_type='FRST', forum_username='nobody',
                                 content='\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)', CELESTIAL_LINE]))
        cache_analysis(frst, [CELESTIAL_LINE])
        fix = make_uploaded_log('fix-def', log_type='Fixlog', content=DEFENDER_BLOCKS, forum_username='nobody')
        for upload in (frst, fix):
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-def'}).json()
        http.assert_not_called()
        request.assert_not_called()
        (item,) = body['correlations'][CELESTIAL_LINE]
        self.assertEqual((item['kind'], item['upload_id'], item['detection'], item['action'], item['source']),
                         ('detection', 'fix-def', 'Trojan:Win32/Malgent!MSR', 'Quarantine', 'defender'))
        self.assertEqual(body['statuses'][CELESTIAL_LINE], 'B')
        self.assertEqual(body['notes'][CELESTIAL_LINE], 'Trojan:Win32/Malgent!MSR · Defender · Fixlog')

    def test_a_defender_exclusion_line_correlates_by_its_path(self):
        exclusion = 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths|' + CELESTIAL
        user = make_user()
        self.client.force_login(user)
        case = InfectionCase.objects.create(owner=user, username='bob', auto_assign_new_items=False)
        frst = make_uploaded_log('frst-excl', log_type='FRST', forum_username='nobody',
                                 content='\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)', exclusion]))
        cache_analysis(frst, [exclusion])  # no parsed components: the path comes from after the "|"
        fix = make_uploaded_log('fix-excl', log_type='Fixlog', content=DEFENDER_BLOCKS, forum_username='nobody')
        for upload in (frst, fix):
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)
        body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-excl'}).json()
        (item,) = body['correlations'][exclusion]
        self.assertEqual((item['detection'], item['source']), ('Trojan:Win32/Malgent!MSR', 'defender'))


class LogViewLookupTests(TestCase):
    """The log page's info panel can look up correlated hashes: it gets the
    same endpoints as the analyzer, and whether centralbox is available."""

    def test_correlation_context_carries_the_lookup_urls(self):
        from django.test import override_settings

        user = make_user()
        case = InfectionCase.objects.create(owner=user, username='bob', auto_assign_new_items=False)
        frst = make_uploaded_log('frst-look', log_type='FRST', content=FRST, forum_username='nobody')
        cache_analysis(frst, [RUN_LINE, OTHER_LINE])
        mb = make_uploaded_log('mb-look', log_type='Malwarebytes', content=MB_SAME, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(mb)
        for upload in (frst, mb):
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)
        correlations_for_upload(frst, user)
        self.client.force_login(user)
        with override_settings(CENTRALBOX_API_KEY='cbt_server'):
            context = self.client.get(reverse('view_uploaded_log', args=['frst-look'])).context['correlations']
        self.assertTrue(context['can_lookup'])
        self.assertEqual(context['hash_url'], reverse('centralbox_hash_check_api'))
        self.assertEqual(context['fresh_url'], reverse('centralbox_fresh_start_api'))
        self.assertEqual(context['fresh_status_url'], reverse('centralbox_fresh_status_api', args=['0' * 64]))
        context = self.client.get(reverse('view_uploaded_log', args=['frst-look'])).context['correlations']
        self.assertFalse(context['can_lookup'])  # no server key in tests
