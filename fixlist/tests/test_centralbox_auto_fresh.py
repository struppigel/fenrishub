"""Automatic fresh centralbox lookups (fixlist/centralbox_auto.py).

Likely malicious hashes (scanner malware detections, MAU removals, files of
FRST lines at B / ! / P) are queued and started slowly, leaving most of the
fresh-lookup budget to the helpers. No test reaches the network (`_request`
is mocked) and no drainer thread runs: rounds are called directly."""

from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .. import centralbox, centralbox_auto
from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..models import (
    CentralboxAutoQueue, CentralboxFreshLookup, HashAlias, HashVerdict, InfectionCase, InfectionCaseLog,
    SiteConfig, UploadedLog, UploadedLogAnalysis, UploadedLogFileHash,
)
from .factories import make_uploaded_log, make_user
from .test_centralbox_views import EVIL_SHA, FRST_LOG, FRST_OTHER_LINE, FRST_RUN_LINE, MB_EVIL
from .test_log_highlighting import MALWAREBYTES

SERVER_KEY = 'cbt_server'
EVIL_MD5 = 'ab' * 16
OK_MD5 = 'cd' * 16

FIXLOG_FOLDER = '\n'.join([
    'Fix result of Farbar Recovery Scan Tool (x64) Version: 01-11-2026',
    '========================= Folder: C:\\Users\\Bob\\AppData\\Roaming\\evil ========================',
    f'2026-11-11 17:32 - 2026-11-11 17:32 - 000000312 ____A [{EVIL_MD5.upper()}] () '
    'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe',
    f'2026-11-11 17:32 - 2026-11-11 17:32 - 000000312 ____A [{OK_MD5.upper()}] (Ok Inc.) '
    'C:\\Program Files\\Ok\\ok.exe',
    '====== End of Folder: ======',
])


def sha(n):
    return f'{n:064x}'


def store_frst_statuses(log, statuses, key='shared'):
    """A cached analysis of an FRST log: {line: dominant status}."""
    UploadedLogAnalysis.objects.update_or_create(
        upload=log, rule_set_key=key,
        defaults={
            'payload': {'format': ANALYSIS_PAYLOAD_FORMAT,
                        'lines': [{'line': line, 'dominant_status': status} for line, status in statuses.items()]},
            'source_content_hash': log.content_hash,
        },
    )


def add_rows(upload, hashes, source='mau', detection=''):
    UploadedLogFileHash.objects.bulk_create([
        UploadedLogFileHash(upload=upload, sha256=value, line_no=i + 1, anchor_line_no=i + 1,
                            source=source, detection=detection, auto=True)
        for i, value in enumerate(hashes)
    ])


class FakeCentralbox:
    """`_request` stand-in: hashes in `known` are known and clean, all
    others unknown; POST /lookup answers 'running'."""

    def __init__(self, known=(), post_status='running'):
        self.known = set(known)
        self.post_status = post_status
        self.calls = []

    def __call__(self, method, path, key, body=None):
        self.calls.append((method, path, body))
        if method == 'POST':
            return {'ok': True, 'status': self.post_status, 'hash': body['hash']}
        value = path.rsplit('/', 1)[-1]
        if value in self.known:
            return {'ok': True, 'analysed': True, 'sha256': value, 'verdict': 'clean', 'family': ''}
        return {'ok': True, 'analysed': False, 'lookup': 'running'}

    def posted(self):
        return [body['hash'] for method, _path, body in self.calls if method == 'POST']


@override_settings(CENTRALBOX_API_KEY=SERVER_KEY)
class CandidateTests(TestCase):
    def setUp(self):
        cache.clear()
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST_LOG, forum_username='nobody')
        self.fixlog = make_uploaded_log('fixlog', log_type='Fixlog', content=FIXLOG_FOLDER, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.fixlog)

    def test_scanner_malware_detections_are_candidates_and_pups_are_not(self):
        evil = make_uploaded_log('mb-evil', log_type='Malwarebytes', content=MB_EVIL)
        pup = make_uploaded_log('mb-pup', log_type='Malwarebytes', content=MALWAREBYTES)
        UploadedLogFileHash.rebuild_for(evil)
        UploadedLogFileHash.rebuild_for(pup)
        found = centralbox_auto.auto_fresh_candidates([evil.pk, pup.pk])
        self.assertEqual(list(found), [EVIL_SHA])
        self.assertEqual(found[EVIL_SHA], (CentralboxAutoQueue.PRIORITY_SCANNER, 'Malwarebytes: Trojan.AsyncRAT'))

    def test_scanner_rows_without_a_detection_name_are_not_candidates(self):
        hmp = make_uploaded_log('hmp', log_type='HitmanPro')
        add_rows(hmp, [sha(1)], source='hitmanpro', detection='')
        add_rows(hmp, [sha(2)], source='hitmanpro', detection='Trojan.Generic')
        self.assertEqual(list(centralbox_auto.auto_fresh_candidates([hmp.pk])), [sha(2)])

    def test_mau_rows_are_candidates(self):
        mau = make_uploaded_log('mau', log_type='MAU')
        add_rows(mau, [sha(1), sha(2)])
        found = centralbox_auto.auto_fresh_candidates([mau.pk])
        self.assertEqual(set(found), {sha(1), sha(2)})
        self.assertEqual(found[sha(1)][0], CentralboxAutoQueue.PRIORITY_MAU)

    def test_folder_md5_counts_when_its_frst_line_is_b_warning_or_pup(self):
        for status, priority in (('B', CentralboxAutoQueue.PRIORITY_FRST_B),
                                 ('!', CentralboxAutoQueue.PRIORITY_FRST_FLAGGED),
                                 ('P', CentralboxAutoQueue.PRIORITY_FRST_FLAGGED)):
            store_frst_statuses(self.frst, {FRST_RUN_LINE: status, FRST_OTHER_LINE: 'C'})
            flagged = centralbox_auto.flagged_frst_paths([self.frst])
            found = centralbox_auto.auto_fresh_candidates([self.fixlog.pk], flagged)
            self.assertEqual(found, {EVIL_MD5: (priority, f'FRST line at {status}')})

    def test_folder_md5_does_not_count_for_clean_or_unknown_lines(self):
        store_frst_statuses(self.frst, {FRST_RUN_LINE: '?', FRST_OTHER_LINE: 'C'})
        flagged = centralbox_auto.flagged_frst_paths([self.frst])
        self.assertEqual(flagged, {})
        self.assertEqual(centralbox_auto.auto_fresh_candidates([self.fixlog.pk], flagged), {})

    def test_stale_cached_analysis_is_ignored(self):
        store_frst_statuses(self.frst, {FRST_RUN_LINE: 'B'})
        UploadedLogAnalysis.objects.filter(upload=self.frst).update(source_content_hash='other')
        self.assertEqual(centralbox_auto.flagged_frst_paths([self.frst]), {})

    def test_a_log_with_more_than_100_candidates_is_skipped_whole(self):
        big = make_uploaded_log('mau-big', log_type='MAU')
        add_rows(big, [sha(i) for i in range(101)])
        small = make_uploaded_log('mau-small', log_type='MAU')
        add_rows(small, [sha(1000 + i) for i in range(100)] + [sha(5)])  # 101 too, but one shared with big
        exact = make_uploaded_log('mau-exact', log_type='MAU')
        add_rows(exact, [sha(2000 + i) for i in range(100)])
        with self.assertLogs('fixlist.centralbox', 'WARNING'):
            found = centralbox_auto.auto_fresh_candidates([big.pk, small.pk, exact.pk])
        self.assertEqual(set(found), {sha(2000 + i) for i in range(100)})

    def test_a_shared_hash_still_counts_through_a_log_under_the_cap(self):
        big = make_uploaded_log('mau-big', log_type='MAU')
        add_rows(big, [sha(i) for i in range(101)])
        small = make_uploaded_log('mau-small', log_type='MAU')
        add_rows(small, [sha(5)])
        with self.assertLogs('fixlist.centralbox', 'WARNING'):
            self.assertEqual(set(centralbox_auto.auto_fresh_candidates([big.pk, small.pk])), {sha(5)})


@override_settings(CENTRALBOX_API_KEY=SERVER_KEY)
class EnqueueTests(TestCase):
    def setUp(self):
        cache.clear()
        self.mau = make_uploaded_log('mau', log_type='MAU')

    def queue(self):
        return dict(CentralboxAutoQueue.objects.values_list('hash', 'priority'))

    def test_queues_unknown_candidates_and_keeps_the_better_priority(self):
        add_rows(self.mau, [sha(1), sha(2)])
        self.assertEqual(centralbox_auto.enqueue_auto_fresh([self.mau.pk]), 2)
        self.assertEqual(self.queue(), {sha(1): 2, sha(2): 2})
        mb = make_uploaded_log('mb', log_type='Malwarebytes')
        add_rows(mb, [sha(1)], source='malwarebytes', detection='Trojan.X')
        self.assertEqual(centralbox_auto.enqueue_auto_fresh([mb.pk]), 0)
        self.assertEqual(self.queue(), {sha(1): 0, sha(2): 2})
        self.assertEqual(CentralboxAutoQueue.objects.get(hash=sha(1)).reason, 'Malwarebytes: Trojan.X')
        # A worse priority never downgrades.
        centralbox_auto.enqueue_auto_fresh([self.mau.pk])
        self.assertEqual(self.queue(), {sha(1): 0, sha(2): 2})

    def test_known_and_already_looked_up_hashes_are_not_queued(self):
        now = timezone.now()
        add_rows(self.mau, [sha(1), sha(2), sha(3), sha(4)])
        HashVerdict.objects.create(sha256=sha(1), state='known', verdict='clean', checked_at=now, next_check_at=now)
        HashVerdict.objects.create(sha256=sha(2), state='unknown', checked_at=now, next_check_at=now)
        CentralboxFreshLookup.objects.create(sha256=sha(3), requested_at=now - timedelta(days=30), state='not_found')
        centralbox_auto.enqueue_auto_fresh([self.mau.pk])
        self.assertEqual(set(self.queue()), {sha(2), sha(4)})

    def test_md5s_are_queued_as_the_sha256_they_stand_for_when_known(self):
        tk = make_uploaded_log('tk', log_type='Trojan Killer')
        UploadedLogFileHash.objects.create(upload=tk, md5=EVIL_MD5, line_no=1, anchor_line_no=1,
                                           source='trojan_killer', detection='Trojan.Win32.X')
        UploadedLogFileHash.objects.create(upload=tk, md5=OK_MD5, line_no=2, anchor_line_no=2,
                                           source='trojan_killer', detection='Trojan.Win32.Y')
        now = timezone.now()
        HashAlias.objects.create(md5=OK_MD5, sha256=sha(9), checked_at=now, next_check_at=now)
        centralbox_auto.enqueue_auto_fresh([tk.pk])
        self.assertEqual(set(self.queue()), {EVIL_MD5, sha(9)})

    def test_nothing_is_queued_when_switched_off_or_without_a_key(self):
        add_rows(self.mau, [sha(1)])
        SiteConfig.get_solo()
        SiteConfig.objects.filter(pk=1).update(centralbox_auto_fresh_enabled=False)
        self.assertEqual(centralbox_auto.enqueue_auto_fresh([self.mau.pk]), 0)
        SiteConfig.objects.filter(pk=1).update(centralbox_auto_fresh_enabled=True)
        with override_settings(CENTRALBOX_API_KEY=''):
            self.assertEqual(centralbox_auto.enqueue_auto_fresh([self.mau.pk]), 0)
        self.assertEqual(self.queue(), {})

    def test_after_upload_the_forum_users_recent_frst_lines_are_used(self):
        frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST_LOG, forum_username='nobody')
        store_frst_statuses(frst, {FRST_RUN_LINE: 'B'})
        fixlog = make_uploaded_log('fixlog', log_type='Fixlog', content=FIXLOG_FOLDER, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(fixlog)
        stranger = make_uploaded_log('fixlog-2', log_type='Fixlog', content=FIXLOG_FOLDER, forum_username='else')
        UploadedLogFileHash.rebuild_for(stranger)
        self.assertEqual(centralbox_auto.enqueue_for_upload(stranger), 0)
        self.assertEqual(centralbox_auto.enqueue_for_upload(fixlog), 1)
        self.assertEqual(self.queue(), {EVIL_MD5: CentralboxAutoQueue.PRIORITY_FRST_B})

    def test_after_upload_old_logs_of_the_forum_user_are_left_out(self):
        frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST_LOG, forum_username='nobody')
        store_frst_statuses(frst, {FRST_RUN_LINE: 'B'})
        UploadedLog.objects.filter(pk=frst.pk).update(created_at=timezone.now() - timedelta(days=60))
        fixlog = make_uploaded_log('fixlog', log_type='Fixlog', content=FIXLOG_FOLDER, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(fixlog)
        self.assertEqual(centralbox_auto.enqueue_for_upload(fixlog), 0)


@override_settings(CENTRALBOX_API_KEY=SERVER_KEY, CENTRALBOX_CALLS_PER_MINUTE=1000,
                   CENTRALBOX_AUTO_READS_PER_MINUTE=1000)
class DrainTests(TestCase):
    def setUp(self):
        cache.clear()
        centralbox._consecutive_failures = 0

    def enqueue(self, value, priority=2, minutes_ago=0):
        return CentralboxAutoQueue.objects.create(
            hash=value, priority=priority, reason='test', enqueued_at=timezone.now() - timedelta(minutes=minutes_ago),
        )

    def drain(self, fake=None):
        fake = fake or FakeCentralbox()
        with mock.patch.object(centralbox, '_request', side_effect=fake):
            more = centralbox_auto.drain_round()
        return fake, more

    def test_starts_by_priority_then_age_up_to_the_running_maximum(self):
        self.enqueue(sha(1), priority=3)
        self.enqueue(sha(2), priority=0, minutes_ago=1)
        self.enqueue(sha(3), priority=0, minutes_ago=5)
        self.enqueue(sha(4), priority=2)
        with override_settings(CENTRALBOX_AUTO_FRESH_MAX_RUNNING=3):
            fake, more = self.drain()
        self.assertEqual(fake.posted(), [sha(3), sha(2), sha(4)])
        self.assertTrue(more)
        self.assertEqual(list(CentralboxAutoQueue.objects.values_list('hash', flat=True)), [sha(1)])
        rows = CentralboxFreshLookup.objects.filter(sha256__in=[sha(2), sha(3), sha(4)])
        self.assertTrue(all(row.auto and row.requested_by is None for row in rows))
        self.assertEqual(rows.count(), 3)

        # Still running: nothing new starts.
        with override_settings(CENTRALBOX_AUTO_FRESH_MAX_RUNNING=3):
            fake, _ = self.drain()
        self.assertEqual(fake.posted(), [])
        self.assertTrue(CentralboxAutoQueue.objects.filter(hash=sha(1)).exists())

    def test_hashes_centralbox_knows_are_dropped_without_a_fresh_lookup(self):
        self.enqueue(sha(1))
        fake, _ = self.drain(FakeCentralbox(known={sha(1)}))
        self.assertEqual(fake.posted(), [])
        self.assertFalse(CentralboxAutoQueue.objects.exists())

    def test_a_hash_without_a_sample_anywhere_is_dropped_for_good(self):
        mau = make_uploaded_log('mau', log_type='MAU')
        add_rows(mau, [sha(1)])
        self.assertEqual(centralbox_auto.enqueue_auto_fresh([mau.pk]), 1)
        fake, more = self.drain(FakeCentralbox(post_status='not_found'))
        self.assertEqual(fake.posted(), [sha(1)])
        self.assertEqual(CentralboxFreshLookup.objects.get(sha256=sha(1)).state, 'not_found')
        self.assertFalse(CentralboxAutoQueue.objects.exists())
        self.assertFalse(more)
        # Later triggers never queue it again, even after the cooldown.
        CentralboxFreshLookup.objects.update(requested_at=timezone.now() - timedelta(days=30))
        self.assertEqual(centralbox_auto.enqueue_auto_fresh([mau.pk]), 0)
        self.assertFalse(CentralboxAutoQueue.objects.exists())

    def test_a_lookup_that_finds_nothing_while_running_is_dropped_too(self):
        CentralboxFreshLookup.objects.create(sha256=sha(1), requested_at=timezone.now(), state='running', auto=True)
        fake = FakeCentralbox()
        fake_status = fake.__call__

        def not_found(method, path, key, body=None):
            if method == 'GET':
                fake.calls.append((method, path, body))
                return {'ok': True, 'analysed': False, 'lookup': 'not_found'}
            return fake_status(method, path, key, body)

        with mock.patch.object(centralbox, '_request', side_effect=not_found):
            more = centralbox_auto.drain_round()
        self.assertEqual(CentralboxFreshLookup.objects.get(sha256=sha(1)).state, 'not_found')
        self.assertFalse(more)
        mau = make_uploaded_log('mau', log_type='MAU')
        add_rows(mau, [sha(1)])
        self.assertEqual(centralbox_auto.enqueue_auto_fresh([mau.pk]), 0)

    def test_md5s_are_checked_then_looked_up(self):
        self.enqueue(EVIL_MD5)
        fake, _ = self.drain()
        self.assertEqual(fake.posted(), [EVIL_MD5])
        self.assertTrue(CentralboxFreshLookup.objects.get(sha256=EVIL_MD5).auto)

    def test_hashes_looked_up_meanwhile_are_dropped(self):
        self.enqueue(sha(1))
        CentralboxFreshLookup.objects.create(sha256=sha(1), requested_at=timezone.now(), state='done')
        fake, _ = self.drain()
        self.assertEqual(fake.calls, [])
        self.assertFalse(CentralboxAutoQueue.objects.exists())

    def test_expired_items_are_dropped(self):
        self.enqueue(sha(1), minutes_ago=8 * 24 * 60)
        fake, more = self.drain()
        self.assertEqual(fake.calls, [])
        self.assertFalse(CentralboxAutoQueue.objects.exists())
        self.assertFalse(more)

    def test_the_minute_ceiling_leaves_the_rest_to_the_helpers(self):
        for i in range(8):
            self.enqueue(sha(i + 1))
        with override_settings(CENTRALBOX_AUTO_FRESH_MAX_RUNNING=10):
            fake, more = self.drain()
        self.assertEqual(len(fake.posted()), 5)
        self.assertEqual(CentralboxAutoQueue.objects.count(), 3)
        self.assertTrue(more)
        # A helper can still start fresh lookups this minute.
        user = make_user()
        with mock.patch.object(centralbox, '_request', side_effect=FakeCentralbox()):
            result = centralbox.start_fresh_lookup(sha(100), user)
            self.assertTrue(result['ok'])
            refused = centralbox.start_fresh_lookup(sha(101), None, auto=True)
        self.assertFalse(refused['ok'])
        self.assertFalse(CentralboxFreshLookup.objects.filter(sha256=sha(101)).exists())

    def test_the_daily_cap_keeps_items_queued(self):
        CentralboxFreshLookup.objects.create(sha256=sha(50), requested_at=timezone.now() - timedelta(hours=2),
                                             state='done', auto=True)
        self.enqueue(sha(1))
        with override_settings(CENTRALBOX_AUTO_FRESH_PER_DAY=1):
            fake, more = self.drain()
        self.assertEqual(fake.calls, [])
        self.assertFalse(more)
        self.assertTrue(CentralboxAutoQueue.objects.filter(hash=sha(1)).exists())

    def test_running_lookups_are_polled_and_finish(self):
        CentralboxFreshLookup.objects.create(sha256=sha(1), requested_at=timezone.now(), state='running', auto=True)
        fake, more = self.drain(FakeCentralbox(known={sha(1)}))
        self.assertIn(('GET', f'/status/{sha(1)}', None), fake.calls)
        self.assertEqual(CentralboxFreshLookup.objects.get(sha256=sha(1)).state, 'done')
        self.assertFalse(more)

    def test_nothing_happens_while_switched_off_or_paused(self):
        self.enqueue(sha(1))
        SiteConfig.get_solo()
        SiteConfig.objects.filter(pk=1).update(centralbox_auto_fresh_enabled=False)
        fake, more = self.drain()
        self.assertEqual((fake.calls, more), ([], False))
        SiteConfig.objects.filter(pk=1).update(
            centralbox_auto_fresh_enabled=True, centralbox_paused_until=timezone.now() + timedelta(minutes=5),
        )
        fake, more = self.drain()
        self.assertEqual((fake.calls, more), ([], False))
        self.assertTrue(CentralboxAutoQueue.objects.exists())

    def test_a_manual_fresh_lookup_takes_the_hash_off_the_queue(self):
        self.enqueue(sha(1))
        with mock.patch.object(centralbox, '_request', side_effect=FakeCentralbox()):
            result = centralbox.start_fresh_lookup(sha(1), make_user())
        self.assertTrue(result['ok'])
        self.assertFalse(result['fresh']['auto'])
        self.assertFalse(CentralboxAutoQueue.objects.exists())

    def test_fresh_info_tells_automatic_lookups_apart(self):
        CentralboxFreshLookup.objects.create(sha256=sha(1), requested_at=timezone.now(), state='running', auto=True)
        self.assertTrue(centralbox.fresh_lookup_info([sha(1)])[sha(1)]['auto'])


class LeaseTests(TestCase):
    def test_one_drainer_at_a_time(self):
        first = centralbox_auto._take_lease()
        self.assertIsNotNone(first)
        self.assertIsNone(centralbox_auto._take_lease())
        renewed = centralbox_auto._renew_lease(first)
        self.assertIsNotNone(renewed)
        # The old value is no longer ours.
        self.assertIsNone(centralbox_auto._renew_lease(first))
        centralbox_auto._release_lease(renewed)
        self.assertIsNotNone(centralbox_auto._take_lease())

    def test_an_expired_lease_is_taken_over(self):
        first = centralbox_auto._take_lease()
        SiteConfig.objects.filter(pk=1).update(centralbox_auto_drainer_until=timezone.now() - timedelta(seconds=1))
        self.assertIsNotNone(centralbox_auto._take_lease())
        # The dead drainer cannot renew or release the new lease.
        self.assertIsNone(centralbox_auto._renew_lease(first))
        centralbox_auto._release_lease(first)
        self.assertIsNotNone(SiteConfig.get_solo().centralbox_auto_drainer_until)

    def test_no_thread_under_the_test_runner(self):
        with override_settings(CENTRALBOX_API_KEY=SERVER_KEY):
            CentralboxAutoQueue.objects.create(hash=sha(1), enqueued_at=timezone.now())
            self.assertFalse(centralbox_auto.ensure_auto_drainer())


@override_settings(CENTRALBOX_API_KEY=SERVER_KEY)
class SuggestionsApiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = make_user()
        self.client.force_login(self.user)
        case = InfectionCase.objects.create(owner=self.user, username='bob')
        self.frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST_LOG, forum_username='nobody')
        self.fixlog = make_uploaded_log('fixlog', log_type='Fixlog', content=FIXLOG_FOLDER, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.fixlog)
        InfectionCaseLog.objects.create(case=case, uploaded_log=self.frst, added_by=self.user)
        InfectionCaseLog.objects.create(case=case, uploaded_log=self.fixlog, added_by=self.user)

    def get(self):
        with mock.patch.object(centralbox, '_request') as request:
            response = self.client.get(reverse('centralbox_suggestions_api'), {'upload_id': 'frst-log'})
        request.assert_not_called()
        return response.json()

    def test_queues_the_files_of_the_viewers_flagged_lines_and_reports_them(self):
        store_frst_statuses(self.frst, {FRST_RUN_LINE: 'B', FRST_OTHER_LINE: 'C'})
        body = self.get()
        self.assertEqual((body['queued'], body['running']), (1, 0))
        self.assertEqual(list(CentralboxAutoQueue.objects.values_list('hash', flat=True)), [EVIL_MD5])

        CentralboxAutoQueue.objects.all().delete()
        CentralboxFreshLookup.objects.create(sha256=EVIL_MD5, requested_at=timezone.now(), state='running', auto=True)
        body = self.get()
        self.assertEqual((body['queued'], body['running']), (0, 1))

    def test_nothing_is_queued_for_clean_lines(self):
        store_frst_statuses(self.frst, {FRST_RUN_LINE: 'C'})
        body = self.get()
        self.assertEqual((body['queued'], body['running']), (0, 0))
        self.assertFalse(CentralboxAutoQueue.objects.exists())
