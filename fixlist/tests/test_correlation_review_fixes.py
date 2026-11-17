"""Fixes from the review of the correlations and automatic centralbox
lookups: a lost cache race keeps the answer, the MD5 and SHA256 of one file
are one queue item, the analyzer is only told about queued lookups that can
start, and files in a flagged line's command line count. No network."""

from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.db import IntegrityError
from django.test import TestCase, override_settings
from django.utils import timezone

from .. import centralbox, centralbox_auto
from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..case_correlations import correlations_for_upload
from ..models import (
    CentralboxAutoQueue, CentralboxFreshLookup, CorrelationCache, HashAlias, InfectionCase, InfectionCaseLog,
    SiteConfig, UploadedLogAnalysis, UploadedLogFileHash,
)
from .factories import make_uploaded_log, make_user
from .test_case_correlations import FRST, MB_EVIL, OTHER_LINE, RUN_LINE, cache_analysis
from .test_centralbox_auto_fresh import SERVER_KEY, FakeCentralbox, sha

MD5 = 'ab' * 16


class CacheRaceTests(TestCase):
    def test_a_lost_cache_write_still_returns_the_answer(self):
        user = make_user()
        case = InfectionCase.objects.create(owner=user, username='bob')
        frst = make_uploaded_log('frst-log', log_type='FRST', content=FRST, forum_username='nobody')
        cache_analysis(frst, [RUN_LINE, OTHER_LINE])
        mb = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MB_EVIL, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(mb)
        for upload in (frst, mb):
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload, added_by=user)
        with mock.patch.object(CorrelationCache.objects, 'update_or_create', side_effect=IntegrityError('race')):
            result = correlations_for_upload(frst, user)
        self.assertEqual(list(result['lines']), [RUN_LINE])


@override_settings(CENTRALBOX_API_KEY=SERVER_KEY, CENTRALBOX_CALLS_PER_MINUTE=1000,
                   CENTRALBOX_AUTO_READS_PER_MINUTE=1000)
class HashFormTests(TestCase):
    def setUp(self):
        cache.clear()
        centralbox._consecutive_failures = 0
        now = timezone.now()
        HashAlias.objects.create(md5=MD5, sha256=sha(1), checked_at=now, next_check_at=now + timedelta(days=1))

    def enqueue(self, value):
        CentralboxAutoQueue.objects.create(hash=value, priority=2, reason='test', enqueued_at=timezone.now())

    def test_hash_forms(self):
        self.assertEqual(centralbox.hash_forms(MD5), {MD5, sha(1)})
        self.assertEqual(centralbox.hash_forms(sha(1)), {MD5, sha(1)})
        self.assertEqual(centralbox.hash_forms(sha(2)), {sha(2)})

    def test_drainer_drops_an_md5_whose_sha256_was_looked_up(self):
        CentralboxFreshLookup.objects.create(sha256=sha(1), requested_at=timezone.now(), state='done')
        self.enqueue(MD5)
        fake = FakeCentralbox()
        with mock.patch.object(centralbox, '_request', side_effect=fake):
            centralbox_auto.drain_round()
        self.assertEqual(fake.posted(), [])
        self.assertFalse(CentralboxAutoQueue.objects.exists())

    def test_a_manual_lookup_of_the_sha256_takes_the_md5_off_the_queue(self):
        self.enqueue(MD5)
        with mock.patch.object(centralbox, '_request', side_effect=FakeCentralbox()):
            result = centralbox.start_fresh_lookup(sha(1), make_user())
        self.assertTrue(result['ok'])
        self.assertFalse(CentralboxAutoQueue.objects.exists())


@override_settings(CENTRALBOX_API_KEY=SERVER_KEY)
class QueueStateTests(TestCase):
    def setUp(self):
        CentralboxAutoQueue.objects.create(hash=sha(1), priority=2, reason='test', enqueued_at=timezone.now())

    def test_queued_items_count_only_while_the_queue_moves(self):
        self.assertEqual(centralbox_auto.queue_state([sha(1)]), (1, 0))
        SiteConfig.get_solo()
        SiteConfig.objects.filter(pk=1).update(centralbox_auto_fresh_enabled=False)
        self.assertEqual(centralbox_auto.queue_state([sha(1)]), (0, 0))

    def test_not_after_the_daily_cap(self):
        CentralboxFreshLookup.objects.create(sha256=sha(2), requested_at=timezone.now(), state='done', auto=True)
        with override_settings(CENTRALBOX_AUTO_FRESH_PER_DAY=1):
            self.assertEqual(centralbox_auto.queue_state([sha(1)]), (0, 0))


class FlaggedArgumentTests(TestCase):
    def test_a_script_run_by_a_flagged_task_is_flagged(self):
        line = (r'Task: {5F2EAF8F-4827-4B10-A79A-83A72769A412} - System32\Tasks\Evil => '
                r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -f "C:\Users\Bob\AppData\Roaming\a.ps1"')
        log = make_uploaded_log('frst-log', log_type='FRST', content=line, forum_username='nobody')
        UploadedLogAnalysis.objects.create(
            upload=log, rule_set_key='shared', source_content_hash=log.content_hash,
            payload={'format': ANALYSIS_PAYLOAD_FORMAT, 'lines': [{
                'line': line, 'dominant_status': 'B',
                'components': {'arguments': r'-f "C:\Users\Bob\AppData\Roaming\a.ps1"'},
            }]},
        )
        flagged = centralbox_auto.flagged_frst_paths([log])
        self.assertEqual(flagged.get(r'c:\users\username\appdata\roaming\a.ps1'), 'B')
