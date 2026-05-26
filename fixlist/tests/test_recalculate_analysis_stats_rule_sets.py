"""End-to-end tests for two-pass recalc (shared + effective) per rule set."""
from django.contrib.auth.models import User
from django.test import TestCase

from ..analyzer import invalidate_rule_buckets_cache
from ..models import (
    ClassificationRule,
    UploadedLog,
    UploadedLogAnalysis,
    UploadedLogStat,
    UserProfile,
)


def _add_rule(owner, source_text):
    return ClassificationRule.objects.create(
        owner=owner,
        status=ClassificationRule.STATUS_MALWARE,
        match_type=ClassificationRule.MATCH_EXACT,
        source_text=source_text,
    )


LOG_CONTENT = '\n'.join([
    'Scan result of Farbar Recovery Scan Tool',
    'shared-only-line',
    'private-only-line',
])


class RecalcCreatesBothCachesForPrivateRecipientTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.alice = User.objects.create_user(username='alice', password='pw')
        UserProfile.objects.create(user=self.alice, rule_set_mode='shared')
        self.bob = User.objects.create_user(username='bob', password='pw')
        UserProfile.objects.create(user=self.bob, rule_set_mode='private')
        _add_rule(self.alice, 'shared-only-line')
        _add_rule(self.bob, 'private-only-line')

    def test_private_recipient_writes_two_cache_rows_and_effective_counts(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content=LOG_CONTENT,
            log_type='FRST',
            recipient_user=self.bob,
        )
        invalidate_rule_buckets_cache()
        log.recalculate_analysis_stats()

        cached = {c.rule_set_key: c for c in UploadedLogAnalysis.objects.filter(upload=log)}
        self.assertIn('shared', cached)
        self.assertIn(f'private:{self.bob.id}', cached)
        self.assertEqual(len(cached), 2)

        # count_* reflects EFFECTIVE (private:bob) — only bob's rule fires => 1
        log.refresh_from_db()
        self.assertEqual(log.count_malware, 1)

        # /stats/ snapshot reflects SHARED — only alice's rule fires => 1
        stat = UploadedLogStat.objects.get(source_id=log.pk)
        self.assertEqual(stat.count_malware, 1)
        # But effective-vs-shared lines that matched differ: verify by checking
        # the cached payloads contain different matches per key
        shared_lines = [l for l in cached['shared'].payload['lines'] if l['matched']]
        private_lines = [l for l in cached[f'private:{self.bob.id}'].payload['lines'] if l['matched']]
        self.assertEqual({l['line'] for l in shared_lines}, {'shared-only-line'})
        self.assertEqual({l['line'] for l in private_lines}, {'private-only-line'})


class RecalcSharedRecipientWritesSingleCacheRowTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.alice = User.objects.create_user(username='alice', password='pw')
        UserProfile.objects.create(user=self.alice, rule_set_mode='shared')
        _add_rule(self.alice, 'shared-only-line')

    def test_shared_recipient_only_writes_shared_cache(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content=LOG_CONTENT,
            log_type='FRST',
            recipient_user=self.alice,
        )
        invalidate_rule_buckets_cache()
        log.recalculate_analysis_stats()

        rows = list(UploadedLogAnalysis.objects.filter(upload=log))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].rule_set_key, 'shared')


class StatsSnapshotZeroForNonAnalyzableTests(TestCase):
    def test_unknown_log_has_zero_malware_counts(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='unknown.txt',
            content='not an FRST log',
            log_type='Unknown',
        )
        log.recalculate_analysis_stats()
        stat = UploadedLogStat.objects.get(source_id=log.pk)
        # No analysis ran, so all classification counts stay zero.
        self.assertEqual(stat.count_malware, 0)
        self.assertEqual(stat.count_pup, 0)
