"""Tests that rule CRUD invalidates the in-memory rule-bucket cache for
affected keys. Persistent `UploadedLogAnalysis` rows are intentionally NOT
deleted on rule change — they're served as an instant (briefly stale) cache
while the next analysis runs."""
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..analyzer import _get_cached_rule_buckets, _rule_buckets_cache, invalidate_rule_buckets_cache
from ..models import (
    ClassificationRule,
    UploadedLog,
    UploadedLogAnalysis,
    UserProfile,
)


def _seed_cache_rows(user):
    """Create two UploadedLogAnalysis rows (shared + private:user.id) for a log."""
    log = UploadedLog.objects.create(
        forum_username='forum_user',
        original_filename='frst.txt',
        content='Scan result of Farbar Recovery Scan Tool\nrandom-line',
        log_type='FRST',
    )
    UploadedLogAnalysis.objects.create(
        upload=log, rule_set_key='shared',
        payload={'summary': {}}, source_content_hash=log.content_hash,
    )
    UploadedLogAnalysis.objects.create(
        upload=log, rule_set_key=f'private:{user.id}',
        payload={'summary': {}}, source_content_hash=log.content_hash,
    )
    return log


def _seed_bucket_cache(user):
    """Warm both in-memory bucket caches so we can assert they got cleared."""
    _get_cached_rule_buckets('shared')
    _get_cached_rule_buckets(f'private:{user.id}')


class SharedOwnerInvalidatesBothBucketsTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = User.objects.create_user(username='alice', password='pw')
        UserProfile.objects.create(user=self.user, rule_set_mode='shared')
        self.log = _seed_cache_rows(self.user)
        _seed_bucket_cache(self.user)

    def test_create_rule_clears_both_bucket_caches_keeps_payloads(self):
        self.client.login(username='alice', password='pw')
        response = self.client.post(reverse('rules'), data={
            'action': 'create',
            'status': ClassificationRule.STATUS_MALWARE,
            'match_type': ClassificationRule.MATCH_EXACT,
            'source_text': 'new-rule-line',
            'description': '',
        })
        self.assertEqual(response.status_code, 302)

        # In-memory bucket caches for the affected keys are flushed so the
        # next analysis runs with the new rule.
        self.assertNotIn('shared', _rule_buckets_cache)
        self.assertNotIn(f'private:{self.user.id}', _rule_buckets_cache)

        # Persistent analysis payloads survive — the analyzer page serves
        # them instantly while the fresh analysis runs in the background.
        remaining = set(
            UploadedLogAnalysis.objects.filter(upload=self.log)
            .values_list('rule_set_key', flat=True)
        )
        self.assertEqual(remaining, {'shared', f'private:{self.user.id}'})


class PrivateOwnerInvalidatesOnlyPrivateBucketTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = User.objects.create_user(username='bob', password='pw')
        UserProfile.objects.create(user=self.user, rule_set_mode='private')
        self.log = _seed_cache_rows(self.user)
        _seed_bucket_cache(self.user)

    def test_create_rule_clears_only_private_bucket_keeps_payloads(self):
        self.client.login(username='bob', password='pw')
        response = self.client.post(reverse('rules'), data={
            'action': 'create',
            'status': ClassificationRule.STATUS_MALWARE,
            'match_type': ClassificationRule.MATCH_EXACT,
            'source_text': 'private-line',
            'description': '',
        })
        self.assertEqual(response.status_code, 302)

        # 'shared' bucket cache is preserved (private user's rules don't
        # contribute to shared); 'private:bob' bucket cache is flushed.
        self.assertIn('shared', _rule_buckets_cache)
        self.assertNotIn(f'private:{self.user.id}', _rule_buckets_cache)

        # Both persistent payloads survive — neither gets deleted on rule edit.
        remaining = set(
            UploadedLogAnalysis.objects.filter(upload=self.log)
            .values_list('rule_set_key', flat=True)
        )
        self.assertEqual(remaining, {'shared', f'private:{self.user.id}'})
