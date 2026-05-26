"""Tests that rule CRUD invalidates only the affected rule-set keys."""
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..analyzer import invalidate_rule_buckets_cache, _rule_buckets_cache
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


class SharedOwnerInvalidatesBothKeysTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = User.objects.create_user(username='alice', password='pw')
        UserProfile.objects.create(user=self.user, rule_set_mode='shared')
        self.log = _seed_cache_rows(self.user)

    def test_create_rule_invalidates_shared_and_private_caches(self):
        self.client.login(username='alice', password='pw')
        response = self.client.post(reverse('rules'), data={
            'action': 'create',
            'status': ClassificationRule.STATUS_MALWARE,
            'match_type': ClassificationRule.MATCH_EXACT,
            'source_text': 'new-rule-line',
            'description': '',
        })
        self.assertEqual(response.status_code, 302)

        remaining = UploadedLogAnalysis.objects.filter(upload=self.log)
        self.assertEqual(remaining.count(), 0)


class PrivateOwnerInvalidatesOnlyPrivateKeyTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = User.objects.create_user(username='bob', password='pw')
        UserProfile.objects.create(user=self.user, rule_set_mode='private')
        self.log = _seed_cache_rows(self.user)

    def test_create_rule_only_invalidates_private_key(self):
        self.client.login(username='bob', password='pw')
        response = self.client.post(reverse('rules'), data={
            'action': 'create',
            'status': ClassificationRule.STATUS_MALWARE,
            'match_type': ClassificationRule.MATCH_EXACT,
            'source_text': 'private-line',
            'description': '',
        })
        self.assertEqual(response.status_code, 302)

        # 'shared' cache is preserved (private user's rules don't affect it);
        # 'private:bob' cache is deleted.
        keys = set(
            UploadedLogAnalysis.objects.filter(upload=self.log)
            .values_list('rule_set_key', flat=True)
        )
        self.assertIn('shared', keys)
        self.assertNotIn(f'private:{self.user.id}', keys)
