"""Tests that assign/unassign actions trigger recalc with the new effective key."""
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..analyzer import invalidate_rule_buckets_cache
from ..models import (
    ClassificationRule,
    UploadedLog,
    UploadedLogAnalysis,
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


class AssignToPrivateUserRefreshesCountsTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        # alice is shared; bob is private. Each owns a distinct malware rule.
        self.alice = User.objects.create_user(username='alice', password='pw')
        UserProfile.objects.create(user=self.alice, rule_set_mode='shared')
        self.bob = User.objects.create_user(username='bob', password='pw')
        UserProfile.objects.create(user=self.bob, rule_set_mode='private')
        _add_rule(self.alice, 'shared-only-line')
        _add_rule(self.bob, 'private-only-line')

        self.log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content=LOG_CONTENT,
            log_type='FRST',
        )
        invalidate_rule_buckets_cache()
        self.log.recalculate_analysis_stats()
        # Unassigned => effective is shared => count_* matches shared analysis (1)
        self.log.refresh_from_db()
        self.assertEqual(self.log.count_malware, 1)

    def test_assign_to_private_user_updates_counts_to_private_view(self):
        self.client.login(username='bob', password='pw')
        self.client.post(reverse('uploaded_logs'), data={
            'action': 'assign_to_me',
            'upload_id': self.log.upload_id,
        })

        self.log.refresh_from_db()
        self.assertEqual(self.log.recipient_user_id, self.bob.id)
        # Effective is now private:bob => only bob's rule fires => count_malware == 1
        # (same number, but it's a different matched line — verify by inspecting cache)
        self.assertEqual(self.log.count_malware, 1)

        # Both shared and private:bob caches should exist after recalc
        keys = set(
            UploadedLogAnalysis.objects.filter(upload=self.log)
            .values_list('rule_set_key', flat=True)
        )
        self.assertIn('shared', keys)
        self.assertIn(f'private:{self.bob.id}', keys)

    def test_copy_to_me_refreshes_stats_for_new_recipient(self):
        # Source log assigned to bob (private). count_malware reflects private:bob.
        self.client.login(username='bob', password='pw')
        self.client.post(reverse('uploaded_logs'), data={
            'action': 'assign_to_me',
            'upload_id': self.log.upload_id,
        })
        self.log.refresh_from_db()
        self.assertEqual(self.log.recipient_user_id, self.bob.id)

        # alice (shared) copies the log to herself.
        self.client.logout()
        self.client.login(username='alice', password='pw')
        self.client.post(reverse('uploaded_logs'), data={
            'action': 'copy_to_me',
            'upload_id': self.log.upload_id,
        })

        copy = UploadedLog.objects.filter(recipient_user=self.alice).exclude(pk=self.log.pk).first()
        self.assertIsNotNone(copy)
        # Copy is assigned to alice (shared) => effective is shared => only the
        # 'shared' cache row exists (effective == shared, no second pass).
        keys = set(
            UploadedLogAnalysis.objects.filter(upload=copy)
            .values_list('rule_set_key', flat=True)
        )
        self.assertEqual(keys, {'shared'})
        # count_* on the copy reflects shared rules (alice's rule matches: 1)
        self.assertEqual(copy.count_malware, 1)

    def test_unassign_back_to_general_refreshes_cache(self):
        # First assign to bob
        self.client.login(username='bob', password='pw')
        self.client.post(reverse('uploaded_logs'), data={
            'action': 'assign_to_me',
            'upload_id': self.log.upload_id,
        })

        # Then unassign
        self.client.post(reverse('uploaded_logs'), data={
            'action': 'unassign_to_general',
            'upload_id': self.log.upload_id,
        })

        self.log.refresh_from_db()
        self.assertIsNone(self.log.recipient_user_id)
        # After unassign, effective is shared. count_* reflects shared.
        self.assertEqual(self.log.count_malware, 1)
