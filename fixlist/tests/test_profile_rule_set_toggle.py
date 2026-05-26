"""Tests for profile rule_set_mode toggle + invalidation behavior."""
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


class ProfileToggleInvalidationTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = User.objects.create_user(username='alice', password='pw')
        self.profile, _ = UserProfile.objects.get_or_create(
            user=self.user, defaults={'rule_set_mode': 'shared'},
        )
        _add_rule(self.user, 'malware-line')

        # Seed cached analyses for shared + private:user.id
        self.log = UploadedLog.objects.create(
            forum_username='forum_user',
            original_filename='frst.txt',
            content='Scan result of Farbar Recovery Scan Tool\nmalware-line',
            log_type='FRST',
        )
        UploadedLogAnalysis.objects.create(
            upload=self.log,
            rule_set_key='shared',
            payload={'summary': {}, 'lines': [], 'warnings': []},
            source_content_hash=self.log.content_hash,
        )
        UploadedLogAnalysis.objects.create(
            upload=self.log,
            rule_set_key=f'private:{self.user.id}',
            payload={'summary': {}, 'lines': [], 'warnings': []},
            source_content_hash=self.log.content_hash,
        )

    def test_toggle_to_private_deletes_affected_cache_rows(self):
        self.client.login(username='alice', password='pw')
        response = self.client.post(reverse('profile'), data={
            'frst_fix_message': '',
            'analyzer_fixlist_template': '',
            'rule_set_mode': 'private',
        })
        self.assertEqual(response.status_code, 302)

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.rule_set_mode, 'private')
        # Both 'shared' and 'private:N' caches deleted
        self.assertEqual(
            UploadedLogAnalysis.objects.filter(upload=self.log).count(),
            0,
        )

    def test_no_toggle_keeps_cache_rows(self):
        self.client.login(username='alice', password='pw')
        # Submit same mode value — should NOT invalidate
        response = self.client.post(reverse('profile'), data={
            'frst_fix_message': '',
            'analyzer_fixlist_template': '',
            'rule_set_mode': 'shared',
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            UploadedLogAnalysis.objects.filter(upload=self.log).count(),
            2,
        )

    def test_invalid_value_falls_back_to_shared(self):
        self.client.login(username='alice', password='pw')
        self.profile.rule_set_mode = 'private'
        self.profile.save()

        response = self.client.post(reverse('profile'), data={
            'frst_fix_message': '',
            'analyzer_fixlist_template': '',
            'rule_set_mode': 'garbage_value',
        })
        self.assertEqual(response.status_code, 302)

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.rule_set_mode, 'shared')

    def test_count_star_not_modified_by_toggle(self):
        """Lazy invalidation — count_* on the upload is NOT touched on toggle."""
        self.log.count_malware = 42
        self.log.save(update_fields=['count_malware'])

        self.client.login(username='alice', password='pw')
        self.client.post(reverse('profile'), data={
            'frst_fix_message': '',
            'analyzer_fixlist_template': '',
            'rule_set_mode': 'private',
        })

        self.log.refresh_from_db()
        self.assertEqual(self.log.count_malware, 42)
