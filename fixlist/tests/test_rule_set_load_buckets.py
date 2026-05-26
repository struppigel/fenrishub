"""Tests for `_load_rule_buckets` filtering by rule_set_key."""
from django.contrib.auth.models import User
from django.test import TestCase

from ..analyzer import _load_rule_buckets, invalidate_rule_buckets_cache
from ..models import ClassificationRule, UserProfile


def _add_rule(owner, source_text):
    return ClassificationRule.objects.create(
        owner=owner,
        status=ClassificationRule.STATUS_MALWARE,
        match_type=ClassificationRule.MATCH_EXACT,
        source_text=source_text,
    )


class LoadRuleBucketsPerSetTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.shared_user = User.objects.create_user(username='shared_user', password='pw')
        UserProfile.objects.create(user=self.shared_user, rule_set_mode='shared')
        self.private_user = User.objects.create_user(username='private_user', password='pw')
        UserProfile.objects.create(user=self.private_user, rule_set_mode='private')
        self.no_profile_user = User.objects.create_user(username='no_profile_user', password='pw')

        self.r_shared = _add_rule(self.shared_user, 'shared-line')
        self.r_private = _add_rule(self.private_user, 'private-line')
        self.r_no_profile = _add_rule(self.no_profile_user, 'no-profile-line')

    def _exact_texts(self, buckets):
        return {rule.source_text for rule in buckets[ClassificationRule.MATCH_EXACT]}

    def test_shared_key_includes_shared_and_no_profile_excludes_private(self):
        buckets = _load_rule_buckets('shared')
        texts = self._exact_texts(buckets)
        self.assertIn('shared-line', texts)
        self.assertIn('no-profile-line', texts)
        self.assertNotIn('private-line', texts)

    def test_private_key_includes_only_that_users_rules(self):
        buckets = _load_rule_buckets(f'private:{self.private_user.id}')
        texts = self._exact_texts(buckets)
        self.assertEqual(texts, {'private-line'})

    def test_private_key_for_shared_user_returns_only_their_rules(self):
        buckets = _load_rule_buckets(f'private:{self.shared_user.id}')
        texts = self._exact_texts(buckets)
        self.assertEqual(texts, {'shared-line'})

    def test_disabled_rules_excluded_from_all_keys(self):
        self.r_shared.is_enabled = False
        self.r_shared.save(update_fields=['is_enabled'])
        invalidate_rule_buckets_cache()
        buckets = _load_rule_buckets('shared')
        self.assertNotIn('shared-line', self._exact_texts(buckets))


class PerKeyCacheTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.alice = User.objects.create_user(username='alice', password='pw')
        UserProfile.objects.create(user=self.alice, rule_set_mode='shared')
        self.bob = User.objects.create_user(username='bob', password='pw')
        UserProfile.objects.create(user=self.bob, rule_set_mode='private')
        _add_rule(self.alice, 'alice-line')
        _add_rule(self.bob, 'bob-line')

    def test_invalidate_one_key_does_not_drop_other(self):
        from ..analyzer import _get_cached_rule_buckets, _rule_buckets_cache

        _get_cached_rule_buckets('shared')
        _get_cached_rule_buckets(f'private:{self.bob.id}')
        self.assertIn('shared', _rule_buckets_cache)
        self.assertIn(f'private:{self.bob.id}', _rule_buckets_cache)

        invalidate_rule_buckets_cache('shared')
        self.assertNotIn('shared', _rule_buckets_cache)
        self.assertIn(f'private:{self.bob.id}', _rule_buckets_cache)

    def test_invalidate_all_drops_every_key(self):
        from ..analyzer import _get_cached_rule_buckets, _rule_buckets_cache

        _get_cached_rule_buckets('shared')
        _get_cached_rule_buckets(f'private:{self.bob.id}')

        invalidate_rule_buckets_cache(None)
        self.assertEqual(_rule_buckets_cache, {})
