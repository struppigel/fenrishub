"""Tests for the rule set scoping helpers in fixlist/rule_sets.py."""
from django.contrib.auth.models import User
from django.test import TestCase

from ..models import UploadedLog, UserProfile
from ..rule_sets import (
    SHARED_RULE_SET_KEY,
    keys_affected_by_owner,
    parse_rule_set_key,
    resolve_effective_rule_set_key,
    resolve_user_rule_set_key,
)


class ResolveUserRuleSetKeyTests(TestCase):
    def test_none_user_resolves_to_shared(self):
        self.assertEqual(resolve_user_rule_set_key(None), SHARED_RULE_SET_KEY)

    def test_unauthenticated_user_resolves_to_shared(self):
        class Anon:
            is_authenticated = False
        self.assertEqual(resolve_user_rule_set_key(Anon()), SHARED_RULE_SET_KEY)

    def test_user_without_profile_resolves_to_shared(self):
        user = User.objects.create_user(username='no_profile', password='pw')
        self.assertEqual(resolve_user_rule_set_key(user), SHARED_RULE_SET_KEY)

    def test_user_with_shared_profile_resolves_to_shared(self):
        user = User.objects.create_user(username='shared_user', password='pw')
        UserProfile.objects.create(user=user, rule_set_mode='shared')
        self.assertEqual(resolve_user_rule_set_key(user), SHARED_RULE_SET_KEY)

    def test_user_with_private_profile_resolves_to_private(self):
        user = User.objects.create_user(username='private_user', password='pw')
        UserProfile.objects.create(user=user, rule_set_mode='private')
        self.assertEqual(resolve_user_rule_set_key(user), f'private:{user.id}')


class ResolveEffectiveRuleSetKeyTests(TestCase):
    def test_unassigned_log_resolves_to_shared(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content='line',
        )
        self.assertEqual(resolve_effective_rule_set_key(log), SHARED_RULE_SET_KEY)

    def test_log_assigned_to_shared_user_resolves_to_shared(self):
        user = User.objects.create_user(username='shared_user', password='pw')
        UserProfile.objects.create(user=user, rule_set_mode='shared')
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content='line',
            recipient_user=user,
        )
        self.assertEqual(resolve_effective_rule_set_key(log), SHARED_RULE_SET_KEY)

    def test_log_assigned_to_private_user_resolves_to_private(self):
        user = User.objects.create_user(username='private_user', password='pw')
        UserProfile.objects.create(user=user, rule_set_mode='private')
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content='line',
            recipient_user=user,
        )
        self.assertEqual(resolve_effective_rule_set_key(log), f'private:{user.id}')


class ParseRuleSetKeyTests(TestCase):
    def test_shared(self):
        self.assertEqual(parse_rule_set_key('shared'), ('shared', None))

    def test_empty_falls_back_to_shared(self):
        self.assertEqual(parse_rule_set_key(''), ('shared', None))
        self.assertEqual(parse_rule_set_key(None), ('shared', None))

    def test_private(self):
        self.assertEqual(parse_rule_set_key('private:42'), ('private', 42))

    def test_invalid_private_falls_back_to_shared(self):
        self.assertEqual(parse_rule_set_key('private:abc'), ('shared', None))

    def test_unknown_prefix_falls_back_to_shared(self):
        self.assertEqual(parse_rule_set_key('weird:42'), ('shared', None))


class KeysAffectedByOwnerTests(TestCase):
    def test_shared_owner_affects_shared_and_private(self):
        owner = User.objects.create_user(username='shared_owner', password='pw')
        UserProfile.objects.create(user=owner, rule_set_mode='shared')
        keys = set(keys_affected_by_owner(owner))
        self.assertEqual(keys, {SHARED_RULE_SET_KEY, f'private:{owner.id}'})

    def test_private_owner_affects_only_private(self):
        owner = User.objects.create_user(username='private_owner', password='pw')
        UserProfile.objects.create(user=owner, rule_set_mode='private')
        keys = set(keys_affected_by_owner(owner))
        self.assertEqual(keys, {f'private:{owner.id}'})

    def test_owner_without_profile_affects_shared_and_private(self):
        owner = User.objects.create_user(username='no_profile_owner', password='pw')
        keys = set(keys_affected_by_owner(owner))
        self.assertEqual(keys, {SHARED_RULE_SET_KEY, f'private:{owner.id}'})
