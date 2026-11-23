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

        # Entries are keyed (rule set, log type); these tests care about the rule set.
        def cached_sets():
            return {key[0] for key in _rule_buckets_cache}

        _get_cached_rule_buckets('shared')
        _get_cached_rule_buckets(f'private:{self.bob.id}')
        self.assertIn('shared', cached_sets())
        self.assertIn(f'private:{self.bob.id}', cached_sets())

        invalidate_rule_buckets_cache('shared')
        self.assertNotIn('shared', cached_sets())
        self.assertIn(f'private:{self.bob.id}', cached_sets())

    def test_invalidate_all_drops_every_key(self):
        from ..analyzer import _get_cached_rule_buckets, _rule_buckets_cache

        _get_cached_rule_buckets('shared')
        _get_cached_rule_buckets(f'private:{self.bob.id}')

        invalidate_rule_buckets_cache(None)
        self.assertEqual(_rule_buckets_cache, {})


class LineLookupIndexTests(TestCase):
    """Exact, substring and file path rules are matched through indexes
    (_index_line_lookups, __filepath_index) with the results the plain loops gave."""

    LINE = r'Task: {X} C:\Program Files (x86)\a+b\tool.exe [unsigned] => .*'

    def setUp(self):
        invalidate_rule_buckets_cache()
        self.owner = User.objects.create_user(username='owner', password='pw')

    def _rule(self, match_type, source_text, **extra):
        return ClassificationRule.objects.create(
            owner=self.owner, status=ClassificationRule.STATUS_MALWARE,
            match_type=match_type, source_text=source_text, **extra,
        )

    def _groups(self, line=LINE):
        from ..analyzer import _collect_match_groups_for_line
        return _collect_match_groups_for_line(line, _load_rule_buckets('shared'))

    def test_substrings_are_literal_and_keep_rule_order(self):
        # Regex metacharacters are plain text in a substring rule.
        later = self._rule(ClassificationRule.MATCH_SUBSTRING, '=> .*')
        first = self._rule(ClassificationRule.MATCH_SUBSTRING, r'(x86)\a+b')
        self._rule(ClassificationRule.MATCH_SUBSTRING, 'a+b\nope')
        self._rule(ClassificationRule.MATCH_SUBSTRING, 'x86)\A+B')    # case-sensitive
        expected = sorted([later, first], key=lambda rule: rule.pk)
        buckets = _load_rule_buckets('shared')
        # Bucket order is the queryset's; the matches must follow it.
        order = [rule for rule in buckets[ClassificationRule.MATCH_SUBSTRING] if rule in expected]
        self.assertEqual([rule for rule, _reason, _m in self._groups()['substring']], order)
        self.assertEqual(sorted(order, key=lambda rule: rule.pk), expected)

    def test_substrings_without_re2(self):
        from .. import regex_engine
        from unittest import mock
        hit = self._rule(ClassificationRule.MATCH_SUBSTRING, r'(x86)\a+b')
        self._rule(ClassificationRule.MATCH_SUBSTRING, 'not in the line')
        with mock.patch.object(regex_engine, '_re2', None):
            buckets = _load_rule_buckets('shared')
            self.assertIsNone(buckets['__substring_set'])
            groups = self._groups()
        self.assertEqual([rule for rule, _reason, _m in groups['substring']], [hit])

    def test_exact_rules_match_stripped_text(self):
        one = self._rule(ClassificationRule.MATCH_EXACT, '  ' + self.LINE + ' ')
        two = self._rule(ClassificationRule.MATCH_EXACT, self.LINE)
        self._rule(ClassificationRule.MATCH_EXACT, self.LINE[:-1])
        self.assertEqual({rule for rule, _reason, _m in self._groups()['exact']}, {one, two})

    def test_filepath_rule_matches_through_index(self):
        path = r'C:\Program Files (x86)\a+b\tool.exe'
        rule = self._rule(ClassificationRule.MATCH_FILEPATH, path, filepath=path, normalized_filepath=path.lower())
        self._rule(ClassificationRule.MATCH_FILEPATH, r'C:\other.exe', filepath=r'C:\other.exe',
                   normalized_filepath=r'c:\other.exe')
        buckets = _load_rule_buckets('shared')
        self.assertIn(path.lower(), buckets['__filepath_index'])
        self.assertEqual([r for r, _reason, _m in self._groups(path)['filepath']], [rule])
