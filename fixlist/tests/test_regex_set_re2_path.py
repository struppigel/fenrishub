"""Regression tests for the re2-backed regex set in the analyzer.

Background: the analyzer was written against the pyre2 API (lowercase
.add/.compile/.match, Set(options, anchor)). The package actually pinned
in requirements.txt is google-re2, which uses PascalCase methods and the
opposite constructor argument order. Calls into re2 silently raised
AttributeError/TypeError, were swallowed by `except Exception`, and every
regex rule was dumped into the stdlib `re` fallback bucket — leaving
production exposed to catastrophic backtracking. These tests guard against
that exact regression: a re2-eligible pattern MUST end up in the fast set,
not in the fallback bucket.
"""
from django.test import TestCase

from .. import analyzer
from ..analyzer import _load_rule_buckets, invalidate_rule_buckets_cache
from ..models import ClassificationRule


def _add_regex_rule(source_text):
    return ClassificationRule.objects.create(
        status=ClassificationRule.STATUS_MALWARE,
        match_type=ClassificationRule.MATCH_REGEX,
        source_text=source_text,
    )


class Re2FastSetPathTests(TestCase):
    """A re2-eligible pattern must land in the fast set, not in fallback."""

    def setUp(self):
        invalidate_rule_buckets_cache()
        if analyzer._re2 is None:
            self.skipTest('re2 binding not installed in this environment')

    def _fallback_texts(self, buckets):
        return {rule.source_text for rule, _ in buckets[ClassificationRule.MATCH_REGEX]}

    def _set_texts(self, buckets):
        return {rule.source_text for rule in buckets.get('__regex_set_rules') or []}

    def test_simple_pattern_lands_in_re2_set_not_fallback(self):
        """\\bdControl\\b is plain re2 syntax — must use the fast set."""
        _add_regex_rule(r'\bdControl\b')
        buckets = _load_rule_buckets('shared')

        self.assertIn(r'\bdControl\b', self._set_texts(buckets))
        self.assertNotIn(r'\bdControl\b', self._fallback_texts(buckets))
        self.assertIsNotNone(
            buckets.get('__regex_set'),
            'regex set must be built when there is at least one eligible rule',
        )

    def test_lookahead_pattern_falls_back_to_stdlib(self):
        """Patterns using lookahead are unsupported by re2 and must fall back."""
        lookahead_pattern = r'(?=.*foo)(?=.*bar)'
        _add_regex_rule(lookahead_pattern)
        buckets = _load_rule_buckets('shared')

        self.assertIn(lookahead_pattern, self._fallback_texts(buckets))
        self.assertNotIn(lookahead_pattern, self._set_texts(buckets))

    def test_mixed_rules_partition_correctly(self):
        """Mixed re2-eligible and lookahead rules must split between buckets."""
        _add_regex_rule(r'\bdControl\b')
        _add_regex_rule(r'powershell\.exe')
        _add_regex_rule(r'(?=.*lookahead)')

        buckets = _load_rule_buckets('shared')
        self.assertEqual(
            self._set_texts(buckets),
            {r'\bdControl\b', r'powershell\.exe'},
        )
        self.assertEqual(self._fallback_texts(buckets), {r'(?=.*lookahead)'})

    def test_regex_set_actually_matches_at_runtime(self):
        """Building the set isn't enough — Match() must return hits on real lines."""
        _add_regex_rule(r'\bdControl\b')
        _add_regex_rule(r'powershell\.exe')
        buckets = _load_rule_buckets('shared')

        regex_set = buckets.get('__regex_set')
        self.assertIsNotNone(regex_set)
        set_rules = buckets['__regex_set_rules']

        hits = regex_set.Match('cmd.exe powershell.exe -c whatever')
        matched_texts = {set_rules[idx].source_text for idx in hits}
        self.assertEqual(matched_texts, {r'powershell\.exe'})

        hits = regex_set.Match('mentions dControl in a sentence')
        matched_texts = {set_rules[idx].source_text for idx in hits}
        self.assertEqual(matched_texts, {r'\bdControl\b'})

        # google-re2's Set.Match returns None (not []) when nothing matched.
        # Whichever it is, it must be falsy so the analyzer's `for idx in ...
        # or ()` loop iterates zero times.
        hits = regex_set.Match('nothing relevant here')
        self.assertFalse(hits)


class AnalyzeLogTextNoMatchTests(TestCase):
    """Regression test for the production crash:
        TypeError: 'NoneType' object is not iterable
    at _collect_match_groups_for_line when google-re2's Set.Match returned
    None on a line that hit none of the re2 rules. Any analyze call where
    the regex set is built but a given line matches nothing must succeed."""

    def setUp(self):
        invalidate_rule_buckets_cache()
        if analyzer._re2 is None:
            self.skipTest('re2 binding not installed')

    def test_analyze_log_text_handles_line_with_no_re2_match(self):
        _add_regex_rule(r'\bsomething-that-never-occurs-anywhere\b')
        log_text = '\n'.join([
            'this line has nothing matching',
            'neither does this one',
            'or this one',
        ])
        result = analyzer.analyze_log_text(log_text, 'shared')
        self.assertEqual(len(result['analyzed_lines']), 3)
        for entry in result['analyzed_lines']:
            self.assertEqual(entry['dominant_status'], '?')
