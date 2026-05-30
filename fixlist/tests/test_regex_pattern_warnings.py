"""Tests for `evaluate_regex_pattern` and the regex_warnings surfaced by the
add-rule preview API. Locks in the behaviour that powers the slow-regex
warning in the rule adder UI."""
import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..analyzer import _re2, evaluate_regex_pattern, invalidate_rule_buckets_cache
from ..models import ClassificationRule


class EvaluateRegexPatternTests(TestCase):
    def test_simple_pattern_is_re2_ok_and_fast(self):
        if _re2 is None:
            self.skipTest('re2 binding not installed')
        result = evaluate_regex_pattern(r'\bdControl\b')
        self.assertTrue(result['re2_ok'])
        self.assertIsNone(result['re2_error'])
        self.assertTrue(result['stdlib_ok'])
        self.assertFalse(result['is_slow'])

    def test_lookahead_pattern_marks_re2_failure(self):
        if _re2 is None:
            self.skipTest('re2 binding not installed')
        result = evaluate_regex_pattern(r'(?=.*foo)(?=.*bar)')
        self.assertFalse(result['re2_ok'])
        self.assertIsNotNone(result['re2_error'])
        # stdlib re still accepts lookaheads, so the rule could still run —
        # just on the slow path.
        self.assertTrue(result['stdlib_ok'])

    def test_invalid_pattern_marks_stdlib_failure(self):
        result = evaluate_regex_pattern(r'(unclosed')
        self.assertFalse(result['stdlib_ok'])
        self.assertIsNotNone(result['stdlib_error'])


class TestRuleApiRegexWarningsTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = User.objects.create_user(username='ruler', password='pw')
        self.client.login(username='ruler', password='pw')
        self.url = reverse('test_rule_api')

    def _post(self, source_text, match_type=ClassificationRule.MATCH_REGEX):
        return self.client.post(
            self.url,
            data=json.dumps({
                'source_text': source_text,
                'match_type': match_type,
                'status': 'B',
                'lines': [],
            }),
            content_type='application/json',
        )

    def test_safe_regex_emits_no_warning(self):
        if _re2 is None:
            self.skipTest('re2 binding not installed')
        resp = self._post(r'\bdControl\b')
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertNotIn('regex_warnings', body)

    def test_lookahead_regex_emits_fallback_warning(self):
        if _re2 is None:
            self.skipTest('re2 binding not installed')
        resp = self._post(r'(?=.*foo)(?=.*bar)')
        self.assertEqual(resp.status_code, 200)
        warnings = resp.json().get('regex_warnings') or []
        self.assertEqual(len(warnings), 1)
        self.assertIn('fallback', warnings[0]['kinds'])
        self.assertEqual(warnings[0]['pattern'], r'(?=.*foo)(?=.*bar)')

    def test_invalid_regex_emits_invalid_warning(self):
        resp = self._post(r'(unclosed')
        self.assertEqual(resp.status_code, 200)
        warnings = resp.json().get('regex_warnings') or []
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]['kinds'], ['invalid'])
        self.assertIsNotNone(warnings[0]['stdlib_error'])

    def test_warnings_only_emitted_for_regex_match_type(self):
        # A pattern that would trigger a warning if treated as regex, but as
        # substring it is just literal text — no warning expected.
        resp = self._post(r'(?=.*foo)', match_type=ClassificationRule.MATCH_SUBSTRING)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn('regex_warnings', resp.json())
