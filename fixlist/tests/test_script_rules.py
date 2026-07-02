"""Tests for the ``script`` classification rule type.

Safety note: never put an actual infinite loop / catastrophic snippet in a rule
inside these tests -- the suite runs as Railway's preDeployCommand and a hang would
block deploys. The timeout guard is exercised directly with a plain ``time.sleep``
callable instead.
"""

import json
import time

from django.contrib.auth.models import Group, User
from django.test import TestCase
from django.urls import reverse

from .. import script_matcher
from ..analyzer import analyze_log_text, inspect_line_matches, invalidate_rule_buckets_cache
from ..models import ClassificationRule
from .factories import make_rule, make_user


def _make_moderator(username="mod", password="password123"):
    user = User.objects.create_user(username=username, password=password)
    group, _ = Group.objects.get_or_create(name="moderator")
    user.groups.add(group)
    return user


class ScriptMatcherUnitTests(TestCase):
    """Direct unit tests of the sandbox helpers."""

    def test_basic_match_and_nomatch(self):
        code = script_matcher.compile_script('result = "evil" in line.lower()')
        self.assertEqual(script_matcher.run_script(code, "an EVIL line"), (True, None))
        self.assertEqual(script_matcher.run_script(code, "clean line"), (False, None))

    def test_match_string_contract(self):
        code = script_matcher.compile_script(
            'result = "MATCH" if line.startswith("R2") else "NOMATCH"'
        )
        self.assertEqual(script_matcher.run_script(code, "R2 svc")[0], True)
        self.assertEqual(script_matcher.run_script(code, "R1 svc")[0], False)
        # Case-insensitive on the MATCH token.
        code2 = script_matcher.compile_script('result = "match"')
        self.assertTrue(script_matcher.run_script(code2, "x")[0])

    def test_missing_result_is_nomatch(self):
        code = script_matcher.compile_script("x = 1")
        self.assertEqual(script_matcher.run_script(code, "x"), (False, None))

    def test_runtime_error_is_nomatch_with_message(self):
        code = script_matcher.compile_script("result = 1 / 0")
        matched, error = script_matcher.run_script(code, "x")
        self.assertFalse(matched)
        self.assertIn("ZeroDivisionError", error)

    def test_run_script_binds_custom_var_name(self):
        # Whole-log script rules read their input from `log`, not `line`.
        code = script_matcher.compile_script('result = "evil.exe" in log')
        self.assertEqual(
            script_matcher.run_script(code, "...\nevil.exe\n...", var_name="log"),
            (True, None),
        )
        # The default `line` variable is undefined when `log` is requested, so a
        # snippet reading `line` would fault (swallowed to a NOMATCH + error).
        line_code = script_matcher.compile_script('result = "evil.exe" in line')
        matched, error = script_matcher.run_script(line_code, "evil.exe", var_name="log")
        self.assertFalse(matched)
        self.assertIn("NameError", error)

    def test_evaluate_script_accepts_log_variable(self):
        evaluation = script_matcher.evaluate_script('result = "x" in log', var_name="log")
        self.assertTrue(evaluation["compile_ok"])
        self.assertIsNone(evaluation["runtime_error"])
        self.assertFalse(evaluation["is_slow"])

    def test_safe_helpers_available(self):
        code = script_matcher.compile_script(
            "result = any(c.isdigit() for c in line) and len(line) > 2"
        )
        self.assertTrue(script_matcher.run_script(code, "abc123")[0])
        self.assertFalse(script_matcher.run_script(code, "abc")[0])

    def test_regex_module_and_tuple_unpacking(self):
        # `re` is exposed and tuple unpacking / multi-line logic work.
        snippet = (
            'result = False\n'
            'm = re.search(r":\\\\Users\\\\([^\\\\]+)\\\\Local\\\\AppData\\\\([^\\\\]+)", line, re.IGNORECASE)\n'
            'if m:\n'
            '    username, last = m.group(1), m.group(2)\n'
            '    result = last.lower() == username.lower()[::-1]\n'
        )
        code = script_matcher.compile_script(snippet)
        self.assertTrue(script_matcher.run_script(code, r"C:\Users\Chris\Local\AppData\sirhC")[0])
        self.assertFalse(script_matcher.run_script(code, r"C:\Users\Chris\Local\AppData\other")[0])

    def test_augmented_assignment(self):
        code = script_matcher.compile_script(
            "n = 0\nfor c in line:\n    if c == 'a':\n        n += 1\nresult = n >= 2"
        )
        self.assertTrue(script_matcher.run_script(code, "banana")[0])
        self.assertFalse(script_matcher.run_script(code, "xyz")[0])

    # -- Sandbox rejections --

    def test_dunder_attribute_rejected_at_compile(self):
        with self.assertRaises(ValueError):
            script_matcher.compile_script("result = line.__class__")

    def test_empty_script_rejected(self):
        with self.assertRaises(ValueError):
            script_matcher.compile_script("   ")

    def test_import_blocked_at_runtime(self):
        evaluation = script_matcher.evaluate_script("import os\nresult = True")
        self.assertTrue(evaluation["compile_ok"])
        self.assertIsNotNone(evaluation["runtime_error"])
        self.assertIn("__import__", evaluation["runtime_error"])

    def test_open_blocked(self):
        evaluation = script_matcher.evaluate_script("result = open('x')")
        self.assertIsNotNone(evaluation["runtime_error"])

    def test_evaluate_accepts_good_script(self):
        evaluation = script_matcher.evaluate_script('result = "x" in line')
        self.assertTrue(evaluation["compile_ok"])
        self.assertIsNone(evaluation["runtime_error"])
        self.assertFalse(evaluation["is_slow"])

    # -- Timeout guard (no runaway loop enters the suite) --

    def test_run_with_timeout_returns_value(self):
        out = script_matcher._run_with_timeout(lambda: 42, timeout_ms=500)
        self.assertEqual(out, 42)

    def test_run_with_timeout_times_out(self):
        def _slow():
            time.sleep(0.5)
            return "done"

        out = script_matcher._run_with_timeout(_slow, timeout_ms=20)
        self.assertIs(out, script_matcher._TIMEOUT_SENTINEL)


class ScriptRuleAnalyzerTests(TestCase):
    """Script rules participate in line analysis like any other rule."""

    def setUp(self):
        invalidate_rule_buckets_cache()

    def test_script_rule_classifies_line(self):
        make_rule(
            'result = "evil" in line.lower()',
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_SCRIPT,
        )
        invalidate_rule_buckets_cache()

        hit = inspect_line_matches("this line is EVIL")
        self.assertEqual(hit["dominant_status"], ClassificationRule.STATUS_MALWARE)

        miss = inspect_line_matches("a perfectly clean line")
        self.assertEqual(miss["dominant_status"], "?")

    def test_uncompilable_script_rule_is_skipped(self):
        # A rule whose source no longer compiles must not break analysis.
        make_rule(
            "result = line.__class__",  # rejected by the sandbox
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_SCRIPT,
        )
        invalidate_rule_buckets_cache()
        # Should not raise and should simply not match.
        self.assertEqual(inspect_line_matches("anything")["dominant_status"], "?")


class ScriptRulePreviewApiTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.url = reverse("test_rule_api")

    def _post(self, payload):
        return self.client.post(self.url, json.dumps(payload), content_type="application/json")

    def test_non_moderator_cannot_preview_script(self):
        make_user()
        self.client.login(username="alice", password="password123")
        response = self._post({
            "source_text": 'result = "x" in line',
            "match_type": "script",
            "status": "B",
            "lines": ["x marks the spot"],
        })
        self.assertEqual(response.status_code, 403)

    def test_moderator_can_preview_script(self):
        _make_moderator()
        self.client.login(username="mod", password="password123")
        response = self._post({
            "source_text": 'result = "evil" in line.lower()',
            "match_type": "script",
            "status": "B",
            "lines": ["EVIL one", "clean two"],
        })
        self.assertEqual(response.status_code, 200)
        results = response.json()["results"]
        self.assertTrue(results[0]["matched"])
        self.assertFalse(results[1]["matched"])

    def test_moderator_preview_invalid_script_returns_400(self):
        _make_moderator()
        self.client.login(username="mod", password="password123")
        response = self._post({
            "source_text": "result = line.__class__",
            "match_type": "script",
            "status": "B",
            "lines": ["x"],
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    def test_whole_log_script_preview_binds_log_and_runs_once(self):
        _make_moderator()
        self.client.login(username="mod", password="password123")
        response = self._post({
            "source_text": 'result = "evil.exe" in log',
            "match_type": "script",
            "status": "A",
            "whole_log": True,
            "lines": ["clean line", "C:\\Temp\\evil.exe", "another"],
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["whole_log"])
        self.assertTrue(data["matched"])

    def test_line_script_preview_log_variable_is_undefined(self):
        # `log` is whole-log only; a per-line (non-whole-log) script referencing it
        # must not see the log -- it gets a swallowed NameError, never a match.
        _make_moderator()
        self.client.login(username="mod", password="password123")
        response = self._post({
            "source_text": 'result = "evil.exe" in log',
            "match_type": "script",
            "status": "B",
            "lines": ["C:\\Temp\\evil.exe"],
        })
        self.assertEqual(response.status_code, 200)
        results = response.json()["results"]
        self.assertFalse(results[0]["matched"])
        self.assertIn("NameError", results[0].get("script_error", ""))

    def test_whole_log_script_preview_line_variable_is_undefined(self):
        # `line` is per-line only; a whole-log script referencing it gets a
        # swallowed NameError (no match) rather than a stale per-line binding.
        _make_moderator()
        self.client.login(username="mod", password="password123")
        response = self._post({
            "source_text": 'result = "evil.exe" in line',
            "match_type": "script",
            "status": "A",
            "whole_log": True,
            "lines": ["C:\\Temp\\evil.exe"],
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["matched"])
        self.assertIn("NameError", data.get("script_error", ""))

    def test_whole_log_regex_preview_matches_across_lines(self):
        make_user()
        self.client.login(username="alice", password="password123")
        response = self._post({
            "source_text": r"ALPHA[\s\S]*OMEGA",
            "match_type": "regex",
            "status": "A",
            "whole_log": True,
            "lines": ["first ALPHA here", "noise", "then OMEGA here"],
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["whole_log"])
        self.assertTrue(data["matched"])
        self.assertTrue(data["match_ranges"])

    def test_whole_log_preview_rejects_unsupported_match_type(self):
        make_user()
        self.client.login(username="alice", password="password123")
        response = self._post({
            "source_text": "EXACT-LINE",
            "match_type": "exact",
            "status": "A",
            "whole_log": True,
            "lines": ["EXACT-LINE"],
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())


class ScriptRuleCreationTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()

    def test_non_moderator_cannot_create_script_rule(self):
        make_user()
        self.client.login(username="alice", password="password123")
        response = self.client.post(reverse("add_rule"), {
            "status": ClassificationRule.STATUS_MALWARE,
            "match_type": ClassificationRule.MATCH_SCRIPT,
            "source_text": 'result = "evil" in line',
        })
        self.assertEqual(response.status_code, 200)  # re-render with error message
        self.assertFalse(
            ClassificationRule.objects.filter(match_type=ClassificationRule.MATCH_SCRIPT).exists()
        )

    def test_non_moderator_does_not_see_script_option(self):
        make_user()
        self.client.login(username="alice", password="password123")
        response = self.client.get(reverse("add_rule"))
        self.assertNotContains(response, "Python script")

    def test_moderator_sees_script_option(self):
        _make_moderator()
        self.client.login(username="mod", password="password123")
        response = self.client.get(reverse("add_rule"))
        self.assertContains(response, "Python script")

    def test_moderator_creates_script_rule(self):
        mod = _make_moderator()
        self.client.login(username="mod", password="password123")
        response = self.client.post(reverse("add_rule"), {
            "status": ClassificationRule.STATUS_MALWARE,
            "match_type": ClassificationRule.MATCH_SCRIPT,
            "source_text": 'result = "evil" in line.lower()',
        })
        self.assertEqual(response.status_code, 302)
        rule = ClassificationRule.objects.get(match_type=ClassificationRule.MATCH_SCRIPT)
        self.assertEqual(rule.owner, mod)
        self.assertEqual(rule.priority, ClassificationRule.default_priority_for("script"))

    def test_multiline_script_is_one_rule(self):
        _make_moderator()
        self.client.login(username="mod", password="password123")
        snippet = 'lowered = line.lower()\nresult = "evil" in lowered or "bad" in lowered'
        response = self.client.post(reverse("add_rule"), {
            "status": ClassificationRule.STATUS_MALWARE,
            "match_type": ClassificationRule.MATCH_SCRIPT,
            "source_text": snippet,
        })
        self.assertEqual(response.status_code, 302)
        rules = ClassificationRule.objects.filter(match_type=ClassificationRule.MATCH_SCRIPT)
        self.assertEqual(rules.count(), 1)
        self.assertEqual(rules.first().source_text, snippet)

    def test_moderator_invalid_script_rejected(self):
        _make_moderator()
        self.client.login(username="mod", password="password123")
        response = self.client.post(reverse("add_rule"), {
            "status": ClassificationRule.STATUS_MALWARE,
            "match_type": ClassificationRule.MATCH_SCRIPT,
            "source_text": "result = line.__class__",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            ClassificationRule.objects.filter(match_type=ClassificationRule.MATCH_SCRIPT).exists()
        )


class WholeLogAlertRuleTests(TestCase):
    """Whole-log alert rules run once against the entire log, not per line."""

    LOG = "first line ALPHA marker\nmiddle noise line\nlast line OMEGA marker\n"

    def setUp(self):
        invalidate_rule_buckets_cache()

    def _alert_warnings(self, raw_log):
        result = analyze_log_text(raw_log)
        return [w for w in result["warnings"] if w.get("title") == "Alert rule matched"], result

    def test_whole_log_regex_alert_matches_across_lines(self):
        make_rule(
            r"ALPHA[\s\S]*OMEGA",  # spans multiple lines -- impossible per line
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_REGEX,
            description="Cross-line ALPHA/OMEGA pattern",
            whole_log=True,
        )
        invalidate_rule_buckets_cache()

        alert_warnings, result = self._alert_warnings(self.LOG)
        self.assertEqual(len(alert_warnings), 1)
        self.assertEqual(alert_warnings[0]["message"], "Cross-line ALPHA/OMEGA pattern")
        # The rule must NOT classify any individual line -- it runs once, log-wide.
        self.assertTrue(all(line["dominant_status"] == "?" for line in result["lines"]))

    def test_whole_log_script_alert_reads_log_variable(self):
        make_rule(
            'result = "evil.exe" in log',
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_SCRIPT,
            description="Found evil.exe somewhere in the log",
            whole_log=True,
        )
        invalidate_rule_buckets_cache()

        alert_warnings, result = self._alert_warnings("clean line\nC:\\Temp\\evil.exe\nanother\n")
        self.assertEqual(len(alert_warnings), 1)
        self.assertEqual(alert_warnings[0]["message"], "Found evil.exe somewhere in the log")
        self.assertTrue(all(line["dominant_status"] == "?" for line in result["lines"]))

    def test_whole_log_rule_does_not_fire_without_match(self):
        make_rule(
            r"ALPHA[\s\S]*OMEGA",
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_REGEX,
            description="Cross-line ALPHA/OMEGA pattern",
            whole_log=True,
        )
        invalidate_rule_buckets_cache()

        alert_warnings, _ = self._alert_warnings("only ALPHA here, no second marker\n")
        self.assertEqual(alert_warnings, [])

    def test_whole_log_rule_message_falls_back_to_source_text(self):
        make_rule(
            "OMEGA",
            status=ClassificationRule.STATUS_ALERT,
            match_type=ClassificationRule.MATCH_REGEX,
            description="",
            whole_log=True,
        )
        invalidate_rule_buckets_cache()

        alert_warnings, _ = self._alert_warnings(self.LOG)
        self.assertEqual(len(alert_warnings), 1)
        self.assertEqual(alert_warnings[0]["message"], "OMEGA")


class WholeLogRuleCreationTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()

    def test_moderator_creates_whole_log_script_alert(self):
        _make_moderator()
        self.client.login(username="mod", password="password123")
        response = self.client.post(reverse("add_rule"), {
            "status": ClassificationRule.STATUS_ALERT,
            "match_type": ClassificationRule.MATCH_SCRIPT,
            "source_text": 'result = "evil.exe" in log',
            "whole_log": "on",
        })
        self.assertEqual(response.status_code, 302)
        rule = ClassificationRule.objects.get(match_type=ClassificationRule.MATCH_SCRIPT)
        self.assertTrue(rule.whole_log)

    def test_whole_log_regex_alert_created_by_regular_user(self):
        make_user()
        self.client.login(username="alice", password="password123")
        response = self.client.post(reverse("add_rule"), {
            "status": ClassificationRule.STATUS_ALERT,
            "match_type": ClassificationRule.MATCH_REGEX,
            "source_text": r"ALPHA[\s\S]*OMEGA",
            "whole_log": "on",
        })
        self.assertEqual(response.status_code, 302)
        rule = ClassificationRule.objects.get(match_type=ClassificationRule.MATCH_REGEX)
        self.assertTrue(rule.whole_log)

    def test_whole_log_rejected_for_non_alert_status(self):
        make_user()
        self.client.login(username="alice", password="password123")
        response = self.client.post(reverse("add_rule"), {
            "status": ClassificationRule.STATUS_MALWARE,
            "match_type": ClassificationRule.MATCH_REGEX,
            "source_text": "OMEGA",
            "whole_log": "on",
        })
        self.assertEqual(response.status_code, 200)  # re-render with error
        self.assertFalse(ClassificationRule.objects.filter(whole_log=True).exists())

    def test_whole_log_rejected_for_non_regex_or_script_match_type(self):
        make_user()
        self.client.login(username="alice", password="password123")
        response = self.client.post(reverse("add_rule"), {
            "status": ClassificationRule.STATUS_ALERT,
            "match_type": ClassificationRule.MATCH_EXACT,
            "source_text": "EXACT-LINE",
            "whole_log": "on",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(ClassificationRule.objects.filter(whole_log=True).exists())
