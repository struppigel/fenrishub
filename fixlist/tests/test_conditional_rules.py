"""Rules with conditions on facts: they apply only where every condition
holds (require / forbid a fact in the line's block, section, or the log).
Facts come only from rules without conditions, so conditions never depend on
each other."""

from ..analyzer import analyze_log_text, inspect_line_matches, invalidate_rule_buckets_cache
from ..fact_service import ConditionSpec, condition_key_for, set_rule_conditions
from ..models import ClassificationRule, Fact, FactRule, FactTagSource, RuleCondition, RuleTag
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

B = ClassificationRule.STATUS_MALWARE
C = ClassificationRule.STATUS_CLEAN
W = ClassificationRule.STATUS_WARNING
A = ClassificationRule.STATUS_ALERT
S = ClassificationRule.STATUS_SECURITY

REQUIRE, FORBID = RuleCondition.POLARITY_REQUIRE, RuleCondition.POLARITY_FORBID
BLOCK, SECTION, LOG = RuleCondition.SCOPE_BLOCK, RuleCondition.SCOPE_SECTION, RuleCondition.SCOPE_LOG

KASPERSKY_LOG = "\n".join([
    "AVP: Kaspersky Anti-Virus service",
    "R1 klif; C:\\Windows\\System32\\drivers\\klif.sys [1 2026-01-01] (Kaspersky)",
])
PLAIN_LOG = "R1 klif; C:\\Windows\\System32\\drivers\\klif.sys [1 2026-01-01] (Kaspersky)"

SPOR_LOG = "\n".join([
    "==================== PERSISTENCE - autostarts ====================",
    "2026-11-20 08:14:02 [task] \\Microsoft\\Windows\\UpdateCheck <==== !hidden-task",
    "    program: C:\\Users\\anna\\AppData\\Roaming\\svc\\run.exe [unsigned]",
    "2026-11-20 08:15:02 [task] \\Microsoft\\Windows\\Defrag",
    "    program: C:\\Windows\\System32\\defrag.exe",
])

SECTIONS_LOG = "\n".join([
    "==================== Processes (Whitelisted) =================",
    "marker: here",
    "target line",
    "==================== Services (Whitelisted) =================",
    "target line two",
])


class ConditionalRuleTests(LogAnalyzerApiBaseTestCase):
    def setUp(self):
        super().setUp()
        self.fact = Fact.objects.create(name="Kaspersky installed")

    def _rule(self, source_text, status=B, match_type=ClassificationRule.MATCH_SUBSTRING, **overrides):
        return ClassificationRule.objects.create(
            owner=self.user, status=status, match_type=match_type, source_text=source_text, **overrides,
        )

    def _conditional(self, source_text, status, conditions, **overrides):
        specs = [ConditionSpec(*condition) for condition in conditions]
        rule = self._rule(source_text, status=status, condition_key=condition_key_for(specs), **overrides)
        set_rule_conditions(rule, specs)
        return rule

    def _fact_rule(self, source_text, fact=None, match_type=FactRule.MATCH_SUBSTRING, **overrides):
        return FactRule.objects.create(
            owner=self.user, fact=fact or self.fact, match_type=match_type,
            source_text=source_text, **overrides,
        )

    def _line(self, payload, needle):
        return next(line for line in payload["lines"] if needle in line["line"])

    # -- log scope --

    def test_require_in_log(self):
        self._fact_rule("AVP:")
        self._rule("klif.sys", status=W)
        rule = self._conditional("klif.sys", C, [(self.fact.pk, REQUIRE, LOG)])

        line = self._line(analyze_log_text(KASPERSKY_LOG), "klif.sys")
        self.assertEqual(line["dominant_status"], C)
        self.assertEqual(line["rule_ids"], [rule.pk])
        self.assertTrue(any('requires "Kaspersky installed" in the log (L1)' in reason for reason in line["reasons"]))

        line = self._line(analyze_log_text(PLAIN_LOG), "klif.sys")
        self.assertEqual(line["dominant_status"], W)

    def test_forbid_in_log(self):
        self._fact_rule("AVP:")
        self._conditional("klif.sys", B, [(self.fact.pk, FORBID, LOG)])
        self.assertEqual(self._line(analyze_log_text(KASPERSKY_LOG), "klif.sys")["dominant_status"], "?")
        line = self._line(analyze_log_text(PLAIN_LOG), "klif.sys")
        self.assertEqual(line["dominant_status"], B)
        self.assertTrue(any('forbids "Kaspersky installed" in the log (not found)' in r for r in line["reasons"]))

    def test_all_conditions_must_hold(self):
        other = Fact.objects.create(name="other")
        self._fact_rule("AVP:")
        self._conditional("klif.sys", B, [(self.fact.pk, REQUIRE, LOG), (other.pk, REQUIRE, LOG)])
        self.assertEqual(self._line(analyze_log_text(KASPERSKY_LOG), "klif.sys")["dominant_status"], "?")

    def test_or_through_two_rules_with_the_same_pattern(self):
        leftovers = Fact.objects.create(name="Kaspersky leftovers")
        self._fact_rule("AVP:", fact=leftovers)
        self._conditional("klif.sys", C, [(self.fact.pk, REQUIRE, LOG)])
        second = self._conditional("klif.sys", C, [(leftovers.pk, REQUIRE, LOG)])
        line = self._line(analyze_log_text(KASPERSKY_LOG), "klif.sys")
        self.assertEqual(line["dominant_status"], C)
        self.assertEqual(line["rule_ids"], [second.pk])

    def test_whole_log_fact_satisfies_a_log_condition(self):
        self._fact_rule(r"AVP:.*\n.*klif", match_type=FactRule.MATCH_REGEX, whole_log=True)
        self._conditional("klif.sys", C, [(self.fact.pk, REQUIRE, LOG)])
        line = self._line(analyze_log_text(KASPERSKY_LOG), "klif.sys")
        self.assertEqual(line["dominant_status"], C)
        self.assertTrue(any("(the whole log)" in reason for reason in line["reasons"]))

    def test_same_default_priority_and_status_precedence(self):
        # Same priority: the stronger status wins, conditions or not.
        self._fact_rule("AVP:")
        self._rule("klif.sys", status=B)
        self._conditional("klif.sys", C, [(self.fact.pk, REQUIRE, LOG)])
        line = self._line(analyze_log_text(KASPERSKY_LOG), "klif.sys")
        self.assertEqual(line["dominant_status"], B)
        self.assertEqual(line["status_codes"], "BC")

    def test_a_raised_priority_overrides(self):
        self._fact_rule("AVP:")
        self._rule("klif.sys", status=B)
        self._conditional("klif.sys", C, [(self.fact.pk, REQUIRE, LOG)], priority=8)
        self.assertEqual(self._line(analyze_log_text(KASPERSKY_LOG), "klif.sys")["dominant_status"], C)

    def test_conditional_match_paints_the_line(self):
        self._fact_rule("AVP:")
        self._conditional("klif.sys", C, [(self.fact.pk, REQUIRE, LOG)])
        line = self._line(analyze_log_text(KASPERSKY_LOG), "klif.sys")
        self.assertTrue(any(span["status"] == C for span in line["highlights"]))

    # -- block and section scope --

    def test_require_in_block_on_a_spor_item(self):
        roaming = Fact.objects.create(name="runs from Roaming")
        self._fact_rule("\\AppData\\Roaming\\", fact=roaming, all_log_types=True)
        self._conditional("[task]", B, [(roaming.pk, REQUIRE, BLOCK)], all_log_types=True)
        payload = analyze_log_text(SPOR_LOG, log_type="Spor")
        self.assertEqual(self._line(payload, "UpdateCheck")["dominant_status"], B)
        self.assertEqual(self._line(payload, "Defrag")["dominant_status"], "?")
        self.assertTrue(any("in its block (L3)" in r for r in self._line(payload, "UpdateCheck")["reasons"]))

    def test_block_scope_does_not_group_indented_lines_of_other_logs(self):
        roaming = Fact.objects.create(name="runs from Roaming")
        self._fact_rule("\\AppData\\Roaming\\", fact=roaming, all_log_types=True)
        self._conditional("[task]", B, [(roaming.pk, REQUIRE, BLOCK)], all_log_types=True)
        payload = analyze_log_text(SPOR_LOG, log_type="FRST")
        self.assertEqual(self._line(payload, "UpdateCheck")["dominant_status"], "?")

    def test_section_scope(self):
        marker = Fact.objects.create(name="marker")
        self._fact_rule("marker: here", fact=marker, all_log_types=True)
        self._conditional("target line", B, [(marker.pk, REQUIRE, SECTION)], all_log_types=True)
        payload = analyze_log_text(SECTIONS_LOG)
        self.assertEqual(self._line(payload, "target line")["dominant_status"], B)
        self.assertEqual(self._line(payload, "target line two")["dominant_status"], "?")

    def test_forbid_in_section(self):
        marker = Fact.objects.create(name="marker")
        self._fact_rule("marker: here", fact=marker, all_log_types=True)
        self._conditional("target line", B, [(marker.pk, FORBID, SECTION)], all_log_types=True)
        payload = analyze_log_text(SECTIONS_LOG)
        self.assertEqual(self._line(payload, "target line")["dominant_status"], "?")
        self.assertEqual(self._line(payload, "target line two")["dominant_status"], B)

    # -- stratification --

    def test_conditional_rules_never_feed_facts(self):
        tag = RuleTag.objects.create(name="Kaspersky")
        FactTagSource.objects.create(fact=self.fact, tag=tag)
        rule = self._conditional("klif.sys", S, [(self.fact.pk, FORBID, LOG)])
        rule.tags.add(tag)
        invalidate_rule_buckets_cache()
        payload = analyze_log_text(PLAIN_LOG)
        # The rule applied (the fact is absent) but its tag did not make the fact.
        self.assertEqual(self._line(payload, "klif.sys")["dominant_status"], S)
        self.assertNotIn("facts", payload)

    # -- whole-log alert rules --

    def test_conditional_whole_log_alert(self):
        self._fact_rule("AVP:")
        rule = self._conditional(
            "klif", A, [(self.fact.pk, REQUIRE, LOG)],
            match_type=ClassificationRule.MATCH_REGEX, whole_log=True, description="Kaspersky driver",
        )
        payload = analyze_log_text(KASPERSKY_LOG)
        self.assertIn(rule.pk, payload["wholelog_rule_ids"])
        self.assertTrue(any(w["message"] == "Kaspersky driver" for w in payload["warnings"]))
        payload = analyze_log_text(PLAIN_LOG)
        self.assertNotIn(rule.pk, payload["wholelog_rule_ids"])

    # -- single-line tools see the rules without conditions only --

    def test_inspect_line_matches_ignores_conditional_rules(self):
        self._conditional("klif.sys", C, [(self.fact.pk, FORBID, LOG)])
        result = inspect_line_matches(PLAIN_LOG)
        self.assertEqual(result["matches"], [])
        self.assertEqual(result["dominant_status"], "?")
