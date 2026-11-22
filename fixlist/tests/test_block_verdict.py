"""A rule whose verdict applies to its whole block (advanced option): where it
decides a line, the other lines of that line's block get its match too."""

from django.urls import reverse

from ..analyzer import analyze_log_text
from ..fact_service import ConditionSpec, condition_key_for, set_rule_conditions
from ..models import ClassificationRule, Fact, FactRule, RuleCondition
from ..views.rules import create_rules
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

B = ClassificationRule.STATUS_MALWARE
C = ClassificationRule.STATUS_CLEAN

SPOR_LOG = "\n".join([
    "==================== PERSISTENCE - autostarts ====================",
    "2026-11-20 08:14:02 [task] \\Microsoft\\Windows\\UpdateCheck <==== !hidden-task",
    "    program: C:\\Users\\anna\\AppData\\Roaming\\svc\\run.exe [unsigned]",
    "    arguments: --silent",
    "2026-11-20 08:15:02 [task] \\Microsoft\\Windows\\Defrag",
    "    program: C:\\Windows\\System32\\defrag.exe",
])


class BlockVerdictTests(LogAnalyzerApiBaseTestCase):
    def _rule(self, source_text, status=B, match_type=ClassificationRule.MATCH_SUBSTRING, **overrides):
        return ClassificationRule.objects.create(
            owner=self.user, status=status, match_type=match_type, source_text=source_text,
            all_log_types=True, **overrides,
        )

    def _statuses(self, payload):
        return [line["dominant_status"] for line in payload["lines"]]

    def test_verdict_spreads_to_the_block_only(self):
        rule = self._rule("UpdateCheck", apply_to_block=True)
        payload = analyze_log_text(SPOR_LOG, log_type="Spor")
        # banner, item, program, arguments, other item, its program
        self.assertEqual(self._statuses(payload), ["?", B, B, B, "?", "?"])
        program = payload["lines"][2]
        self.assertEqual(program["rule_ids"], [rule.pk])
        self.assertTrue(any("applies to its block (L2)" in reason for reason in program["reasons"]))

    def test_without_the_option_sub_lines_keep_their_own_verdict(self):
        self._rule("UpdateCheck")
        self.assertEqual(self._statuses(analyze_log_text(SPOR_LOG, log_type="Spor")), ["?", B, "?", "?", "?", "?"])

    def test_a_stronger_rule_on_a_sub_line_still_wins(self):
        self._rule("UpdateCheck", apply_to_block=True)
        self._rule("arguments: --silent", status=C, match_type=ClassificationRule.MATCH_EXACT)
        statuses = self._statuses(analyze_log_text(SPOR_LOG, log_type="Spor"))
        self.assertEqual(statuses[3], C)
        self.assertEqual(statuses[2], B)

    def test_a_rule_that_did_not_decide_its_line_does_not_spread(self):
        self._rule("UpdateCheck", apply_to_block=True)
        self._rule(SPOR_LOG.splitlines()[1], status=C, match_type=ClassificationRule.MATCH_EXACT)
        statuses = self._statuses(analyze_log_text(SPOR_LOG, log_type="Spor"))
        self.assertEqual(statuses[1:4], [C, "?", "?"])

    def test_no_blocks_outside_their_log_types(self):
        self._rule("UpdateCheck", apply_to_block=True)
        statuses = self._statuses(analyze_log_text(SPOR_LOG, log_type="FRST"))
        self.assertEqual(statuses, ["?", B, "?", "?", "?", "?"])

    def test_conditional_rule_with_block_verdict(self):
        fact = Fact.objects.create(name="runs from Roaming")
        FactRule.objects.create(
            owner=self.user, fact=fact, match_type="substring", source_text="\\AppData\\Roaming\\", all_log_types=True,
        )
        specs = [ConditionSpec(fact.pk, RuleCondition.POLARITY_REQUIRE, RuleCondition.SCOPE_BLOCK)]
        rule = self._rule("[task]", apply_to_block=True, condition_key=condition_key_for(specs))
        set_rule_conditions(rule, specs)
        statuses = self._statuses(analyze_log_text(SPOR_LOG, log_type="Spor"))
        self.assertEqual(statuses, ["?", B, B, B, "?", "?"])

    # -- editor --

    def test_add_page_and_edits(self):
        self.client.force_login(self.user)
        self.client.post(reverse("add_rule"), {
            "status": B, "match_type": "substring", "source_text": "evil", "priority": "",
            "apply_to_block_present": "1", "apply_to_block": "on",
        })
        rule = ClassificationRule.objects.get(source_text="evil")
        self.assertTrue(rule.apply_to_block)
        # An edit without the box (as the token API edits) keeps it.
        self.client.post(reverse("edit_rule", args=[rule.pk]), {
            "status": B, "match_type": "substring",
            "source_text": "evil2", "is_enabled": "on", "priority": "7",
        })
        rule.refresh_from_db()
        self.assertTrue(rule.apply_to_block)
        # The full editor posts it: unticking clears it.
        self.client.post(reverse("edit_rule", args=[rule.pk]), {
            "status": B, "match_type": "substring", "source_text": "evil2", "is_enabled": "on",
            "priority": "7", "apply_to_block_present": "1",
        })
        rule.refresh_from_db()
        self.assertFalse(rule.apply_to_block)

    def test_whole_log_rules_have_no_block(self):
        created, _skipped, error = create_rules(
            self.user, status="A", match_type="regex", source_text="x", whole_log=True, apply_to_block=True,
        )
        self.assertIsNone(error)
        self.assertFalse(created[0].apply_to_block)

    def test_editor_shows_the_option_and_the_list_its_badge(self):
        self.client.force_login(self.user)
        rule = self._rule("evil", apply_to_block=True)
        page = self.client.get(reverse("edit_rule", args=[rule.pk]))
        self.assertContains(page, 'id="ruleApplyToBlock" name="apply_to_block" checked')
        self.assertContains(self.client.get(reverse("rules")), ">block</span>")
