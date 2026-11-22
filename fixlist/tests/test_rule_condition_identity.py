"""A rule's conditions are part of its identity (condition_key): rules may
differ in their conditions alone, and every lookup of "the same rule" must
take them into account."""

import json

from django.urls import reverse

from ..analyzer import find_rule_duplicates, parse_rule_line, upsert_parsed_rule
from ..fact_service import ConditionSpec, condition_key_for, fact_delete_error, set_rule_conditions
from ..models import ClassificationRule, Fact, RuleCondition
from ..views.rules import create_rules
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

B = ClassificationRule.STATUS_MALWARE
REQUIRE, LOG, BLOCK = RuleCondition.POLARITY_REQUIRE, RuleCondition.SCOPE_LOG, RuleCondition.SCOPE_BLOCK

SERVICE_LINE = (
    r"R3 ProtoVPN Service; C:\Program Files\Proton\VPN\v4.3.13\ProtoVPNService.exe "
    r"[477424 2026-03-06] (Proto AG -> ProtoVPN)"
)


class RuleConditionIdentityTests(LogAnalyzerApiBaseTestCase):
    def setUp(self):
        super().setUp()
        self.fact = Fact.objects.create(name="Kaspersky installed")
        self.specs = [ConditionSpec(self.fact.pk, REQUIRE, LOG)]
        self.client.force_login(self.user)

    def _conditional(self, source_text, status=B, match_type=ClassificationRule.MATCH_SUBSTRING, specs=None):
        specs = self.specs if specs is None else specs
        rule = ClassificationRule.objects.create(
            owner=self.user, status=status, match_type=match_type, source_text=source_text,
            condition_key=condition_key_for(specs),
        )
        set_rule_conditions(rule, specs)
        return rule

    def test_condition_key_is_canonical(self):
        other = Fact.objects.create(name="other")
        one = [ConditionSpec(self.fact.pk, REQUIRE, LOG), ConditionSpec(other.pk, "forbid", BLOCK)]
        self.assertEqual(condition_key_for(one), condition_key_for(list(reversed(one))))
        self.assertEqual(condition_key_for([]), "")

    def test_review_persist_next_to_a_conditional_twin(self):
        parsed = parse_rule_line(SERVICE_LINE, status=B, source_name="test")
        twin = self._conditional(parsed["source_text"], match_type=parsed["match_type"])
        rule, created = upsert_parsed_rule(parsed, self.user.pk)
        self.assertTrue(created)
        self.assertNotEqual(rule.pk, twin.pk)
        self.assertEqual(rule.condition_key, "")
        # Again: the plain rule is updated, the conditional one left alone.
        again, created = upsert_parsed_rule(parsed, self.user.pk)
        self.assertFalse(created)
        self.assertEqual(again.pk, rule.pk)
        twin.refresh_from_db()
        self.assertEqual(twin.conditions.count(), 1)

    def test_create_rules_with_and_without_conditions(self):
        self._conditional("evil")
        created, skipped, error = create_rules(self.user, status=B, match_type="substring", source_text="evil")
        self.assertIsNone(error)
        self.assertEqual(len(created), 1)
        created, skipped, error = create_rules(
            self.user, status=B, match_type="substring", source_text="evil", conditions=self.specs,
        )
        self.assertEqual((created, skipped), ([], ["evil"]))
        new, _skipped, _error = create_rules(
            self.user, status=B, match_type="substring", source_text="worse", conditions=self.specs,
        )
        self.assertEqual([c.fact_id for c in new[0].conditions.all()], [self.fact.pk])
        self.assertEqual(new[0].condition_key, condition_key_for(self.specs))

    def test_add_page_posts_conditions(self):
        self.client.post(reverse("add_rule"), {
            "status": B, "match_type": "substring", "source_text": "evil", "priority": "",
            "conditions_present": "1",
            "conditions": json.dumps([{"fact_id": self.fact.pk, "polarity": "forbid", "scope": "block"}]),
        })
        rule = ClassificationRule.objects.get(source_text="evil")
        self.assertEqual(
            [(c.fact_id, c.polarity, c.scope) for c in rule.conditions.all()], [(self.fact.pk, "forbid", "block")],
        )

    def test_whole_log_rule_conditions_must_look_at_the_log(self):
        created, _skipped, error = create_rules(
            self.user, status="A", match_type="regex", source_text="x", whole_log=True,
            conditions=[ConditionSpec(self.fact.pk, REQUIRE, BLOCK)],
        )
        self.assertEqual(created, [])
        self.assertIn("anywhere in the log", error)

    def test_a_fact_only_once_per_rule(self):
        _created, _skipped, error = create_rules(
            self.user, status=B, match_type="substring", source_text="x",
            conditions=[ConditionSpec(self.fact.pk, REQUIRE, LOG), ConditionSpec(self.fact.pk, "forbid", LOG)],
        )
        self.assertIn("only one condition", error)

    def test_an_edit_without_conditions_keeps_them(self):
        rule = self._conditional("evil")
        self.client.post(reverse("edit_rule", args=[rule.pk]), {
            "status": B, "match_type": "substring",
            "source_text": "evil2", "description": "", "is_enabled": "on", "priority": "7",
        })
        rule.refresh_from_db()
        self.assertEqual(rule.source_text, "evil2")
        self.assertEqual(rule.condition_key, condition_key_for(self.specs))
        self.assertEqual(rule.conditions.count(), 1)

    def test_an_edit_turning_on_whole_log_checks_kept_conditions(self):
        rule = self._conditional("x", status="A", match_type="regex", specs=[ConditionSpec(self.fact.pk, REQUIRE, BLOCK)])
        self.client.post(reverse("edit_rule", args=[rule.pk]), {
            "status": "A", "match_type": "regex",
            "source_text": "x", "is_enabled": "on", "priority": "3", "whole_log": "on",
        })
        rule.refresh_from_db()
        self.assertFalse(rule.whole_log)

    def test_editor_clears_conditions(self):
        rule = self._conditional("evil")
        self.client.post(reverse("edit_rule", args=[rule.pk]), {
            "status": B, "match_type": "substring", "source_text": "evil", "is_enabled": "on",
            "priority": "7", "conditions_present": "1", "conditions": "[]",
        })
        rule.refresh_from_db()
        self.assertEqual(rule.condition_key, "")
        self.assertFalse(rule.conditions.exists())

    def test_editor_refuses_a_duplicate_with_the_same_conditions(self):
        self._conditional("evil")
        rule = self._conditional("other")
        response = self.client.post(reverse("edit_rule", args=[rule.pk]), {
            "status": B, "match_type": "substring", "source_text": "evil", "is_enabled": "on",
            "priority": "7", "conditions_present": "1",
            "conditions": json.dumps([{"fact_id": self.fact.pk, "polarity": "require", "scope": "log"}]),
        })
        self.assertContains(response, "same conditions already exists")
        rule.refresh_from_db()
        self.assertEqual(rule.source_text, "other")

    def test_editor_shows_the_conditions_on_the_advanced_tab(self):
        rule = self._conditional("evil")
        page = self.client.get(reverse("edit_rule", args=[rule.pk]))
        self.assertContains(page, 'id="ruleConditionsGroup"')
        self.assertContains(page, f'"fact_id": {self.fact.pk}')

    def test_rules_list_marks_conditional_rules(self):
        self._conditional("evil")
        self.assertContains(self.client.get(reverse("rules")), ">conditional</span>")

    def test_find_duplicates_keeps_conditional_variants_apart(self):
        parsed = parse_rule_line(SERVICE_LINE, status=B, source_name="test")
        plain, _created = upsert_parsed_rule(parsed, self.user.pk)
        self._conditional(parsed["source_text"], match_type=parsed["match_type"])
        groups = find_rule_duplicates(ClassificationRule.objects.filter(pk__gte=plain.pk))
        self.assertEqual(groups, [])

    def test_a_fact_in_a_condition_cannot_be_deleted(self):
        self._conditional("evil")
        self.assertIn("conditions", fact_delete_error(self.fact, self.user))
