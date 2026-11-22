"""Advanced: a rule or fact rule restricted to lines FRST parses as given
entry types (only_entry_types)."""

import json
import re
from pathlib import Path

from django.test import SimpleTestCase
from django.urls import reverse

from .. import frst_extractors as ex
from ..analyzer import analyze_log_text, entry_types_allow, inspect_line_matches
from ..fact_service import ConditionSpec, condition_key_for, set_rule_conditions
from ..models import ClassificationRule, Fact, FactRule, RuleCondition
from ..views.rules import create_rules
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

B = ClassificationRule.STATUS_MALWARE

SERVICE = r"S2 AVP; C:\Program Files\Kaspersky\avp.exe [123 2026-01-01] (Kaspersky -> Kaspersky)"
ONEMONTH = r"2026-11-18 13:45 - 2026-11-18 13:45 - 000000000 ____D C:\Program Files\Kaspersky"
RUNKEY = r"HKLM\...\Run: [AVP] => C:\Program Files\Kaspersky\avp.exe [123 2026-01-01] (Kaspersky -> Kaspersky)"
PLAIN = "Kaspersky mentioned on a line no extractor understands"
LOG = "\n".join([SERVICE, ONEMONTH, RUNKEY, PLAIN])


class EntryTypesListTests(SimpleTestCase):
    def test_every_extractor_type_is_listed(self):
        source = Path(ex.__file__).read_text(encoding="utf-8")
        produced = set(re.findall(r'entry_type="([a-z_]+)"', source))
        self.assertTrue(produced)
        self.assertEqual(produced - set(ex.ENTRY_TYPES), set())

    def test_any_of_a_lines_parsed_types_counts(self):
        self.assertTrue(entry_types_allow(["service"], {"scheduled_task", "service"}))
        self.assertFalse(entry_types_allow(["service"], {"scheduled_task"}))
        self.assertFalse(entry_types_allow(["service"], set()))
        self.assertTrue(entry_types_allow([], set()))


class EntryTypeRestrictionTests(LogAnalyzerApiBaseTestCase):
    def _rule(self, source_text="Kaspersky", status=B, match_type=ClassificationRule.MATCH_SUBSTRING, **overrides):
        return ClassificationRule.objects.create(
            owner=self.user, status=status, match_type=match_type, source_text=source_text, **overrides,
        )

    def _statuses(self, payload):
        return [line["dominant_status"] for line in payload["lines"]]

    def test_restricted_rule_matches_only_lines_of_those_types(self):
        self._rule(only_entry_types=["service"])
        self.assertEqual(self._statuses(analyze_log_text(LOG)), [B, "?", "?", "?"])

    def test_several_types(self):
        self._rule(only_entry_types=["service", "runkey"])
        self.assertEqual(self._statuses(analyze_log_text(LOG)), [B, "?", B, "?"])

    def test_unrestricted_rule_matches_everywhere(self):
        self._rule()
        self.assertEqual(self._statuses(analyze_log_text(LOG)), [B, B, B, B])

    def test_fact_rule_restricted(self):
        fact = Fact.objects.create(name="Kaspersky service")
        FactRule.objects.create(
            owner=self.user, fact=fact, match_type="substring", source_text="Kaspersky", only_entry_types=["service"],
        )
        [found] = analyze_log_text(LOG)["facts"]
        self.assertEqual(found["line_indexes"], [0])

    def test_conditional_rule_restricted(self):
        fact = Fact.objects.create(name="f")
        FactRule.objects.create(owner=self.user, fact=fact, match_type="substring", source_text="Kaspersky")
        specs = [ConditionSpec(fact.pk, RuleCondition.POLARITY_REQUIRE, RuleCondition.SCOPE_LOG)]
        rule = self._rule(only_entry_types=["runkey"], condition_key=condition_key_for(specs))
        set_rule_conditions(rule, specs)
        self.assertEqual(self._statuses(analyze_log_text(LOG)), ["?", "?", B, "?"])

    def test_inspect_line_matches_honours_it(self):
        self._rule(only_entry_types=["service"])
        self.assertEqual(inspect_line_matches(SERVICE)["dominant_status"], B)
        self.assertEqual(inspect_line_matches(ONEMONTH)["matches"], [])

    # -- previews --

    def test_preview_honours_it(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("test_rule_api"), data=json.dumps({
            "source_text": "Kaspersky", "status": B, "match_type": "substring",
            "lines": [SERVICE, ONEMONTH], "only_entry_types": ["service"],
        }), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([r["matched"] for r in response.json()["results"]], [True, False])

    def test_preview_refuses_unknown_types(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("test_rule_api"), data=json.dumps({
            "source_text": "Kaspersky", "status": B, "match_type": "substring", "lines": [SERVICE],
            "only_entry_types": ["nonsense"],
        }), content_type="application/json")
        self.assertEqual(response.status_code, 400)

    # -- editor --

    def test_add_page_and_edits(self):
        self.client.force_login(self.user)
        self.client.post(reverse("add_rule"), {
            "status": B, "match_type": "substring", "source_text": "evil", "priority": "",
            "only_entry_types_present": "1", "only_entry_types": ["runkey", "service"],
        })
        rule = ClassificationRule.objects.get(source_text="evil")
        self.assertEqual(rule.only_entry_types, ["service", "runkey"])  # ENTRY_TYPES order
        # An edit without the boxes (as the token API edits) keeps them.
        self.client.post(reverse("edit_rule", args=[rule.pk]), {
            "status": B, "match_type": "substring",
            "source_text": "evil2", "is_enabled": "on", "priority": "7",
        })
        rule.refresh_from_db()
        self.assertEqual(rule.only_entry_types, ["service", "runkey"])
        page = self.client.get(reverse("edit_rule", args=[rule.pk]))
        self.assertContains(page, 'name="only_entry_types" value="service" checked')
        self.assertContains(self.client.get(reverse("rules")), "only: service, runkey")
        # The full editor posts them: none ticked clears them.
        self.client.post(reverse("edit_rule", args=[rule.pk]), {
            "status": B, "match_type": "substring", "source_text": "evil2", "is_enabled": "on",
            "priority": "7", "only_entry_types_present": "1",
        })
        rule.refresh_from_db()
        self.assertEqual(rule.only_entry_types, [])

    def test_unknown_types_refused(self):
        _created, _skipped, error = create_rules(
            self.user, status=B, match_type="substring", source_text="x", only_entry_types=["nonsense"],
        )
        self.assertIn("Unknown parsed type", error)

    def test_whole_log_rules_have_no_parsed_type(self):
        created, _skipped, error = create_rules(
            self.user, status="A", match_type="regex", source_text="x", whole_log=True, only_entry_types=["service"],
        )
        self.assertIsNone(error)
        self.assertEqual(created[0].only_entry_types, [])

    def test_fact_rule_via_the_editor(self):
        self.client.force_login(self.user)
        fact = Fact.objects.create(name="f")
        self.client.post(reverse("add_rule"), {
            "status": "fact", "fact_id": str(fact.pk), "match_type": "substring", "source_text": "AVP",
            "only_entry_types_present": "1", "only_entry_types": ["service"],
        })
        rule = FactRule.objects.get(fact=fact)
        self.assertEqual(rule.only_entry_types, ["service"])
        page = self.client.get(reverse("fact_edit", args=[fact.pk]))
        self.assertContains(page, "only: service")


class LogScopeDropdownTests(LogAnalyzerApiBaseTestCase):
    """The log type picker posts log_scope "default" with the default types."""

    def test_default_choice_saves_the_default_scope(self):
        self.client.force_login(self.user)
        self.client.post(reverse("add_rule"), {
            "status": B, "match_type": "substring", "source_text": "evil", "priority": "",
            "log_scope": "default", "log_types": ["FRST&Addition", "FRST", "Addition"],
        })
        rule = ClassificationRule.objects.get(source_text="evil")
        self.assertFalse(rule.all_log_types)
        self.assertEqual(sorted(rule.log_types), ["Addition", "FRST", "FRST&Addition"])


class KeptLogScopeTests(LogAnalyzerApiBaseTestCase):
    """After "create", the add page keeps a log type scope only when the user
    chose one other than the match type's default, so a new file path rule
    still defaults to all log types."""

    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)

    def _create(self, **fields):
        data = {"status": B, "match_type": "substring", "source_text": "evil", "priority": ""}
        data.update(fields)
        return self.client.post(reverse("add_rule"), data)

    def test_default_scope_is_not_carried_over(self):
        response = self._create(log_scope="default", log_types=["FRST&Addition", "FRST", "Addition"])
        self.assertNotIn("log_scope", response["Location"])
        page = self.client.get(response["Location"])
        self.assertFalse(page.context["log_scope_picker"]["chosen"])

    def test_all_types_for_a_file_path_rule_is_its_default(self):
        response = self._create(match_type="filepath", source_text=r"C:\x\evil.exe", log_scope="all")
        self.assertNotIn("log_scope", response["Location"])

    def test_a_chosen_scope_is_kept(self):
        response = self._create(log_scope="selected", log_types=["Spor"])
        self.assertIn("log_scope=selected", response["Location"])
        self.assertIn("log_types=Spor", response["Location"])
        page = self.client.get(response["Location"])
        self.assertTrue(page.context["log_scope_picker"]["chosen"])

    def test_fact_rules_too(self):
        fact = Fact.objects.create(name="f")
        response = self._create(
            status="fact", fact_id=str(fact.pk), log_scope="default", log_types=["FRST&Addition", "FRST", "Addition"],
        )
        self.assertIn("record_fact=1", response["Location"])
        self.assertNotIn("log_scope", response["Location"])
