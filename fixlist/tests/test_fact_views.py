"""The facts list and editor, and fact rules through the rule editor page."""

import json

from django.contrib.auth.models import User
from django.urls import reverse

from ..models import ClassificationRule, Fact, FactRule, FactTagSource, RuleTag
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase


class FactViewTests(LogAnalyzerApiBaseTestCase):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)
        self.tag = RuleTag.objects.create(name="Kaspersky")

    def _fact_rule(self, fact, owner=None, source_text="Kaspersky"):
        return FactRule.objects.create(
            owner=owner or self.user, fact=fact, match_type=FactRule.MATCH_SUBSTRING, source_text=source_text,
        )

    # -- facts list and editor --

    def test_list_shows_facts_with_counts(self):
        fact = Fact.objects.create(name="Kaspersky installed", description="AV present")
        self._fact_rule(fact)
        response = self.client.get(reverse("facts"))
        self.assertContains(response, "Kaspersky installed")
        self.assertContains(response, "1 fact rule,")

    def test_create_fact_with_tag_sources(self):
        sources = [{"tag_id": self.tag.pk, "statuses": ["S", "C"], "mode": "decided",
                    "include_filepath_fallback": True}]
        response = self.client.post(reverse("fact_add"), {
            "name": "Kaspersky installed", "description": "notes", "tag_sources": json.dumps(sources),
        })
        fact = Fact.objects.get(name="Kaspersky installed")
        self.assertRedirects(response, reverse("fact_edit", args=[fact.pk]))
        source = FactTagSource.objects.get(fact=fact)
        self.assertEqual((source.tag_id, source.statuses, source.mode, source.include_filepath_fallback),
                         (self.tag.pk, ["C", "S"], "decided", True))
        self.assertEqual(fact.created_by, self.user)

    def test_fact_names_are_unique_ignoring_case(self):
        Fact.objects.create(name="Kaspersky installed")
        response = self.client.post(reverse("fact_add"), {"name": "kaspersky INSTALLED", "tag_sources": "[]"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already exists")
        self.assertEqual(Fact.objects.count(), 1)

    def test_saving_replaces_the_tag_sources(self):
        fact = Fact.objects.create(name="Kaspersky installed")
        other = RuleTag.objects.create(name="Avast")
        FactTagSource.objects.create(fact=fact, tag=self.tag)
        self.client.post(reverse("fact_edit", args=[fact.pk]), {
            "name": "Kaspersky installed", "tag_sources": json.dumps([{"tag_id": other.pk}]),
        })
        self.assertEqual(list(FactTagSource.objects.filter(fact=fact).values_list("tag_id", flat=True)), [other.pk])

    def test_bad_tag_source_is_refused(self):
        fact = Fact.objects.create(name="Kaspersky installed")
        response = self.client.post(reverse("fact_edit", args=[fact.pk]), {
            "name": "Kaspersky installed", "tag_sources": json.dumps([{"tag_id": self.tag.pk, "statuses": ["?"]}]),
        })
        self.assertContains(response, "Unknown status")
        self.assertFalse(FactTagSource.objects.exists())

    def test_delete_fact_with_own_rules(self):
        fact = Fact.objects.create(name="Kaspersky installed")
        self._fact_rule(fact)
        FactTagSource.objects.create(fact=fact, tag=self.tag)
        self.client.post(reverse("facts"), {"action": "delete", "pk": fact.pk})
        self.assertFalse(Fact.objects.exists())
        self.assertFalse(FactRule.objects.exists())
        self.assertTrue(RuleTag.objects.filter(pk=self.tag.pk).exists())

    def test_fact_with_other_helpers_rules_is_kept(self):
        fact = Fact.objects.create(name="Kaspersky installed")
        self._fact_rule(fact, owner=self.other_user)
        self.client.post(reverse("facts"), {"action": "delete", "pk": fact.pk})
        self.assertTrue(Fact.objects.filter(pk=fact.pk).exists())

    def test_superuser_deletes_any_unused_fact(self):
        fact = Fact.objects.create(name="Kaspersky installed")
        self._fact_rule(fact, owner=self.other_user)
        admin = User.objects.create_superuser(username="boss", password="pw")
        self.client.force_login(admin)
        self.client.post(reverse("facts"), {"action": "delete", "pk": fact.pk})
        self.assertFalse(Fact.objects.exists())

    def test_only_the_owner_toggles_or_deletes_a_fact_rule(self):
        fact = Fact.objects.create(name="Kaspersky installed")
        theirs = self._fact_rule(fact, owner=self.other_user)
        response = self.client.post(reverse("facts"), {"action": "fact_rule_delete", "pk": theirs.pk})
        self.assertEqual(response.status_code, 404)
        mine = self._fact_rule(fact, source_text="AVP")
        self.client.post(reverse("facts"), {"action": "fact_rule_toggle", "pk": mine.pk, "return_to": "fact"})
        mine.refresh_from_db()
        self.assertFalse(mine.is_enabled)

    # -- fact rules through the rule editor --

    def test_add_page_offers_fact_in_the_status_dropdown_and_the_rule_editor_does_not(self):
        self.assertContains(self.client.get(reverse("add_rule")), '>fact rule</option>')
        rule = ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="substring", source_text="evil",
        )
        self.assertNotContains(self.client.get(reverse("edit_rule", args=[rule.pk])), '>fact rule</option>')

    def test_choosing_fact_as_status_creates_a_fact_rule(self):
        fact = Fact.objects.create(name="Kaspersky installed")
        self.client.post(reverse("add_rule"), {
            "status": "fact", "fact_id": str(fact.pk), "match_type": "substring", "source_text": "AVP",
        })
        self.assertTrue(FactRule.objects.filter(fact=fact, source_text="AVP").exists())
        self.assertFalse(ClassificationRule.objects.exists())

    def test_fact_rule_editor_offers_only_fact(self):
        rule = self._fact_rule(Fact.objects.create(name="f"))
        page = self.client.get(reverse("edit_fact_rule", args=[rule.pk]))
        self.assertContains(page, '<option value="fact" selected title=')
        self.assertContains(page, '>fact rule</option>')
        self.assertContains(page, '<h2 id="ruleHeading">edit fact rule</h2>')
        self.assertNotContains(page, '>B - ')

    def test_creating_fact_rules_says_fact_rules(self):
        fact = Fact.objects.create(name="f")
        response = self.client.post(reverse("add_rule"), {
            "status": "fact", "fact_id": str(fact.pk), "match_type": "substring", "source_text": "a\nb",
        }, follow=True)
        self.assertContains(response, "2 fact rules created.")

    def test_add_page_creates_fact_rules_and_a_new_fact(self):
        response = self.client.post(reverse("add_rule"), {
            "record_fact": "on", "fact_id": "new", "new_fact_name": "Kaspersky installed",
            "status": "B", "match_type": "substring", "source_text": "Kaspersky\nAVP",
            "description": "the AV", "priority": "",
        })
        fact = Fact.objects.get(name="Kaspersky installed")
        self.assertEqual(response.status_code, 302)
        self.assertIn("record_fact=1", response["Location"])
        self.assertEqual(
            sorted(FactRule.objects.filter(fact=fact).values_list("source_text", flat=True)), ["AVP", "Kaspersky"],
        )
        self.assertFalse(ClassificationRule.objects.exists())

    def test_add_page_without_fact_mode_still_creates_classification_rules(self):
        self.client.post(reverse("add_rule"), {
            "status": "B", "match_type": "substring", "source_text": "evil", "priority": "",
        })
        self.assertTrue(ClassificationRule.objects.filter(source_text="evil").exists())
        self.assertFalse(FactRule.objects.exists())

    def test_fact_rule_needs_a_fact(self):
        response = self.client.post(reverse("add_rule"), {
            "record_fact": "on", "fact_id": "", "status": "B", "match_type": "substring", "source_text": "x",
        })
        self.assertContains(response, "Choose the fact")
        self.assertFalse(FactRule.objects.exists())

    def test_whole_log_fact_rule_needs_regex_or_script(self):
        fact = Fact.objects.create(name="f")
        response = self.client.post(reverse("add_rule"), {
            "record_fact": "on", "fact_id": str(fact.pk), "status": "B", "match_type": "substring",
            "source_text": "x", "whole_log": "on",
        })
        self.assertContains(response, "regex and script")
        self.client.post(reverse("add_rule"), {
            "record_fact": "on", "fact_id": str(fact.pk), "status": "B", "match_type": "regex",
            "source_text": "x.*y", "whole_log": "on",
        })
        self.assertTrue(FactRule.objects.get(fact=fact).whole_log)

    def test_edit_fact_rule(self):
        fact = Fact.objects.create(name="Kaspersky installed")
        other_fact = Fact.objects.create(name="Avast installed")
        rule = self._fact_rule(fact)
        page = self.client.get(reverse("edit_fact_rule", args=[rule.pk]))
        self.assertContains(page, "edit fact rule")
        self.assertContains(page, "const EXCLUDE_RULE_ID = null;")
        response = self.client.post(reverse("edit_fact_rule", args=[rule.pk]), {
            "record_fact": "on", "fact_id": str(other_fact.pk), "match_type": "substring",
            "source_text": "avast", "is_enabled": "on",
        })
        self.assertRedirects(response, reverse("fact_edit", args=[other_fact.pk]))
        rule.refresh_from_db()
        self.assertEqual((rule.fact_id, rule.source_text), (other_fact.pk, "avast"))

    def test_other_helpers_cannot_edit_a_fact_rule(self):
        rule = self._fact_rule(Fact.objects.create(name="f"), owner=self.other_user)
        self.assertEqual(self.client.get(reverse("edit_fact_rule", args=[rule.pk])).status_code, 404)


class RulesOverviewFactRuleTests(LogAnalyzerApiBaseTestCase):
    """Fact rules are listed on the rules page with the rules."""

    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)
        self.fact = Fact.objects.create(name="Kaspersky installed")
        self.fact_rule = FactRule.objects.create(
            owner=self.user, fact=self.fact, match_type="substring", source_text="AVP service",
        )
        self.rule = ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="substring", source_text="evil",
        )

    def _page(self, **params):
        return self.client.get(reverse("rules"), params)

    def test_listed_with_the_rules(self):
        page = self._page()
        self.assertContains(page, "AVP service")
        self.assertContains(page, "evil")
        self.assertContains(page, ">Kaspersky installed</a>")
        self.assertContains(page, reverse("edit_fact_rule", args=[self.fact_rule.pk]))
        self.assertContains(page, "2 rules found")

    def test_fact_rules_filter(self):
        page = self._page(status="fact")
        self.assertContains(page, "AVP service")
        self.assertNotContains(page, ">evil<")
        self.assertContains(page, '<option value="fact" selected>fact rules</option>')

    def test_rule_only_filters_hide_fact_rules(self):
        tag = RuleTag.objects.create(name="t")
        self.rule.tags.add(tag)
        for params in ({"status": "B"}, {"tags": tag.pk}, {"priority": "7"}):
            with self.subTest(params=params):
                self.assertNotContains(self._page(**params), "AVP service")

    def test_text_search_finds_fact_rules_by_fact_name(self):
        page = self._page(q="kaspersky")
        self.assertContains(page, "AVP service")
        self.assertNotContains(page, ">evil<")

    def test_line_search_finds_fact_rules(self):
        page = self._page(q="AVP service started", search_mode="line")
        self.assertContains(page, "AVP service")

    def test_merged_paging_newest_first(self):
        for number in range(12):
            ClassificationRule.objects.create(
                owner=self.user, status="B", match_type="substring", source_text=f"filler {number}",
            )
        self.fact_rule.description = "touched last"
        self.fact_rule.save()  # newest of all: first on page 1
        page = self._page()
        self.assertContains(page, "14 rules found")
        content = page.content.decode()
        self.assertLess(content.index("AVP service"), content.index("filler 11"))
        self.assertNotContains(self._page(page=2), "AVP service")

    def test_actions_return_to_the_rules_page(self):
        response = self.client.post(reverse("facts"), {
            "action": "fact_rule_toggle", "pk": self.fact_rule.pk, "return_to": "rules",
            "return_q": "filter=own&status=fact",
        })
        self.assertRedirects(response, reverse("rules") + "?filter=own&status=fact", fetch_redirect_response=False)
        self.fact_rule.refresh_from_db()
        self.assertFalse(self.fact_rule.is_enabled)
