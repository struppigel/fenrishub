"""Superusers may view and edit every rule from the web UI; the rule keeps its
original owner. Also covers the rule editors' priority-20 confirm wiring."""
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from ..analyzer import invalidate_rule_buckets_cache
from ..models import PRIORITY_MAX, ClassificationRule
from .factories import make_rule, make_superuser, make_user

HIGHEST_PRIORITY_WARNING = 'highest priority should only be used in exceptional cases, are you sure?'


class SuperuserRuleEditingTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        self.owner = make_user("bob")
        self.admin = make_superuser()
        self.client.login(username="admin", password="password123")
        self.rule = make_rule("BOB-RULE", owner=self.owner, is_enabled=True)

    def _edit_body(self, **overrides):
        body = {
            "status": ClassificationRule.STATUS_PUP,
            "match_type": ClassificationRule.MATCH_EXACT,
            "source_text": "BOB-RULE-EDITED",
            "description": "edited by admin",
            "is_enabled": "on",
            "priority": str(self.rule.priority),
        }
        body.update(overrides)
        return body

    def test_quick_edit_changes_rule_and_keeps_owner(self):
        with patch("fixlist.views.rules.invalidate_for_rule_owner") as invalidate:
            response = self.client.post(
                reverse("rules"), {"action": "edit", "pk": self.rule.pk, **self._edit_body()}
            )
        self.assertEqual(response.status_code, 302)
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.source_text, "BOB-RULE-EDITED")
        self.assertEqual(self.rule.status, ClassificationRule.STATUS_PUP)
        self.assertEqual(self.rule.owner, self.owner)
        invalidate.assert_called_with(self.owner)

    def test_full_editor_opens_another_users_rule(self):
        response = self.client.get(reverse("edit_rule", args=[self.rule.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="ruleOwnerNote"')
        self.assertContains(response, "editing a rule owned by bob")

    def test_full_editor_saves_and_keeps_owner(self):
        response = self.client.post(reverse("edit_rule", args=[self.rule.pk]), self._edit_body())
        self.assertRedirects(response, reverse("rules"))
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.source_text, "BOB-RULE-EDITED")
        self.assertEqual(self.rule.owner, self.owner)
        self.assertEqual(ClassificationRule.objects.count(), 1)

    def test_toggle_invalidates_owners_rule_set(self):
        with patch("fixlist.views.rules.invalidate_for_rule_owner") as invalidate:
            response = self.client.post(reverse("rules"), {"action": "toggle", "pk": self.rule.pk})
        self.assertEqual(response.status_code, 302)
        self.rule.refresh_from_db()
        self.assertFalse(self.rule.is_enabled)
        self.assertEqual(self.rule.owner, self.owner)
        invalidate.assert_called_once_with(self.owner)

    def test_delete_invalidates_owners_rule_set(self):
        with patch("fixlist.views.rules.invalidate_for_rule_owner") as invalidate:
            response = self.client.post(reverse("rules"), {"action": "delete", "pk": self.rule.pk})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ClassificationRule.objects.filter(pk=self.rule.pk).exists())
        invalidate.assert_called_once_with(self.owner)

    def test_rules_list_offers_actions_on_other_users_rules(self):
        response = self.client.get(reverse("rules"), {"filter": "others"})
        self.assertContains(response, f'name="pk" value="{self.rule.pk}"')

    def test_own_rule_has_no_owner_note(self):
        own = make_rule("ADMIN-RULE", owner=self.admin)
        response = self.client.get(reverse("edit_rule", args=[own.pk]))
        self.assertNotContains(response, 'id="ruleOwnerNote"')


class RegularUserRuleListTests(TestCase):
    def setUp(self):
        self.user = make_user("alice")
        self.other = make_user("bob")
        self.client.login(username="alice", password="password123")

    def test_rules_list_hides_actions_on_other_users_rules(self):
        rule = make_rule("BOB-RULE", owner=self.other)
        response = self.client.get(reverse("rules"), {"filter": "others"})
        self.assertContains(response, "BOB-RULE")
        self.assertNotContains(response, f'name="pk" value="{rule.pk}"')


class RuleEditorWarningWiringTests(TestCase):
    """The confirm dialogs are browser-only; these check the pages ship them."""

    def setUp(self):
        self.user = make_user("alice")
        self.client.login(username="alice", password="password123")

    def test_add_rule_page_has_priority_warning(self):
        response = self.client.get(reverse("add_rule"))
        self.assertContains(response, HIGHEST_PRIORITY_WARNING)
        self.assertContains(response, f"const PRIORITY_MAX = {PRIORITY_MAX};")

    def test_rules_page_has_priority_and_case_insensitive_warnings(self):
        response = self.client.get(reverse("rules"))
        self.assertContains(response, HIGHEST_PRIORITY_WARNING)
        self.assertContains(response, f"const PRIORITY_MAX = {PRIORITY_MAX};")
        self.assertContains(response, 'id="editCaseInsensitiveWarning"')
        self.assertContains(response, "this will make regex matching slow")

    def test_add_rule_page_labels_case_insensitive_regex_warning(self):
        response = self.client.get(reverse("add_rule"))
        self.assertContains(response, "'case_insensitive'")
        self.assertContains(response, "this will make regex matching slow")
