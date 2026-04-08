from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule


class RulesViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.other = User.objects.create_user(username="bob", password="password123")
        self.client.login(username="alice", password="password123")

    def test_rules_page_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("rules"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_rules_page_renders(self):
        response = self.client.get(reverse("rules"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "rules")

    # -- Create --

    def test_create_rule(self):
        response = self.client.post(
            reverse("rules"),
            {
                "action": "create",
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "MALICIOUS-LINE",
                "description": "test rule",
            },
        )
        self.assertEqual(response.status_code, 302)
        rule = ClassificationRule.objects.get(source_text="MALICIOUS-LINE")
        self.assertEqual(rule.owner, self.user)
        self.assertEqual(rule.status, ClassificationRule.STATUS_MALWARE)
        self.assertEqual(rule.match_type, ClassificationRule.MATCH_EXACT)
        self.assertEqual(rule.description, "test rule")
        self.assertTrue(rule.is_enabled)

    def test_create_rule_requires_source_text(self):
        response = self.client.post(
            reverse("rules"),
            {
                "action": "create",
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_rule_rejects_invalid_status(self):
        response = self.client.post(
            reverse("rules"),
            {
                "action": "create",
                "status": "X",
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "some-line",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_rule_rejects_invalid_match_type(self):
        response = self.client.post(
            reverse("rules"),
            {
                "action": "create",
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": "invalid",
                "source_text": "some-line",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_rule_rejects_duplicate(self):
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="DUP-LINE",
        )
        response = self.client.post(
            reverse("rules"),
            {
                "action": "create",
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "DUP-LINE",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ClassificationRule.objects.filter(source_text="DUP-LINE").count(), 1)

    # -- Edit --

    def test_edit_own_rule(self):
        rule = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="ORIGINAL",
        )
        response = self.client.post(
            reverse("rules"),
            {
                "action": "edit",
                "pk": rule.pk,
                "status": ClassificationRule.STATUS_PUP,
                "match_type": ClassificationRule.MATCH_SUBSTRING,
                "source_text": "UPDATED",
                "description": "new desc",
                "is_enabled": "on",
            },
        )
        self.assertEqual(response.status_code, 302)
        rule.refresh_from_db()
        self.assertEqual(rule.status, ClassificationRule.STATUS_PUP)
        self.assertEqual(rule.match_type, ClassificationRule.MATCH_SUBSTRING)
        self.assertEqual(rule.source_text, "UPDATED")
        self.assertEqual(rule.description, "new desc")
        self.assertTrue(rule.is_enabled)

    def test_edit_can_disable_rule(self):
        rule = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="TO-DISABLE",
        )
        response = self.client.post(
            reverse("rules"),
            {
                "action": "edit",
                "pk": rule.pk,
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "TO-DISABLE",
                "description": "",
            },
        )
        self.assertEqual(response.status_code, 302)
        rule.refresh_from_db()
        self.assertFalse(rule.is_enabled)

    def test_cannot_edit_other_users_rule(self):
        rule = ClassificationRule.objects.create(
            owner=self.other,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="BOB-RULE",
        )
        response = self.client.post(
            reverse("rules"),
            {
                "action": "edit",
                "pk": rule.pk,
                "status": ClassificationRule.STATUS_PUP,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "BOB-RULE",
            },
        )
        self.assertEqual(response.status_code, 404)
        rule.refresh_from_db()
        self.assertEqual(rule.status, ClassificationRule.STATUS_MALWARE)

    # -- Delete --

    def test_delete_own_rule(self):
        rule = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="DELETE-ME",
        )
        response = self.client.post(
            reverse("rules"),
            {"action": "delete", "pk": rule.pk},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ClassificationRule.objects.filter(pk=rule.pk).exists())

    def test_delete_own_rule_preserves_filter_and_search_query(self):
        rule = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="DELETE-WITH-QUERY",
        )
        query = "filter=own&status=B&match=exact&q=abc&search_mode=text&sort=recent&page=2"

        response = self.client.post(
            reverse("rules"),
            {"action": "delete", "pk": rule.pk, "return_q": query},
        )

        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, f"{reverse('rules')}?{query}")
        self.assertFalse(ClassificationRule.objects.filter(pk=rule.pk).exists())

    def test_cannot_delete_other_users_rule(self):
        rule = ClassificationRule.objects.create(
            owner=self.other,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="BOB-NODELETE",
        )
        response = self.client.post(
            reverse("rules"),
            {"action": "delete", "pk": rule.pk},
        )
        self.assertEqual(response.status_code, 404)
        self.assertTrue(ClassificationRule.objects.filter(pk=rule.pk).exists())

    # -- Toggle --

    def test_toggle_disables_enabled_rule(self):
        rule = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="TOGGLE-ME",
            is_enabled=True,
        )
        self.client.post(reverse("rules"), {"action": "toggle", "pk": rule.pk})
        rule.refresh_from_db()
        self.assertFalse(rule.is_enabled)

    def test_toggle_enables_disabled_rule(self):
        rule = ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="TOGGLE-ME-ON",
            is_enabled=False,
        )
        self.client.post(reverse("rules"), {"action": "toggle", "pk": rule.pk})
        rule.refresh_from_db()
        self.assertTrue(rule.is_enabled)

    def test_cannot_toggle_other_users_rule(self):
        rule = ClassificationRule.objects.create(
            owner=self.other,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text="BOB-NOTOGGLE",
            is_enabled=True,
        )
        response = self.client.post(
            reverse("rules"),
            {"action": "toggle", "pk": rule.pk},
        )
        self.assertEqual(response.status_code, 404)
        rule.refresh_from_db()
        self.assertTrue(rule.is_enabled)

    # -- Filtering --

    def test_filter_own_shows_only_own_rules(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="ALICE-RULE"
        )
        ClassificationRule.objects.create(
            owner=self.other, status="B", match_type="exact", source_text="BOB-RULE"
        )
        response = self.client.get(reverse("rules") + "?filter=own")
        self.assertContains(response, "ALICE-RULE")
        self.assertNotContains(response, "BOB-RULE")

    def test_filter_others_shows_only_other_rules(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="ALICE-RULE2"
        )
        ClassificationRule.objects.create(
            owner=self.other, status="B", match_type="exact", source_text="BOB-RULE2"
        )
        response = self.client.get(reverse("rules") + "?filter=others")
        self.assertNotContains(response, "ALICE-RULE2")
        self.assertContains(response, "BOB-RULE2")

    def test_filter_all_shows_both(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="ALICE-ALL"
        )
        ClassificationRule.objects.create(
            owner=self.other, status="B", match_type="exact", source_text="BOB-ALL"
        )
        response = self.client.get(reverse("rules") + "?filter=all")
        self.assertContains(response, "ALICE-ALL")
        self.assertContains(response, "BOB-ALL")

    def test_filter_by_status(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="MALWARE-FILTER"
        )
        ClassificationRule.objects.create(
            owner=self.user, status="C", match_type="exact", source_text="CLEAN-FILTER"
        )
        response = self.client.get(reverse("rules") + "?filter=own&status=B")
        self.assertContains(response, "MALWARE-FILTER")
        self.assertNotContains(response, "CLEAN-FILTER")

    def test_filter_by_alert_status(self):
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_ALERT,
            match_type="exact",
            source_text="ALERT-FILTER",
        )
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type="exact",
            source_text="NON-ALERT-FILTER",
        )

        response = self.client.get(reverse("rules") + "?filter=own&status=A")
        self.assertContains(response, "ALERT-FILTER")
        self.assertNotContains(response, "NON-ALERT-FILTER")

    def test_filter_by_match_type(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="EXACT-MT"
        )
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="substring", source_text="SUB-MT"
        )
        response = self.client.get(reverse("rules") + "?filter=own&match=exact")
        self.assertContains(response, "EXACT-MT")
        self.assertNotContains(response, "SUB-MT")

    def test_search_filters_by_source_text(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="NEEDLE-IN-HAYSTACK"
        )
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="UNRELATED"
        )
        response = self.client.get(reverse("rules") + "?filter=own&q=NEEDLE")
        self.assertContains(response, "NEEDLE-IN-HAYSTACK")
        self.assertNotContains(response, "UNRELATED")

    def test_search_filters_by_description(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact",
            source_text="RULE-A", description="important malware rule",
        )
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact",
            source_text="RULE-B", description="something else",
        )
        response = self.client.get(reverse("rules") + "?filter=own&q=important")
        self.assertContains(response, "RULE-A")
        self.assertNotContains(response, "RULE-B")

    def test_other_users_rules_have_no_action_buttons(self):
        ClassificationRule.objects.create(
            owner=self.other, status="B", match_type="exact", source_text="BOB-READONLY"
        )
        response = self.client.get(reverse("rules") + "?filter=others")
        self.assertContains(response, "BOB-READONLY")
        content = response.content.decode()
        self.assertNotIn('value="toggle"', content)
        self.assertNotIn('value="delete"', content)
        self.assertNotIn('onclick="startEdit(', content)

    def test_own_rules_have_action_buttons(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="ALICE-ACTIONS"
        )
        response = self.client.get(reverse("rules") + "?filter=own")
        self.assertContains(response, "ALICE-ACTIONS")
        content = response.content.decode()
        self.assertIn('value="toggle"', content)
        self.assertIn('value="delete"', content)
        self.assertIn("startEdit(", content)

    # -- Pagination --

    def test_pagination_limits_per_page(self):
        for i in range(15):
            ClassificationRule.objects.create(
                owner=self.user, status="B", match_type="exact", source_text=f"PAGERULE-{i:02d}"
            )
        response = self.client.get(reverse("rules") + "?filter=own")
        content = response.content.decode()
        shown = sum(1 for i in range(15) if f"PAGERULE-{i:02d}" in content)
        self.assertEqual(shown, 12)

    def test_pagination_page_2(self):
        for i in range(15):
            ClassificationRule.objects.create(
                owner=self.user, status="B", match_type="exact", source_text=f"PG2RULE-{i:02d}"
            )
        response = self.client.get(reverse("rules") + "?filter=own&page=2")
        content = response.content.decode()
        shown = sum(1 for i in range(15) if f"PG2RULE-{i:02d}" in content)
        self.assertEqual(shown, 3)

    def test_pagination_preserves_filters(self):
        for i in range(15):
            ClassificationRule.objects.create(
                owner=self.user, status="C", match_type="exact", source_text=f"FILTPAGE-{i:02d}"
            )
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="OTHER-STATUS"
        )
        response = self.client.get(reverse("rules") + "?filter=own&status=C")
        self.assertNotContains(response, "OTHER-STATUS")
        self.assertContains(response, "page 1 of 2")

    # -- Match by line --

    def test_match_by_line_exact(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="EVIL-PROCESS.EXE"
        )
        ClassificationRule.objects.create(
            owner=self.user, status="C", match_type="exact", source_text="GOOD-PROCESS.EXE"
        )
        response = self.client.get(
            reverse("rules") + "?filter=all&q=EVIL-PROCESS.EXE&search_mode=line"
        )
        self.assertContains(response, "EVIL-PROCESS.EXE")
        self.assertNotContains(response, "GOOD-PROCESS.EXE")

    def test_match_by_line_substring(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="substring", source_text="malware-sig"
        )
        ClassificationRule.objects.create(
            owner=self.user, status="C", match_type="exact", source_text="UNRELATED-LINE"
        )
        response = self.client.get(
            reverse("rules") + "?filter=all&q=this-line-has-malware-sig-inside&search_mode=line"
        )
        self.assertContains(response, "malware-sig")
        self.assertNotContains(response, "UNRELATED-LINE")

    def test_match_by_line_no_match(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="SOME-RULE"
        )
        response = self.client.get(
            reverse("rules") + "?filter=all&q=COMPLETELY-DIFFERENT&search_mode=line"
        )
        self.assertNotContains(response, "SOME-RULE")
        self.assertContains(response, "no rules found")

    def test_match_by_line_respects_owner_filter(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="SHARED-LINE"
        )
        ClassificationRule.objects.create(
            owner=self.other, status="C", match_type="exact", source_text="SHARED-LINE"
        )
        response = self.client.get(
            reverse("rules") + "?filter=own&q=SHARED-LINE&search_mode=line"
        )
        self.assertContains(response, "SHARED-LINE")
        # Only alice's rule should have action buttons
        content = response.content.decode()
        self.assertEqual(content.count("SHARED-LINE"), content.count("SHARED-LINE"))
        self.assertNotContains(response, "bob")

    def test_text_search_mode_default(self):
        """Default search_mode=text still does text search, not line matching."""
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="substring", source_text="needle"
        )
        response = self.client.get(reverse("rules") + "?filter=own&q=needle")
        self.assertContains(response, "needle")

    # -- Sort --

    def test_default_sort_is_recently_edited(self):
        r1 = ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="FIRST-CREATED",
        )
        r2 = ClassificationRule.objects.create(
            owner=self.user, status="C", match_type="exact", source_text="SECOND-CREATED",
        )
        # Touch r1 so it has a later updated_at
        r1.description = "edited"
        r1.save(update_fields=["description", "updated_at"])

        response = self.client.get(reverse("rules"))
        content = response.content.decode()
        pos_first = content.index("FIRST-CREATED")
        pos_second = content.index("SECOND-CREATED")
        self.assertLess(pos_first, pos_second, "Recently edited rule should appear first")

    def test_sort_by_created(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="OLDER-RULE",
        )
        ClassificationRule.objects.create(
            owner=self.user, status="C", match_type="exact", source_text="NEWER-RULE",
        )
        response = self.client.get(reverse("rules") + "?sort=created")
        content = response.content.decode()
        pos_newer = content.index("NEWER-RULE")
        pos_older = content.index("OLDER-RULE")
        self.assertLess(pos_newer, pos_older, "Most recently created rule should appear first")

    def test_sort_by_status(self):
        ClassificationRule.objects.create(
            owner=self.user, status="C", match_type="exact", source_text="CLEAN-RULE",
        )
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="MALWARE-RULE",
        )
        response = self.client.get(reverse("rules") + "?sort=status")
        content = response.content.decode()
        pos_malware = content.index("MALWARE-RULE")
        pos_clean = content.index("CLEAN-RULE")
        self.assertLess(pos_malware, pos_clean, "Status B should appear before C in status sort")

    def test_sort_preserved_in_context(self):
        response = self.client.get(reverse("rules") + "?sort=created")
        self.assertEqual(response.context["sort"], "created")

    def test_invalid_sort_falls_back_to_recent(self):
        ClassificationRule.objects.create(
            owner=self.user, status="B", match_type="exact", source_text="SOME-RULE",
        )
        response = self.client.get(reverse("rules") + "?sort=bogus")
        self.assertEqual(response.status_code, 200)

    # -- Add rule link visible on all tabs --

    def test_add_rule_link_visible_on_own_tab(self):
        response = self.client.get(reverse("rules") + "?filter=own")
        self.assertContains(response, reverse("add_rule"))

    def test_add_rule_link_visible_on_others_tab(self):
        response = self.client.get(reverse("rules") + "?filter=others")
        self.assertContains(response, reverse("add_rule"))

    def test_add_rule_link_visible_on_all_tab(self):
        response = self.client.get(reverse("rules") + "?filter=all")
        self.assertContains(response, reverse("add_rule"))
