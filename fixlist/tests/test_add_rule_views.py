from django.test import TestCase
from django.urls import reverse

from ..analyzer import invalidate_rule_buckets_cache
from ..models import ClassificationRule
from .factories import make_rule, make_superuser, make_user


class AddRuleViewTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.login(username="alice", password="password123")

    # -- Page rendering --

    def test_add_rule_page_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("add_rule"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_add_rule_page_renders(self):
        response = self.client.get(reverse("add_rule"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "add rule")
        self.assertContains(response, "log lines")

    def test_add_rule_page_has_form_fields(self):
        response = self.client.get(reverse("add_rule"))
        self.assertContains(response, 'id="ruleStatus"')
        self.assertContains(response, 'id="ruleMatchType"')
        self.assertContains(response, 'id="ruleSourceText"')
        self.assertContains(response, 'id="logLinesInput"')

    # -- Create via add_rule_view --

    def test_create_rule(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "MALICIOUS-LINE",
                "description": "test rule",
            },
        )
        self.assertRedirects(
            response,
            f"{reverse('add_rule')}?status={ClassificationRule.STATUS_MALWARE}&match_type={ClassificationRule.MATCH_EXACT}",
        )
        rule = ClassificationRule.objects.get(source_text="MALICIOUS-LINE")
        self.assertEqual(rule.owner, self.user)
        self.assertEqual(rule.status, ClassificationRule.STATUS_MALWARE)
        self.assertEqual(rule.match_type, ClassificationRule.MATCH_EXACT)
        self.assertEqual(rule.description, "test rule")
        self.assertTrue(rule.is_enabled)

    def test_create_rule_with_alert_status(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_ALERT,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "ALERT-ONLY-LINE",
                "description": "Alert description",
            },
        )

        self.assertRedirects(
            response,
            f"{reverse('add_rule')}?status={ClassificationRule.STATUS_ALERT}&match_type={ClassificationRule.MATCH_EXACT}",
        )
        rule = ClassificationRule.objects.get(source_text="ALERT-ONLY-LINE")
        self.assertEqual(rule.status, ClassificationRule.STATUS_ALERT)

    def test_create_rule_stays_on_add_page_with_settings_preserved_and_text_fields_cleared(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_PUP,
                "match_type": ClassificationRule.MATCH_SUBSTRING,
                "source_text": "TEMP-SOURCE",
                "description": "TEMP-DESC",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request["PATH_INFO"], reverse("add_rule"))
        self.assertEqual(response.context["form_status"], ClassificationRule.STATUS_PUP)
        self.assertEqual(response.context["form_match_type"], ClassificationRule.MATCH_SUBSTRING)
        self.assertEqual(response.context["form_source_text"], "")
        self.assertEqual(response.context["form_description"], "")

    def test_create_rule_requires_source_text(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_rule_rejects_invalid_status(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": "X",
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "some-line",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_rule_rejects_invalid_match_type(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": "invalid",
                "source_text": "some-line",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_create_rule_rejects_duplicate(self):
        make_rule("DUP-LINE", owner=self.user)
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_EXACT,
                "source_text": "DUP-LINE",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.filter(source_text="DUP-LINE").count(), 1)

    # -- Bulk create from multi-line source_text --

    def test_create_multiple_rules_from_multiline_source(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_SUBSTRING,
                "source_text": "pattern-one\npattern-two\npattern-three",
                "description": "shared description",
            },
        )
        self.assertEqual(response.status_code, 302)
        rules = ClassificationRule.objects.filter(owner=self.user).order_by("source_text")
        self.assertEqual(rules.count(), 3)
        for rule in rules:
            self.assertEqual(rule.status, ClassificationRule.STATUS_MALWARE)
            self.assertEqual(rule.match_type, ClassificationRule.MATCH_SUBSTRING)
            self.assertEqual(rule.description, "shared description")
        self.assertSetEqual(
            set(rules.values_list("source_text", flat=True)),
            {"pattern-one", "pattern-two", "pattern-three"},
        )

    def test_create_multiple_rules_skips_duplicates(self):
        make_rule(
            "pattern-one",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_SUBSTRING,
        )
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_SUBSTRING,
                "source_text": "pattern-one\npattern-two\npattern-three\npattern-four",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.filter(owner=self.user).count(), 4)
        body = response.content.decode()
        self.assertIn("3 rules created", body)
        self.assertIn("1 duplicate", body)

    def test_create_multiple_rules_dedupes_within_submit(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_SUBSTRING,
                "source_text": "same-pattern\nsame-pattern\nsame-pattern",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ClassificationRule.objects.filter(source_text="same-pattern").count(), 1)

    def test_create_multiple_rules_strips_blank_lines(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_SUBSTRING,
                "source_text": "alpha\n\n   \nbeta\n\ngamma\n",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertSetEqual(
            set(ClassificationRule.objects.filter(owner=self.user).values_list("source_text", flat=True)),
            {"alpha", "beta", "gamma"},
        )

    def test_create_multiple_rules_handles_crlf(self):
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_SUBSTRING,
                "source_text": "alpha\r\nbeta\r\ngamma\r\n",
            },
        )
        self.assertEqual(response.status_code, 302)
        sources = set(ClassificationRule.objects.filter(owner=self.user).values_list("source_text", flat=True))
        self.assertSetEqual(sources, {"alpha", "beta", "gamma"})
        for source in sources:
            self.assertFalse(source.endswith("\r"))

    def test_create_multiple_rules_all_duplicates_stays_on_form(self):
        make_rule(
            "alpha",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_SUBSTRING,
        )
        make_rule(
            "beta",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_SUBSTRING,
        )
        response = self.client.post(
            reverse("add_rule"),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_SUBSTRING,
                "source_text": "alpha\nbeta",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ClassificationRule.objects.filter(owner=self.user).count(), 2)

    # -- rules.html links to add page --

    def test_rules_page_links_to_add_rule(self):
        response = self.client.get(reverse("rules"))
        self.assertContains(response, reverse("add_rule"))

    def test_add_page_is_not_in_edit_mode(self):
        response = self.client.get(reverse("add_rule"))
        self.assertFalse(response.context["editing"])
        self.assertContains(response, "add rule")
        self.assertContains(response, "auto from match type")
        # New rules are always enabled, so the add form has no such field.
        self.assertNotContains(response, 'id="ruleIsEnabled"')


class EditRuleViewTests(TestCase):
    """The full-page editor, which reuses add_rule.html with `editing=True`."""

    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        self.user = make_user()
        self.client.login(username="alice", password="password123")
        self.rule = make_rule(
            "EDIT-ME",
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            description="before",
        )

    def _url(self):
        return reverse("edit_rule", args=[self.rule.pk])

    def _post_body(self, **overrides):
        body = {
            "status": ClassificationRule.STATUS_PUP,
            "match_type": ClassificationRule.MATCH_SUBSTRING,
            "source_text": "EDITED",
            "description": "after",
            "is_enabled": "on",
            "priority": str(self.rule.priority),
        }
        body.update(overrides)
        return body

    # -- Rendering --

    def test_edit_page_requires_login(self):
        self.client.logout()
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_edit_page_renders_the_add_form_with_the_test_panel(self):
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["editing"])
        self.assertContains(response, "edit rule")
        # The whole point: the same line-testing panel the add page has.
        self.assertContains(response, 'id="logLinesInput"')
        self.assertContains(response, 'id="ruleSourceText"')
        self.assertContains(response, 'id="ruleIsEnabled"')
        self.assertContains(response, "EDIT-ME")

    def test_edit_page_excludes_the_edited_rule_from_its_own_preview(self):
        response = self.client.get(self._url())
        self.assertContains(response, f"const EXCLUDE_RULE_ID = {self.rule.pk};")

    def test_edit_page_hides_the_auto_priority_option(self):
        # Picking "auto" would silently discard a hand-tuned priority.
        response = self.client.get(self._url())
        self.assertNotContains(response, "auto from match type")

    def test_edit_page_preselects_priority_as_a_string(self):
        # An int would never compare equal to the str-keyed priority choices, so the
        # select would render unselected and the page's JS would overwrite the rule's
        # priority with the match-type default.
        response = self.client.get(self._url())
        self.assertEqual(response.context["form_priority"], str(self.rule.priority))
        self.assertContains(response, f'<option value="{self.rule.priority}" selected')

    def test_warns_when_the_rule_holds_a_status_the_user_cannot_assign(self):
        # `?` rules are not supposed to exist, so the editor says so rather than
        # quietly offering `?` as a choice. Without an option to select, the browser
        # falls back to the first one and saving would rewrite the status.
        rule = make_rule("ODD-STATUS", owner=self.user, status="?")
        response = self.client.get(reverse("edit_rule", args=[rule.pk]))
        self.assertContains(response, "cannot be assigned here")
        self.assertNotContains(response, '<option value="?"')

    def test_warns_when_the_rule_holds_a_match_type_the_user_cannot_assign(self):
        # Script rules are moderator-only; alice is not one.
        rule = make_rule(
            'result = True',
            owner=self.user,
            match_type=ClassificationRule.MATCH_SCRIPT,
        )
        response = self.client.get(reverse("edit_rule", args=[rule.pk]))
        self.assertContains(response, "which you cannot assign")

    def test_no_warning_for_an_ordinary_rule(self):
        response = self.client.get(self._url())
        self.assertNotContains(response, "cannot be assigned here")
        self.assertNotContains(response, "which you cannot assign")

    def test_cannot_open_another_users_rule(self):
        other = make_user("bob")
        rule = make_rule("BOBS-RULE", owner=other)
        response = self.client.get(reverse("edit_rule", args=[rule.pk]))
        self.assertEqual(response.status_code, 404)

    # -- Saving --

    def test_edit_updates_the_rule_without_creating_another(self):
        response = self.client.post(self._url(), self._post_body())
        self.assertRedirects(response, reverse("rules"))
        self.assertEqual(ClassificationRule.objects.count(), 1)
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.source_text, "EDITED")
        self.assertEqual(self.rule.status, ClassificationRule.STATUS_PUP)
        self.assertEqual(self.rule.match_type, ClassificationRule.MATCH_SUBSTRING)
        self.assertEqual(self.rule.description, "after")
        self.assertTrue(self.rule.is_enabled)

    def test_edit_can_disable_the_rule(self):
        self.client.post(self._url(), self._post_body(is_enabled=""))
        self.rule.refresh_from_db()
        self.assertFalse(self.rule.is_enabled)

    def test_edit_preserves_priority_when_another_field_changes(self):
        self.rule.priority = 7
        self.rule.save(update_fields=["priority"])
        self.client.post(self._url(), self._post_body(priority="7"))
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.priority, 7)

    def test_edit_keeps_a_multiline_script_as_one_rule(self):
        moderator = make_superuser("mod")
        self.client.force_login(moderator)
        rule = make_rule(
            'result = "a" in line',
            owner=moderator,
            match_type=ClassificationRule.MATCH_SCRIPT,
        )
        snippet = 'x = line.lower()\nresult = "evil" in x'
        response = self.client.post(
            reverse("edit_rule", args=[rule.pk]),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_SCRIPT,
                "source_text": snippet,
                "is_enabled": "on",
                "priority": str(rule.priority),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            ClassificationRule.objects.filter(owner=moderator).count(), 1
        )
        rule.refresh_from_db()
        self.assertEqual(rule.source_text, snippet)

    def test_edit_rejects_multiline_source_text(self):
        # One edit saves one rule, so the line breaks would end up inside a single
        # source_text and that rule would never match a real log line.
        response = self.client.post(
            self._url(), self._post_body(source_text="first-line\nsecond-line")
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "matches a single line")
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.source_text, "EDIT-ME")

    def test_edit_rejects_multiline_source_text_pasted_from_windows(self):
        response = self.client.post(
            self._url(), self._post_body(source_text="first-line\r\nsecond-line")
        )
        self.assertEqual(response.status_code, 200)
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.source_text, "EDIT-ME")

    def test_quick_edit_rejects_multiline_source_text(self):
        response = self.client.post(
            reverse("rules"),
            {
                **self._post_body(source_text="first-line\nsecond-line"),
                "action": "edit",
                "pk": self.rule.pk,
            },
            follow=True,
        )
        self.assertContains(response, "matches a single line")
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.source_text, "EDIT-ME")

    def test_edit_page_warns_about_line_breaks_before_saving(self):
        response = self.client.get(self._url())
        self.assertContains(response, 'id="ruleMultilineWarning"')

    def test_add_page_has_no_multiline_warning(self):
        # The add page deliberately creates one rule per line.
        response = self.client.get(reverse("add_rule"))
        self.assertNotContains(response, 'id="ruleMultilineWarning"')

    def test_edit_rejects_a_duplicate_and_keeps_the_typed_text(self):
        make_rule(
            "TAKEN",
            owner=self.user,
            status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_SUBSTRING,
        )
        response = self.client.post(self._url(), self._post_body(source_text="TAKEN"))
        self.assertEqual(response.status_code, 200)
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.source_text, "EDIT-ME")
        self.assertEqual(response.context["form_source_text"], "TAKEN")

    def test_edit_refreshes_parsed_metadata(self):
        rule = make_rule(
            r"C:\ProgramData\Old\old.exe",
            owner=self.user,
            match_type=ClassificationRule.MATCH_FILEPATH,
            filepath=r"C:\ProgramData\Old\old.exe",
            normalized_filepath=r"c:\programdata\old\old.exe",
        )
        self.client.post(
            reverse("edit_rule", args=[rule.pk]),
            {
                "status": ClassificationRule.STATUS_MALWARE,
                "match_type": ClassificationRule.MATCH_FILEPATH,
                "source_text": r"C:\ProgramData\New\new.exe",
                "is_enabled": "on",
                "priority": str(rule.priority),
            },
        )
        rule.refresh_from_db()
        # Stale metadata would leave the rule matching the old path forever.
        self.assertEqual(rule.filepath, r"C:\ProgramData\New\new.exe")
        self.assertEqual(rule.normalized_filepath, r"c:\programdata\new\new.exe")

    # -- return_q round trip --

    def test_save_returns_to_the_filtered_list(self):
        query = "filter=own&status=B"
        response = self.client.post(self._url(), self._post_body(return_q=query))
        self.assertRedirects(response, f"{reverse('rules')}?{query}")

    def test_hostile_return_q_falls_back_to_the_plain_list(self):
        response = self.client.post(self._url(), self._post_body(return_q="//evil.com"))
        self.assertRedirects(response, reverse("rules"))

    def test_cancel_link_carries_the_filter(self):
        response = self.client.get(self._url() + "?return_q=filter=own%26status=B")
        self.assertEqual(
            response.context["cancel_url"], f"{reverse('rules')}?filter=own&status=B"
        )

    # -- Hand-off from the quick edit --

    def test_open_editor_prefills_from_post_without_saving(self):
        # The browser posts the whole quick-edit form, so `action=edit` and `pk` ride
        # along too -- the editor must ignore them and not save.
        response = self.client.post(
            self._url(),
            self._post_body(
                open_editor="1",
                action="edit",
                pk=str(self.rule.pk),
                source_text="TYPED-NOT-SAVED",
            ),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["form_source_text"], "TYPED-NOT-SAVED")
        self.assertEqual(response.context["form_status"], ClassificationRule.STATUS_PUP)
        self.rule.refresh_from_db()
        self.assertEqual(self.rule.source_text, "EDIT-ME")

    def test_open_editor_carries_the_filter_into_the_cancel_link(self):
        response = self.client.post(
            self._url(), self._post_body(open_editor="1", return_q="filter=own&status=B")
        )
        self.assertEqual(
            response.context["cancel_url"], f"{reverse('rules')}?filter=own&status=B"
        )

    def test_quick_edit_panel_offers_the_full_editor(self):
        response = self.client.get(reverse("rules"))
        self.assertContains(response, 'name="open_editor"')
        self.assertContains(response, reverse("edit_rule", args=[0]))

    # -- The two editors must not drift --

    def test_quick_edit_and_full_editor_produce_the_same_rule(self):
        twin = make_rule("EDIT-ME-TOO", owner=self.user)
        body = self._post_body(source_text="SAME-RESULT")

        self.client.post(self._url(), body)
        self.client.post(
            reverse("rules"),
            {**body, "action": "edit", "pk": twin.pk, "source_text": "SAME-RESULT-2"},
        )

        self.rule.refresh_from_db()
        twin.refresh_from_db()
        fields = ("status", "match_type", "description", "is_enabled", "priority", "whole_log")
        for field in fields:
            self.assertEqual(
                getattr(self.rule, field), getattr(twin, field), f"{field} drifted"
            )
