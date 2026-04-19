from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule
from .factories import make_user, make_rule


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

    # -- rules.html links to add page --

    def test_rules_page_links_to_add_rule(self):
        response = self.client.get(reverse("rules"))
        self.assertContains(response, reverse("add_rule"))
