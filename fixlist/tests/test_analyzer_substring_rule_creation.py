"""Tests for the `SUBSTRING:` prefix contract the analyzer lookup menu relies on.

The lookup menu ("create substring rule" on a highlighted extension id, IP, url
or domain) does not have its own endpoint. It posts a synthetic pending change
whose line is `SUBSTRING:<token>` to persist_pending_rule_changes_api and relies
on parse_rule_line turning that prefix into a substring rule. These tests pin
that contract down so the frontend cannot silently start producing exact-line
rules.
"""

import json

from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule, SiteConfig
from .factories import make_user


EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop'
GUEST_TOKEN = 'TestGuestToken1234567890abcdef'


def _payload(token, status=ClassificationRule.STATUS_MALWARE, change_id='lookup-rule-1'):
    """The exact shape buildSubstringRuleChange() sends from the lookup menu."""
    return {
        'pending_changes': [
            {
                'id': change_id,
                'order': 0,
                'line': f'SUBSTRING:{token}',
                'original_status': '?',
                'new_status': status,
            }
        ],
        'selected_rule_change_ids': [change_id],
        'conflict_resolutions': [],
    }


class AnalyzerSubstringRuleCreationTests(TestCase):
    def setUp(self):
        self.user = make_user(username='analyzer')
        self.url = reverse('persist_pending_rule_changes_api')

    def _post(self, payload):
        return self.client.post(
            self.url,
            data=json.dumps(payload),
            content_type='application/json',
        )

    def test_substring_prefix_creates_substring_rule_with_bare_token(self):
        self.client.force_login(self.user)

        response = self._post(_payload(EXTENSION_ID))

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body['ok'])
        self.assertEqual(body['created_rules'], 1)

        rule = ClassificationRule.objects.get(owner=self.user, source_text=EXTENSION_ID)
        self.assertEqual(rule.match_type, ClassificationRule.MATCH_SUBSTRING)
        self.assertEqual(rule.status, ClassificationRule.STATUS_MALWARE)
        # The prefix is a directive, not part of the pattern.
        self.assertNotIn('SUBSTRING:', rule.source_text)
        self.assertEqual(
            rule.priority,
            ClassificationRule.default_priority_for(ClassificationRule.MATCH_SUBSTRING),
        )

    def test_ip_and_domain_tokens_create_substring_rules(self):
        self.client.force_login(self.user)

        for token in ('185.199.108.153', 'evil.example.com', 'http://evil.example.com/a'):
            with self.subTest(token=token):
                response = self._post(_payload(token, change_id=f'lookup-rule-{token}'))

                self.assertEqual(response.status_code, 200)
                rule = ClassificationRule.objects.get(owner=self.user, source_text=token)
                self.assertEqual(rule.match_type, ClassificationRule.MATCH_SUBSTRING)

    def test_repeating_the_same_action_updates_instead_of_duplicating(self):
        self.client.force_login(self.user)

        self._post(_payload(EXTENSION_ID))
        second = self._post(_payload(EXTENSION_ID, change_id='lookup-rule-2'))

        body = second.json()
        self.assertEqual(body['created_rules'], 0)
        self.assertEqual(body['updated_rules'], 1)
        self.assertEqual(
            ClassificationRule.objects.filter(owner=self.user, source_text=EXTENSION_ID).count(),
            1,
        )

    def test_unknown_status_is_skipped(self):
        self.client.force_login(self.user)

        response = self._post(_payload(EXTENSION_ID, status='?'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['skipped_changes'], 1)
        self.assertFalse(ClassificationRule.objects.filter(source_text=EXTENSION_ID).exists())

    def test_guests_cannot_create_rules(self):
        config = SiteConfig.get_solo()
        config.guest_token = GUEST_TOKEN
        config.save()

        response = self.client.post(
            f'{self.url}?guest={GUEST_TOKEN}',
            data=json.dumps(_payload(EXTENSION_ID)),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 403)
        self.assertFalse(ClassificationRule.objects.filter(source_text=EXTENSION_ID).exists())
