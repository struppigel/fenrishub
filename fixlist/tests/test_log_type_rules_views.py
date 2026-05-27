"""Tests for moderator-gated log-type-rule management views."""

import json

from django.contrib.auth.models import Group, User
from django.test import Client, TestCase
from django.urls import reverse

from fixlist.models import LogTypeDetectionRule


def _make_moderator(username='mod', password='pw'):
    user = User.objects.create_user(username=username, password=password)
    group, _ = Group.objects.get_or_create(name='moderator')
    user.groups.add(group)
    return user


class LogTypeRulesPermissionTests(TestCase):
    def test_anonymous_redirected_to_login(self):
        client = Client()
        resp = client.get(reverse('log_type_rules'))
        self.assertEqual(resp.status_code, 302)

    def test_regular_user_forbidden(self):
        User.objects.create_user(username='alice', password='pw')
        client = Client()
        client.login(username='alice', password='pw')
        resp = client.get(reverse('log_type_rules'))
        self.assertEqual(resp.status_code, 403)

    def test_moderator_can_view_list(self):
        _make_moderator()
        client = Client()
        client.login(username='mod', password='pw')
        resp = client.get(reverse('log_type_rules'))
        self.assertEqual(resp.status_code, 200)

    def test_superuser_can_view_list(self):
        User.objects.create_superuser(username='root', password='pw')
        client = Client()
        client.login(username='root', password='pw')
        resp = client.get(reverse('log_type_rules'))
        self.assertEqual(resp.status_code, 200)


class LogTypeRulesCrudTests(TestCase):
    def setUp(self):
        _make_moderator()
        self.client = Client()
        self.client.login(username='mod', password='pw')

    def test_create_rule(self):
        resp = self.client.post(reverse('add_log_type_rule'), {
            'name': 'My rule',
            'log_type': 'HitmanPro',
            'color': '#ef4444',
            'pattern': r'^XYZ marker',
            'scope': 'start',
            'priority': '42',
            'is_enabled': 'on',
        })
        self.assertEqual(resp.status_code, 302)
        rule = LogTypeDetectionRule.objects.get(name='My rule')
        self.assertEqual(rule.log_type, 'HitmanPro')
        self.assertEqual(rule.priority, 42)
        self.assertTrue(rule.is_enabled)

    def test_create_rule_with_brand_new_log_type_creates_badge(self):
        from fixlist.models import LogTypeBadge
        resp = self.client.post(reverse('add_log_type_rule'), {
            'name': 'Kaspersky detector',
            'log_type': 'Kaspersky',
            'color': '#abcdef',
            'pattern': r'^Kaspersky Anti-Virus',
            'scope': 'start',
            'priority': '60',
            'is_enabled': 'on',
        })
        self.assertEqual(resp.status_code, 302)
        rule = LogTypeDetectionRule.objects.get(name='Kaspersky detector')
        self.assertEqual(rule.log_type, 'Kaspersky')
        badge = LogTypeBadge.objects.get(name='Kaspersky')
        self.assertEqual(badge.color, '#abcdef')
        self.assertFalse(badge.is_builtin)

    def test_create_rule_rejects_invalid_color(self):
        resp = self.client.post(reverse('add_log_type_rule'), {
            'name': 'Bad color',
            'log_type': 'NewType',
            'color': 'not-a-hex',
            'pattern': r'^marker',
            'scope': 'start',
            'priority': '100',
            'is_enabled': 'on',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(LogTypeDetectionRule.objects.filter(name='Bad color').exists())

    def test_create_rule_rejects_reserved_log_type_name(self):
        resp = self.client.post(reverse('add_log_type_rule'), {
            'name': 'Reserved test',
            'log_type': 'Unknown',
            'color': '#888888',
            'pattern': r'^marker',
            'scope': 'start',
            'priority': '100',
            'is_enabled': 'on',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(LogTypeDetectionRule.objects.filter(name='Reserved test').exists())

    def test_create_rule_rejects_invalid_regex(self):
        resp = self.client.post(reverse('add_log_type_rule'), {
            'name': 'Bad',
            'log_type': 'HitmanPro',
            'color': '#ef4444',
            'pattern': r'(unclosed',
            'scope': 'full',
            'priority': '100',
            'is_enabled': 'on',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(LogTypeDetectionRule.objects.filter(name='Bad').exists())

    def test_edit_rule(self):
        rule = LogTypeDetectionRule.objects.create(
            name='Original', log_type='ESET', pattern='^foo', scope='start', priority=10,
        )
        resp = self.client.post(reverse('edit_log_type_rule', args=[rule.pk]), {
            'pk': str(rule.pk),
            'name': 'Renamed',
            'log_type': 'ESET',
            'color': '#a3e635',
            'pattern': '^bar',
            'scope': 'start',
            'priority': '15',
            'is_enabled': 'on',
        })
        self.assertEqual(resp.status_code, 302)
        rule.refresh_from_db()
        self.assertEqual(rule.name, 'Renamed')
        self.assertEqual(rule.pattern, '^bar')

    def test_delete_custom_rule(self):
        rule = LogTypeDetectionRule.objects.create(
            name='Disposable', log_type='ESET', pattern='^x', scope='start', priority=10,
        )
        resp = self.client.post(reverse('delete_log_type_rule', args=[rule.pk]))
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(LogTypeDetectionRule.objects.filter(pk=rule.pk).exists())

    def test_delete_builtin_rule_allowed(self):
        builtin = LogTypeDetectionRule.objects.filter(is_builtin=True).first()
        self.assertIsNotNone(builtin, 'seed migration should have created built-in rules')
        resp = self.client.post(reverse('delete_log_type_rule', args=[builtin.pk]))
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(LogTypeDetectionRule.objects.filter(pk=builtin.pk).exists())

    def test_toggle_rule(self):
        rule = LogTypeDetectionRule.objects.create(
            name='ToggleMe', log_type='ESET', pattern='^y', scope='start', priority=10,
        )
        self.assertTrue(rule.is_enabled)
        self.client.post(reverse('toggle_log_type_rule', args=[rule.pk]))
        rule.refresh_from_db()
        self.assertFalse(rule.is_enabled)


class LogTypeTestApiTests(TestCase):
    def setUp(self):
        _make_moderator()
        self.client = Client()
        self.client.login(username='mod', password='pw')

    def _post(self, payload):
        return self.client.post(
            reverse('test_log_type_api'),
            data=json.dumps(payload),
            content_type='application/json',
        )

    def test_match_reported(self):
        resp = self._post({'pattern': r'foo', 'content': 'this contains foo'})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data['matches'])
        self.assertEqual(data['sample'], 'foo')

    def test_no_match(self):
        resp = self._post({'pattern': r'foo', 'content': 'no match here'})
        data = resp.json()
        self.assertFalse(data['matches'])

    def test_invalid_regex_returns_400(self):
        resp = self._post({'pattern': r'(unclosed', 'content': 'whatever'})
        self.assertEqual(resp.status_code, 400)

    def test_detected_log_type_included(self):
        resp = self._post({
            'pattern': r'foo',
            'content': 'Scan result of Farbar Recovery Scan Tool\n',
        })
        data = resp.json()
        self.assertEqual(data['detected_log_type'], 'FRST')

    def test_anonymous_blocked(self):
        client = Client()
        resp = client.post(
            reverse('test_log_type_api'),
            data=json.dumps({'pattern': 'foo', 'content': 'bar'}),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 302)
