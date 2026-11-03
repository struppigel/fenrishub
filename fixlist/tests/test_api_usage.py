"""Tests for the moderator API usage pages and API log retention."""

from datetime import timedelta

from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from ..models import ApiRequestLog, ApiToken
from ..views.guest import MODERATOR_GROUP_NAME
from ..views.utils import _purge_old_trash
from .factories import make_user


def make_moderator(username='mod'):
    user = make_user(username)
    group, _ = Group.objects.get_or_create(name=MODERATOR_GROUP_NAME)
    user.groups.add(group)
    return user


def log_request(user, token=None, *, endpoint='api_v1_upload', target='amber-falcon',
                status_code=200, response_bytes=100, count=1, age=None, **extra):
    row = ApiRequestLog.objects.create(
        user=user, token=token, endpoint=endpoint, target=target,
        status_code=status_code, response_bytes=response_bytes, count=count, **extra,
    )
    if age is not None:
        ApiRequestLog.objects.filter(pk=row.pk).update(created_at=timezone.now() - age)
    return row


class ApiUsageAccessTests(TestCase):
    def test_regular_user_gets_403(self):
        self.client.force_login(make_user('alice'))
        self.assertEqual(self.client.get(reverse('api_usage')).status_code, 403)
        self.assertEqual(self.client.get(reverse('api_usage_user', args=[1])).status_code, 403)

    def test_moderator_gets_200(self):
        self.client.force_login(make_moderator())
        self.assertEqual(self.client.get(reverse('api_usage')).status_code, 200)


class ApiUsageStatsTests(TestCase):
    def setUp(self):
        self.moderator = make_moderator()
        self.client.force_login(self.moderator)
        self.alice = make_user('alice')
        self.token, _ = ApiToken.issue(self.alice, 'laptop')

    def _row_for(self, response, username):
        return next(row for row in response.context['rows'] if row['username'] == username)

    def test_aggregates(self):
        log_request(self.alice, self.token, target='a-one')
        log_request(self.alice, self.token, target='a-one')
        log_request(self.alice, self.token, target='a-two')
        log_request(self.alice, self.token, endpoint='api_v1_uploads', target='', status_code=429)
        log_request(self.alice, self.token, target='a-old', age=timedelta(days=3))

        row = self._row_for(self.client.get(reverse('api_usage')), 'alice')
        self.assertEqual(row['requests_24h'], 4)
        self.assertEqual(row['requests_7d'], 5)
        self.assertEqual(row['uploads_24h'], 2)
        self.assertEqual(row['limited_24h'], 1)
        self.assertEqual(row['active_tokens'], 1)

    def test_user_with_token_but_no_requests_is_listed(self):
        row = self._row_for(self.client.get(reverse('api_usage')), 'alice')
        self.assertEqual(row['requests_24h'], 0)
        self.assertEqual(row['flags'], [])

    @override_settings(API_RATE_LIMIT_PER_DAY=10)
    def test_high_usage_flag(self):
        log_request(self.alice, self.token, count=6)
        response = self.client.get(reverse('api_usage'))
        self.assertTrue(self._row_for(response, 'alice')['flags'])
        self.assertContains(response, 'high usage')

    def test_failed_auth_grouped_by_ip(self):
        log_request(None, endpoint='api_v1_uploads', target='', status_code=401, count=7, ip_address='203.0.113.9')
        response = self.client.get(reverse('api_usage'))
        self.assertEqual(response.context['failed_auth'][0]['attempts'], 7)

    def test_user_agent_is_escaped_on_drilldown(self):
        log_request(self.alice, self.token, user_agent='<script>alert(1)</script>')
        response = self.client.get(reverse('api_usage_user', args=[self.alice.pk]))
        self.assertNotContains(response, '<script>alert(1)</script>')
        self.assertContains(response, '&lt;script&gt;alert(1)&lt;/script&gt;')

    def test_moderator_revokes_token(self):
        self.client.post(
            reverse('api_usage_user', args=[self.alice.pk]),
            {'action': 'revoke', 'token_id': self.token.pk},
        )
        self.token.refresh_from_db()
        self.assertIsNotNone(self.token.revoked_at)
        self.assertEqual(self.token.revoked_by, self.moderator)

    def test_moderator_revoke_is_scoped_to_subject(self):
        bob_token, _ = ApiToken.issue(make_user('bob'), 'bob laptop')
        self.client.post(
            reverse('api_usage_user', args=[self.alice.pk]),
            {'action': 'revoke', 'token_id': bob_token.pk},
        )
        bob_token.refresh_from_db()
        self.assertIsNone(bob_token.revoked_at)


class ApiLogRetentionTests(TestCase):
    @override_settings(API_LOG_RETENTION_DAYS=90)
    def test_purge_removes_old_api_logs(self):
        user = make_user('alice')
        old = log_request(user, age=timedelta(days=91))
        recent = log_request(user, age=timedelta(days=89))
        _purge_old_trash()
        self.assertFalse(ApiRequestLog.objects.filter(pk=old.pk).exists())
        self.assertTrue(ApiRequestLog.objects.filter(pk=recent.pk).exists())
