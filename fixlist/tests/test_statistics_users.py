"""The users tab of /stats/: the logs tab's stats counted per forum user.

Stat rows are written by hand, so the analyzer never runs.
"""

import importlib
from datetime import timedelta

from django.apps import apps
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import Fixlist, FixlistStat, RuleTag, TagCategory, UploadedLogStat
from .factories import make_rule, make_uploaded_log


def make_fixlist(owner, username):
    return Fixlist.objects.create(owner=owner, username=username, content='CloseProcesses:')


class StatUsernameSnapshotTests(TestCase):
    def test_log_snapshot_keys_the_forum_username_and_follows_a_rename(self):
        log = make_uploaded_log('a', forum_username='  Bob ')
        self.assertEqual(UploadedLogStat.objects.get(source_id=log.pk).forum_username, 'bob')

        log.forum_username = 'Robert'
        log.save(update_fields=['forum_username'])

        self.assertEqual(UploadedLogStat.objects.get(source_id=log.pk).forum_username, 'robert')

    def test_fixlist_snapshot_keys_the_username(self):
        fixlist = make_fixlist(User.objects.create_user(username='helper'), username='Bob')
        self.assertEqual(FixlistStat.objects.get(source_id=fixlist.pk).username, 'bob')


class UsersTabTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='pw')
        self.client.force_login(self.user)
        self.family = TagCategory.objects.create(name='family', color='#aa5555', priority=7)
        self.miner_rule = make_rule('C:\\miner.exe')
        self.miner = RuleTag.objects.create(name='miner', category=self.family)
        self.miner_rule.tags.add(self.miner)
        self._next_source_id = 10000

    def _stat(self, user, days_ago=0, rule_ids=(), log_type='FRST', recipient='', **counts):
        self._next_source_id += 1
        return UploadedLogStat.objects.create(
            source_id=self._next_source_id, forum_username=user, log_type=log_type, recipient_username=recipient,
            created_at=timezone.now() - timedelta(days=days_ago), total_line_count=10,
            rule_ids=list(rule_ids), warning_codes=[], **counts,
        )

    def _fixlist(self, user, days_ago=0):
        self._next_source_id += 1
        return FixlistStat.objects.create(
            source_id=self._next_source_id, username=user, created_at=timezone.now() - timedelta(days=days_ago),
        )

    def _get(self, **params):
        params.setdefault('tab', 'users')
        params.setdefault('tag_category', '')
        response = self.client.get(reverse('statistics'), params)
        self.assertEqual(response.status_code, 200)
        return response

    def _series(self, data):
        return {s['label']: s['data'] for s in data['series']}

    def test_users_count_once_per_bucket_and_in_range(self):
        self._stat('bob')
        self._stat('bob')
        self._stat('bob', days_ago=2)
        self._stat('carol', days_ago=2)

        response = self._get()

        self.assertEqual(response.context['tab'], 'users')
        self.assertEqual(response.context['users_headline']['users'], 2)
        users = self._series(response.context['users_series'])['users']
        self.assertEqual((users[-1], users[-3], sum(users)), (1, 2, 3))

    def test_unknown_users_are_reported_not_counted(self):
        self._stat('')
        self._stat('bob')

        response = self._get()

        self.assertEqual(response.context['users_headline']['users'], 1)
        self.assertEqual(response.context['unknown_user_logs'], 1)
        self.assertContains(response, '1 log in range has no known forum user')

    def test_new_users_are_those_whose_first_log_is_in_range(self):
        self._stat('old', days_ago=100)
        self._stat('old')
        self._stat('fresh', days_ago=1)
        self._stat('fresh')

        response = self._get()

        self.assertEqual(response.context['users_headline']['new_users'], 1)
        new = self._series(response.context['users_series'])['new users']
        self.assertEqual((new[-2], sum(new)), (1, 1))

    def test_line_status_users(self):
        self._stat('bob', count_malware=2)
        self._stat('bob', count_pup=1)
        self._stat('carol', count_warning=3)
        self._stat('dave')

        headline = self._get().context['users_headline']

        self.assertEqual((headline['malware_users'], headline['pup_users'], headline['warning_users']), (1, 1, 1))

    def test_tags_count_users_not_logs(self):
        self._stat('bob', rule_ids=[self.miner_rule.pk])
        self._stat('bob', rule_ids=[self.miner_rule.pk])
        self._stat('bob', days_ago=2, rule_ids=[self.miner_rule.pk])
        self._stat('carol')

        response = self._get()

        [row] = response.context['tag_stats']
        self.assertEqual((row['name'], row['count'], row['percent']), ('miner', 1, 50.0))
        self.assertEqual(response.context['tag_counted_count'], 2)
        miner = self._series(response.context['tag_series'])['miner']
        self.assertEqual((miner[-1], miner[-3]), (1, 1))
        self.assertContains(response, 'users with tag, per day')

    def test_logs_tab_tags_still_count_logs(self):
        self._stat('bob', rule_ids=[self.miner_rule.pk])
        self._stat('bob', rule_ids=[self.miner_rule.pk])

        response = self._get(tab='logs')

        self.assertEqual(response.context['tag_stats'][0]['count'], 2)

    def test_logs_per_user(self):
        for _ in range(3):
            self._stat('bob', days_ago=4)
        self._stat('bob')
        self._stat('carol')

        stats = self._get().context['logs_per_user']

        self.assertEqual({g['label']: g['count'] for g in stats['groups']}, {'1': 1, '2': 0, '3-5': 1, '6-10': 0, '11+': 0})
        self.assertEqual((stats['mean'], stats['median'], stats['returning']), (2.5, 2.5, 1))
        self.assertEqual(stats['median_span_days'], 4)

    def test_cleanup_reach(self):
        self._stat('bob')
        self._stat('bob', log_type='Fixlog')
        self._stat('carol')
        self._fixlist('bob')
        self._fixlist('carol')
        self._fixlist('nobody-with-logs')

        cleanup = self._get().context['users_cleanup']

        self.assertEqual((cleanup['with_fixlist'], cleanup['with_fixlist_pct']), (2, 100.0))
        self.assertEqual((cleanup['with_fixlog'], cleanup['with_fixlog_pct']), (1, 50.0))

    def test_users_per_helper(self):
        self._stat('bob', recipient='helper1')
        self._stat('bob', recipient='helper1')
        self._stat('carol', recipient='helper1')
        self._stat('dave')

        response = self._get()

        self.assertEqual(
            [(r['username'], r['count']) for r in response.context['users_per_helper']],
            [('helper1', 2), ('Unassigned', 1)],
        )
        series = {s['username']: s['data'] for s in response.context['users_per_helper_series']['series']}
        self.assertEqual(series['helper1'][-1], 2)

    def _helper_days(self, response, helper='helper1'):
        series = {s['username']: s['data'] for s in response.context['users_per_helper_series']['series']}
        return series.get(helper, [0] * len(response.context['users_per_helper_series']['days']))

    def _range(self, start_days_ago, end_days_ago):
        today = timezone.localdate()
        return {
            'start': (today - timedelta(days=start_days_ago)).isoformat(),
            'end': (today - timedelta(days=end_days_ago)).isoformat(),
        }

    def test_a_case_stays_open_between_logs(self):
        self._stat('bob', days_ago=6, recipient='helper1')
        self._stat('bob', days_ago=2, recipient='helper1')

        days = self._helper_days(self._get())

        # Index -1 is today: open from 6 to 2 days ago, closed since.
        self.assertEqual(days[-7:], [1, 1, 1, 1, 1, 0, 0])

    def test_a_long_gap_ends_the_case(self):
        self._stat('bob', days_ago=25, recipient='helper1')
        self._stat('bob', days_ago=2, recipient='helper1')

        days = self._helper_days(self._get())

        self.assertEqual((days[-26], days[-15], days[-3]), (1, 0, 1))
        self.assertEqual(sum(days), 2)

    def test_a_log_before_the_range_keeps_the_case_open_into_it(self):
        self._stat('bob', days_ago=15, recipient='helper1')
        self._stat('bob', days_ago=5, recipient='helper1')

        response = self._get(**self._range(10, 0))

        self.assertEqual(self._helper_days(response)[:6], [1] * 6)

    def test_a_log_after_the_range_bridges_its_last_days(self):
        self._stat('bob', days_ago=10, recipient='helper1')
        self._stat('bob', days_ago=1, recipient='helper1')

        response = self._get(**self._range(12, 4))

        days = self._helper_days(response)
        self.assertEqual((days[0], days[2], days[-1]), (0, 1, 1))

    def test_a_case_open_without_a_log_in_the_range_is_in_the_table(self):
        self._stat('bob', days_ago=12, recipient='helper1')
        self._stat('bob', days_ago=1, recipient='helper1')

        response = self._get(**self._range(8, 4))

        self.assertEqual([(r['username'], r['count']) for r in response.context['users_per_helper']], [('helper1', 1)])
        self.assertEqual(response.context['users_headline']['users'], 0)

    def test_blank_helpers_collapse_without_counting_a_user_twice(self):
        self._stat('bob', recipient='')
        self._stat('bob', recipient='  ')

        response = self._get()

        self.assertEqual([(r['username'], r['count']) for r in response.context['users_per_helper']], [('Unassigned', 1)])
        series = {s['username']: s['data'] for s in response.context['users_per_helper_series']['series']}
        self.assertEqual(series['Unassigned'][-1], 1)

    def test_a_fixlist_after_the_range_end_still_counts(self):
        self._stat('bob', days_ago=5)
        self._fixlist('bob', days_ago=1)
        end = (timezone.localdate() - timedelta(days=3)).isoformat()
        start = (timezone.localdate() - timedelta(days=10)).isoformat()

        cleanup = self._get(start=start, end=end).context['users_cleanup']

        self.assertEqual(cleanup['with_fixlist'], 1)

    def test_top_users(self):
        self._stat('bob', days_ago=3)
        self._stat('bob')
        self._stat('carol')
        self._fixlist('bob')

        top = self._get().context['top_users']

        self.assertEqual([(r['username'], r['logs'], r['fixlists']) for r in top], [('bob', 2, 1), ('carol', 1, 0)])
        self.assertLess(top[0]['first'], top[0]['last'])

    def test_tab_keeps_range_and_tag_choices(self):
        response = self._get(tag_category=self.family.pk, tags=[self.miner.pk])

        self.assertContains(response, '<input type="hidden" name="tab" value="users">', html=True)
        self.assertContains(response, f'?all=1&amp;tab=users&amp;tag_category={self.family.pk}&amp;tags={self.miner.pk}')
        self.assertContains(response, f'?tab=users&amp;start=')


class StatUsernameMigrationTests(TestCase):
    def test_backfills_existing_logs_and_fixlists(self):
        log = make_uploaded_log('a', forum_username='\tBob ')
        accented = make_uploaded_log('b', forum_username='ÄNNA')
        fixlist = make_fixlist(User.objects.create_user(username='helper'), username='Carol')
        UploadedLogStat.objects.update(forum_username='')
        FixlistStat.objects.update(username='')
        gone = UploadedLogStat.objects.create(source_id=99999, created_at=timezone.now())

        importlib.import_module('fixlist.migrations.0112_stat_usernames').backfill_stat_usernames(apps, None)

        # The same key new snapshots get (stat_username), not the database's TRIM / LOWER.
        self.assertEqual(UploadedLogStat.objects.get(source_id=log.pk).forum_username, 'bob')
        self.assertEqual(UploadedLogStat.objects.get(source_id=accented.pk).forum_username, 'änna')
        self.assertEqual(FixlistStat.objects.get(source_id=fixlist.pk).username, 'carol')
        gone.refresh_from_db()
        self.assertEqual(gone.forum_username, '')
