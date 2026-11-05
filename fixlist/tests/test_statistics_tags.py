"""Tests for the rule tag stats on /stats/: snapshotting, counting, filtering, backfill.

Stat rows and analyses are written by hand with chosen rule ids and warning
codes, so the analyzer never runs.
"""

import importlib
from datetime import timedelta

from django.apps import apps
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..models import (
    RuleTag, TagCategory, UploadedLog, UploadedLogAnalysis, UploadedLogStat,
    update_uploaded_log_stat_snapshot,
)
from .factories import make_rule


def _payload(line_rule_ids=(), warnings=(), wholelog_rule_ids=()):
    return {
        'format': ANALYSIS_PAYLOAD_FORMAT,
        'lines': [{'line': f'line {i}', 'rule_ids': list(ids)} for i, ids in enumerate(line_rule_ids)],
        'summary': {'total_lines': 10, 'status_counts': {}},
        'warnings': list(warnings),
        'wholelog_rule_ids': list(wholelog_rule_ids),
    }


def _log(name, log_type='FRST'):
    return UploadedLog.objects.create(
        forum_username='forum_user', original_filename=f'{name}.txt',
        content=f'Scan result of Farbar Recovery Scan Tool {name}', log_type=log_type,
    )


class StatSnapshotTagSourceTests(TestCase):
    def test_snapshot_records_rule_ids_and_warning_codes(self):
        log = _log('a')
        payload = _payload(
            line_rule_ids=[[3, 1], [], [1]],
            warnings=[{'code': 'low_memory', 'rule_ids': [7]}, {'code': ''}],
            wholelog_rule_ids=[5],
        )

        update_uploaded_log_stat_snapshot(log, payload)

        stat = UploadedLogStat.objects.get(source_id=log.pk)
        self.assertEqual(stat.rule_ids, [1, 3, 5, 7])
        self.assertEqual(stat.warning_codes, ['low_memory'])

    def test_unanalyzed_log_type_records_empty_lists(self):
        log = _log('fix', log_type='Fixlog')
        self.assertIsNone(UploadedLogStat.objects.get(source_id=log.pk).rule_ids)

        log.recalculate_analysis_stats()

        stat = UploadedLogStat.objects.get(source_id=log.pk)
        self.assertEqual(stat.rule_ids, [])
        self.assertEqual(stat.warning_codes, [])


class TagStatsViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='pw')
        self.client.force_login(self.user)
        self.family = TagCategory.objects.create(name='family', color='#aa5555')
        self.noise = TagCategory.objects.create(name='noise', color='#555555', priority=0)
        self.miner_rule = make_rule('C:\\miner.exe')
        self.adware_rule = make_rule('C:\\adware.exe')
        self.noise_rule = make_rule('C:\\common.exe')
        self.miner = RuleTag.objects.create(name='miner', category=self.family)
        self.adware = RuleTag.objects.create(name='adware')
        self.common = RuleTag.objects.create(name='common', category=self.noise)
        self.miner_rule.tags.add(self.miner)
        self.adware_rule.tags.add(self.adware)
        self.noise_rule.tags.add(self.common)
        self.low_memory = RuleTag.objects.get(builtin_code='low_memory')
        self._next_source_id = 10000

    def _stat(self, days_ago=0, rule_ids=(), codes=(), log_type='FRST', total=10, recorded=True):
        self._next_source_id += 1
        return UploadedLogStat.objects.create(
            source_id=self._next_source_id,
            log_type=log_type,
            created_at=timezone.now() - timedelta(days=days_ago),
            total_line_count=total,
            rule_ids=list(rule_ids) if recorded else None,
            warning_codes=list(codes) if recorded else None,
        )

    def _get(self, **params):
        response = self.client.get(reverse('statistics'), params)
        self.assertEqual(response.status_code, 200)
        return response

    def _rows(self, response):
        return {row['name']: row['count'] for row in response.context['tag_stats']}

    def _series(self, response):
        return {s['label']: s['data'] for s in response.context['tag_series']['series']}

    def test_counts_each_log_once_per_tag_per_bucket(self):
        self._stat(days_ago=0, rule_ids=[self.miner_rule.pk, self.adware_rule.pk])
        self._stat(days_ago=0, rule_ids=[self.miner_rule.pk])
        self._stat(days_ago=2, rule_ids=[self.miner_rule.pk])
        self._stat(days_ago=2, rule_ids=[])

        response = self._get()

        self.assertEqual(self._rows(response), {'miner': 3, 'adware': 1})
        self.assertEqual(response.context['tag_counted_count'], 4)
        miner_row = response.context['tag_stats'][0]
        self.assertEqual(miner_row['name'], 'miner')
        self.assertEqual(miner_row['percent'], 75.0)
        miner = self._series(response)['miner']
        self.assertEqual(len(miner), 30)
        self.assertEqual(miner[-1], 2)
        self.assertEqual(miner[-3], 1)
        self.assertEqual(sum(miner), 3)

    def test_builtin_tag_counts_through_its_warning_code(self):
        self._stat(codes=['low_memory'])

        self.assertEqual(self._rows(self._get()), {self.low_memory.name: 1})

    def test_rule_tagged_after_the_snapshot_counts(self):
        late_rule = make_rule('C:\\late.exe')
        self._stat(rule_ids=[late_rule.pk])
        self.assertEqual(self._rows(self._get()), {})

        late_rule.tags.add(self.adware)

        self.assertEqual(self._rows(self._get()), {'adware': 1})

    def test_deleted_log_still_counts(self):
        log = _log('gone')
        update_uploaded_log_stat_snapshot(log, _payload(line_rule_ids=[[self.miner_rule.pk]]))
        log.delete()

        self.assertEqual(self._rows(self._get()), {'miner': 1})

    def test_unanalyzed_and_out_of_range_logs_are_not_counted(self):
        self._stat(log_type='Fixlog', rule_ids=[self.miner_rule.pk])
        self._stat(total=0, rule_ids=[self.miner_rule.pk])
        self._stat(days_ago=100, rule_ids=[self.miner_rule.pk])

        response = self._get()

        self.assertEqual(self._rows(response), {})
        self.assertEqual(response.context['tag_counted_count'], 0)

    def test_priority_zero_categories_are_hidden_unless_selected(self):
        self._stat(rule_ids=[self.noise_rule.pk, self.adware_rule.pk])

        self.assertEqual(self._rows(self._get()), {'adware': 1})
        self.assertEqual(self._rows(self._get(tag_category=self.noise.pk)), {'common': 1})

    def test_category_limits_the_table_and_the_chart(self):
        self._stat(rule_ids=[self.miner_rule.pk, self.adware_rule.pk])

        response = self._get(tag_category=self.family.pk)

        self.assertEqual(self._rows(response), {'miner': 1})
        self.assertEqual(set(self._series(response)), {'miner'})
        self.assertEqual(response.context['selected_tag_category'], self.family.pk)
        self.assertContains(response, f'<option value="{self.family.pk}" selected>family</option>', html=True)

    def test_invalid_category_shows_all(self):
        self._stat(rule_ids=[self.miner_rule.pk, self.adware_rule.pk])

        response = self._get(tag_category='nope')

        self.assertIsNone(response.context['selected_tag_category'])
        self.assertEqual(self._rows(response), {'miner': 1, 'adware': 1})

    def test_chart_draws_the_ten_most_found_tags(self):
        rule_ids = []
        for i in range(12):
            rule = make_rule(f'C:\\family{i}.exe')
            rule.tags.add(RuleTag.objects.create(name=f'family{i:02d}'))
            rule_ids.append(rule.pk)
        # family00 is found in 12 logs, family01 in 11, ... family11 in 1.
        for n in range(12):
            self._stat(rule_ids=rule_ids[:12 - n])

        response = self._get()

        self.assertEqual(len(response.context['tag_stats']), 12)
        self.assertEqual(
            [s['label'] for s in response.context['tag_series']['series']],
            [f'family{i:02d}' for i in range(10)],
        )

    def test_picked_tags_replace_the_most_found_ones(self):
        self._stat(rule_ids=[self.miner_rule.pk, self.adware_rule.pk])
        unseen = RuleTag.objects.create(name='unseen')

        response = self._get(tags=[unseen.pk, self.adware.pk])

        series = response.context['tag_series']['series']
        self.assertEqual([s['label'] for s in series], ['unseen', 'adware'])
        self.assertEqual(sum(series[0]['data']), 0)
        self.assertEqual(sum(series[1]['data']), 1)
        self.assertEqual([tag['id'] for tag in response.context['selected_tags']], [unseen.pk, self.adware.pk])
        # The table still lists every found tag.
        self.assertEqual(self._rows(response), {'miner': 1, 'adware': 1})

    def test_unrecorded_snapshots_are_reported_not_counted(self):
        self._stat(recorded=False)
        self._stat(rule_ids=[self.miner_rule.pk])

        response = self._get()

        self.assertEqual(response.context['tag_unrecorded_count'], 1)
        self.assertEqual(response.context['tag_counted_count'], 1)
        self.assertContains(response, '1 analyzed log in range has no tag data')

    def test_filters_survive_the_date_form_and_all_time(self):
        response = self._get(tag_category=self.family.pk, tags=[self.miner.pk])

        self.assertContains(response, f'<input type="hidden" name="tag_category" value="{self.family.pk}">', html=True)
        self.assertContains(response, f'<input type="hidden" name="tags" value="{self.miner.pk}">', html=True)
        self.assertContains(
            response, f'?all=1&amp;tag_category={self.family.pk}&amp;tags={self.miner.pk}',
        )

    def test_page_shows_the_table_with_search_links(self):
        self._stat(rule_ids=[self.miner_rule.pk])

        response = self._get()

        self.assertContains(response, f'{reverse("log_search")}?tags={self.miner.pk}')
        self.assertContains(response, 'logs with tag, per day')


class BackfillMigrationTests(TestCase):
    def _backfill(self):
        module = importlib.import_module('fixlist.migrations.0086_uploadedlogstat_rule_ids')
        module.backfill_stat_tag_sources(apps, None)

    def test_fills_from_fresh_shared_analyses_only(self):
        fresh = _log('fresh')
        stale = _log('stale')
        private_only = _log('private')
        fixlog = _log('fix', log_type='Fixlog')
        UploadedLogAnalysis.objects.create(
            upload=fresh, rule_set_key='shared', source_content_hash=fresh.content_hash,
            payload=_payload(line_rule_ids=[[4], [2]], warnings=[{'code': 'low_memory', 'rule_ids': [9]}]),
        )
        UploadedLogAnalysis.objects.create(
            upload=stale, rule_set_key='shared', source_content_hash='outdated',
            payload=_payload(line_rule_ids=[[4]]),
        )
        UploadedLogAnalysis.objects.create(
            upload=private_only, rule_set_key='private:1', source_content_hash=private_only.content_hash,
            payload=_payload(line_rule_ids=[[4]]),
        )
        deleted_stat = UploadedLogStat.objects.create(source_id=99999, created_at=timezone.now())

        self._backfill()

        fresh_stat = UploadedLogStat.objects.get(source_id=fresh.pk)
        self.assertEqual(fresh_stat.rule_ids, [2, 4, 9])
        self.assertEqual(fresh_stat.warning_codes, ['low_memory'])
        self.assertIsNone(UploadedLogStat.objects.get(source_id=stale.pk).rule_ids)
        self.assertIsNone(UploadedLogStat.objects.get(source_id=private_only.pk).rule_ids)
        self.assertEqual(UploadedLogStat.objects.get(source_id=fixlog.pk).rule_ids, [])
        deleted_stat.refresh_from_db()
        self.assertIsNone(deleted_stat.rule_ids)
