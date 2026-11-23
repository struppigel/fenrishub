"""The performance tab of /stats/ and the scan timings it reads (AnalysisTiming)."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..analyzer import invalidate_rule_buckets_cache
from ..models import AnalysisTiming, ClassificationRule, UploadedLog
from ..views.statistics_performance import _median, _percentile

LOG_CONTENT = '\n'.join(['Scan result of Farbar Recovery Scan Tool', 'line one', '', 'line two'])


class RecordingTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.owner = User.objects.create_user(username='alice', password='pw')
        ClassificationRule.objects.create(
            owner=self.owner, status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT, source_text='line one',
        )

    def upload(self, log_type='FRST', content=LOG_CONTENT):
        return UploadedLog.objects.create(
            forum_username='user', original_filename='frst.txt', content=content, log_type=log_type,
        )

    def test_analysis_records_a_timing(self):
        log = self.upload()
        AnalysisTiming.objects.all().delete()
        log.recalculate_analysis_stats()
        timing = AnalysisTiming.objects.get()
        self.assertEqual((timing.upload_id, timing.log_type), (log.upload_id, 'FRST'))
        self.assertEqual(timing.line_count, 3)
        self.assertEqual(timing.char_count, len(LOG_CONTENT))
        self.assertEqual(timing.rule_count, 1)

    def test_every_analysis_adds_a_row(self):
        log = self.upload()
        before = AnalysisTiming.objects.count()
        log.recalculate_analysis_stats()
        log.recalculate_analysis_stats()
        self.assertEqual(AnalysisTiming.objects.count(), before + 2)

    def test_rules_load_is_zero_when_cached_rules_are_current(self):
        log = self.upload()
        log.recalculate_analysis_stats()
        AnalysisTiming.objects.all().delete()
        log.recalculate_analysis_stats()
        self.assertEqual(AnalysisTiming.objects.get().rules_load_ms, 0)

    def test_logs_the_analyzer_skips_record_nothing(self):
        log = self.upload(log_type='Fixlog', content='Fix result of Farbar Recovery Scan Tool')
        AnalysisTiming.objects.all().delete()
        log.recalculate_analysis_stats()
        self.assertFalse(AnalysisTiming.objects.exists())

    def test_a_failed_timing_never_breaks_the_analysis(self):
        log = self.upload()
        with mock.patch.object(AnalysisTiming.objects, 'create', side_effect=RuntimeError('boom')), \
                self.assertLogs('fixlist.models', level='ERROR'):
            log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertEqual(log.count_malware, 1)


class PercentileTests(TestCase):
    def test_median(self):
        self.assertIsNone(_median([]))
        self.assertEqual(_median([3, 1, 2]), 2)
        self.assertEqual(_median([4, 1, 2, 3]), 2.5)

    def test_percentile_is_nearest_rank(self):
        self.assertIsNone(_percentile([], 0.9))
        self.assertEqual(_percentile([5], 0.9), 5)
        self.assertEqual(_percentile(list(range(1, 11)), 0.9), 9)
        self.assertEqual(_percentile(list(range(1, 101)), 0.9), 90)


class TabTests(TestCase):
    def setUp(self):
        self.client.force_login(User.objects.create_user(username='helper', password='pw'))
        self.now = timezone.now()

    def get(self, **params):
        params.setdefault('tab', 'performance')
        return self.client.get(reverse('statistics'), params)

    def timing(self, *, lines, ms, log_type='FRST', upload_id='', days_ago=0, rules=100, load_ms=0):
        return AnalysisTiming.objects.create(
            created_at=self.now - timedelta(days=days_ago), upload_id=upload_id, log_type=log_type,
            line_count=lines, char_count=lines * 80, rule_count=rules, duration_ms=ms, rules_load_ms=load_ms,
        )

    def test_empty_range_says_so(self):
        response = self.get()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['tab'], 'performance')
        self.assertContains(response, 'no timed scans')

    def test_headline_uses_speed_per_thousand_lines(self):
        self.timing(lines=1000, ms=100)          # 100 ms / 1k lines
        self.timing(lines=2000, ms=400)          # 200
        self.timing(lines=4000, ms=1200, load_ms=2500)    # 300
        self.timing(lines=0, ms=50)              # no lines: left out
        headline = self.get().context['perf']['headline']
        self.assertEqual(headline['scans'], 3)
        self.assertEqual(headline['median_speed'], 200.0)
        self.assertEqual(headline['p90_speed'], 300.0)
        self.assertEqual(headline['max_seconds'], 1.2)
        self.assertEqual((headline['rule_loads'], headline['median_rule_load_seconds']), (1, 2.5))

    def test_out_of_range_rows_are_left_out(self):
        self.timing(lines=1000, ms=100)
        self.timing(lines=1000, ms=900, days_ago=60)
        self.assertEqual(self.get().context['perf']['headline']['scans'], 1)

    def test_series_has_gaps_for_buckets_without_scans(self):
        self.timing(lines=1000, ms=100, days_ago=2)
        perf = self.get().context['perf']
        median = perf['speed_series']['series'][0]
        self.assertEqual(median['label'], 'median')
        self.assertEqual(len(median['data']), len(perf['speed_series']['days']))
        self.assertEqual([value for value in median['data'] if value is not None], [100.0])
        self.assertIsNone(median['data'][-1])
        self.assertEqual([v for v in perf['rule_series']['series'][0]['data'] if v is not None], [100])

    def test_per_type_table_and_chart(self):
        for log_type in ('Spor', 'Spor', 'FRST', 'Addition', 'MAU', 'ESET', 'Malwarebytes'):
            self.timing(lines=1000, ms=100, log_type=log_type)
        perf = self.get().context['perf']
        self.assertEqual(perf['types'][0]['log_type'], 'Spor')
        self.assertEqual(perf['types'][0]['scans'], 2)
        labels = [series['label'] for series in perf['type_series']['series']]
        self.assertEqual(len(labels), 6)
        self.assertEqual(labels[0], 'Spor')
        self.assertEqual(labels[-1], 'other')

    def test_slowest_link_only_live_logs(self):
        live = UploadedLog.objects.create(forum_username='u', original_filename='a.txt', content='x')
        trashed = UploadedLog.objects.create(forum_username='u', original_filename='b.txt', content='x')
        UploadedLog.objects.filter(pk=trashed.pk).move_to_trash()
        self.timing(lines=1000, ms=300, upload_id=live.upload_id)
        self.timing(lines=1000, ms=200, upload_id=trashed.upload_id)
        self.timing(lines=1000, ms=100, upload_id='gone-log')
        response = self.get()
        slowest = response.context['perf']['slowest']
        self.assertEqual([row['upload_id'] for row in slowest], [live.upload_id, trashed.upload_id, 'gone-log'])
        self.assertEqual([bool(row['url']) for row in slowest], [True, False, False])
        self.assertContains(response, reverse('view_uploaded_log', args=[live.upload_id]))

    def test_tag_choices_ride_along(self):
        response = self.get(tag_category='3', tags=['5'])
        self.assertIn(('tag_category', '3'), response.context['carry_params'])
        self.assertIn(('tags', 5), response.context['carry_params'])
