from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import Fixlist, FixlistStat, UploadedLog, UploadedLogStat


def _make_fixlog_content(success=0, not_found=0, error=0):
    lines = ['Fix result of Farbar Recovery Scan Tool']
    lines += [f'item-{i} => removed successfully' for i in range(success)]
    lines += [f'item-nf-{i} => not found' for i in range(not_found)]
    lines += [f'item-err-{i} => Error something' for i in range(error)]
    return '\n'.join(lines) + '\n'


class StatSnapshotSignalTests(TestCase):
    def test_uploaded_log_save_creates_snapshot(self):
        helper = User.objects.create_user(username='alice', password='pw')

        log = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='log.txt',
            content='line one',
            created_by=helper,
        )

        snapshot = UploadedLogStat.objects.get(source_id=log.pk)
        self.assertEqual(snapshot.owner_id, helper.id)
        self.assertEqual(snapshot.owner_username, 'alice')
        self.assertEqual(snapshot.created_at, log.created_at)

    def test_anonymous_upload_snapshot_has_blank_owner(self):
        log = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='log.txt',
            content='content',
        )
        snapshot = UploadedLogStat.objects.get(source_id=log.pk)
        self.assertIsNone(snapshot.owner_id)
        self.assertEqual(snapshot.owner_username, '')

    def test_fixlog_recalculation_updates_snapshot(self):
        log = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='fixlog.txt',
            content=_make_fixlog_content(success=3, not_found=1, error=2),
            log_type='Fixlog',
        )
        log.recalculate_analysis_stats()

        snapshot = UploadedLogStat.objects.get(source_id=log.pk)
        self.assertEqual(snapshot.fixlog_success, 3)
        self.assertEqual(snapshot.fixlog_not_found, 1)
        self.assertEqual(snapshot.fixlog_error, 2)
        self.assertEqual(snapshot.fixlog_total, 6)
        self.assertEqual(snapshot.log_type, 'Fixlog')

    def test_snapshot_survives_uploaded_log_hard_delete(self):
        helper = User.objects.create_user(username='alice', password='pw')
        log = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='log.txt',
            content='line',
            created_by=helper,
        )
        log_pk = log.pk

        log.delete()

        self.assertFalse(UploadedLog.objects.filter(pk=log_pk).exists())
        self.assertTrue(UploadedLogStat.objects.filter(source_id=log_pk).exists())

    def test_fixlist_save_creates_snapshot(self):
        helper = User.objects.create_user(username='bob', password='pw')
        fixlist = Fixlist.objects.create(
            owner=helper,
            username='target',
            content='line a\nline b\n',
        )

        snapshot = FixlistStat.objects.get(source_id=fixlist.pk)
        self.assertEqual(snapshot.owner_id, helper.id)
        self.assertEqual(snapshot.owner_username, 'bob')
        self.assertEqual(snapshot.line_count, 2)

    def test_fixlist_snapshot_survives_hard_delete(self):
        helper = User.objects.create_user(username='bob', password='pw')
        fixlist = Fixlist.objects.create(
            owner=helper,
            username='target',
            content='line a',
        )
        pk = fixlist.pk

        fixlist.delete()

        self.assertFalse(Fixlist.objects.filter(pk=pk).exists())
        self.assertTrue(FixlistStat.objects.filter(source_id=pk).exists())


class StatisticsViewTests(TestCase):
    def setUp(self):
        self.helper = User.objects.create_user(username='alice', password='pw')

    def test_anonymous_user_redirected_to_login(self):
        response = self.client.get(reverse('statistics'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('login')))

    def test_authenticated_user_sees_page(self):
        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'total logs')

    def test_view_aggregates_within_default_window(self):
        UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='a.txt',
            content='x',
            created_by=self.helper,
            log_type='FRST',
        )
        UploadedLogStat.objects.filter(owner_id=self.helper.id).update(
            count_malware=4, count_pup=2, count_warning=1,
        )

        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        self.assertEqual(response.status_code, 200)

        headline = response.context['headline']
        self.assertEqual(headline['total_logs'], 1)
        self.assertEqual(headline['malware_lines'], 4)
        self.assertEqual(headline['pup_lines'], 2)
        self.assertEqual(headline['warning_lines'], 1)

    def test_date_range_filter_excludes_old_data(self):
        log = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='a.txt',
            content='x',
            created_by=self.helper,
        )
        old_dt = timezone.now() - timedelta(days=200)
        UploadedLogStat.objects.filter(source_id=log.pk).update(
            created_at=old_dt, count_malware=99,
        )

        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        self.assertEqual(response.context['headline']['total_logs'], 0)
        self.assertEqual(response.context['headline']['malware_lines'], 0)

        widened = response.client.get(
            reverse('statistics'),
            {'start': (old_dt - timedelta(days=1)).date().isoformat(),
             'end': timezone.localdate().isoformat()},
        )
        self.assertEqual(widened.context['headline']['total_logs'], 1)
        self.assertEqual(widened.context['headline']['malware_lines'], 99)

    def test_logs_grouped_by_assigned_helper(self):
        bob = User.objects.create_user(username='bob', password='pw')
        UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='a.txt',
            content='x',
            recipient_user=self.helper,
        )
        UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='b.txt',
            content='x',
            recipient_user=self.helper,
        )
        UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='c.txt',
            content='x',
            recipient_user=bob,
        )

        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        rows = {row['username']: row['count'] for row in response.context['logs_per_helper']}
        self.assertEqual(rows.get('alice'), 2)
        self.assertEqual(rows.get('bob'), 1)

    def test_logs_per_helper_series_is_per_day_with_zero_fill(self):
        bob = User.objects.create_user(username='bob', password='pw')
        log_a = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='a.txt',
            content='x',
            recipient_user=self.helper,
        )
        log_b = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='b.txt',
            content='x',
            recipient_user=bob,
        )
        target_dt = timezone.now() - timedelta(days=3)
        UploadedLogStat.objects.filter(source_id__in=[log_a.pk, log_b.pk]).update(created_at=target_dt)

        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        series_payload = response.context['logs_per_helper_series']

        self.assertEqual(len(series_payload['days']), 30)
        labels = [s['username'] for s in series_payload['series']]
        self.assertIn('alice', labels)
        self.assertIn('bob', labels)

        target_iso = timezone.localtime(target_dt).date().isoformat()
        target_index = series_payload['days'].index(target_iso)
        for s in series_payload['series']:
            self.assertEqual(len(s['data']), 30)
            if s['username'] in ('alice', 'bob'):
                self.assertEqual(s['data'][target_index], 1)
                others = [v for i, v in enumerate(s['data']) if i != target_index]
                self.assertTrue(all(v == 0 for v in others))

    def test_unassigned_uploads_bucketed(self):
        UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='a.txt',
            content='x',
        )
        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        rows = {row['username']: row['count'] for row in response.context['logs_per_helper']}
        self.assertEqual(rows.get('Unassigned'), 1)

    def test_fixlog_summary_sums_success(self):
        UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='fixlog.txt',
            content=_make_fixlog_content(success=5, not_found=2, error=1),
            created_by=self.helper,
            log_type='Fixlog',
        )
        UploadedLog.objects.last().recalculate_analysis_stats()

        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        summary = response.context['fixlog_summary']
        self.assertEqual(summary['count'], 1)
        self.assertEqual(summary['success'], 5)
        self.assertEqual(summary['not_found'], 2)
        self.assertEqual(summary['error'], 1)

    def test_mean_known_unknown_pct_averages_per_log(self):
        # Three FRST logs with known%/unknown% of 100/0, 50/50, 0/100 → mean known = 50.
        for i, (total, unknown) in enumerate([(10, 0), (10, 5), (10, 10)]):
            log = UploadedLog.objects.create(
                reddit_username='redditor',
                original_filename=f'frst-{i}.txt',
                content='x',
                created_by=self.helper,
                log_type='FRST',
            )
            UploadedLogStat.objects.filter(source_id=log.pk).update(
                total_line_count=total, count_unknown=unknown,
            )

        # A non-analyzed Fixlog should be ignored.
        fixlog_log = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='fixlog.txt',
            content='x',
            created_by=self.helper,
            log_type='Fixlog',
        )
        UploadedLogStat.objects.filter(source_id=fixlog_log.pk).update(
            total_line_count=10, count_unknown=10,
        )

        # An analyzed log with zero total_line_count must not divide by zero.
        empty_log = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='empty.txt',
            content='x',
            created_by=self.helper,
            log_type='FRST',
        )
        UploadedLogStat.objects.filter(source_id=empty_log.pk).update(
            total_line_count=0, count_unknown=0,
        )

        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        ku = response.context['known_unknown']
        self.assertEqual(ku['analyzed_log_count'], 3)
        self.assertEqual(ku['mean_known_pct'], 50.0)
        self.assertEqual(ku['mean_unknown_pct'], 50.0)

    def test_mean_known_unknown_zero_when_no_analyzed_logs(self):
        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        ku = response.context['known_unknown']
        self.assertEqual(ku['analyzed_log_count'], 0)
        self.assertEqual(ku['mean_known_pct'], 0.0)
        self.assertEqual(ku['mean_unknown_pct'], 0.0)

    def test_uploads_per_day_series_covers_full_range_with_zero_fill(self):
        log = UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='a.txt',
            content='x',
            created_by=self.helper,
        )
        # Force the snapshot's created_at to a specific day in the past 30-day window.
        target_dt = timezone.now() - timedelta(days=2)
        UploadedLogStat.objects.filter(source_id=log.pk).update(created_at=target_dt)

        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        series = response.context['uploads_per_day']

        # Default range is 30 days inclusive.
        self.assertEqual(len(series), 30)

        target_day = timezone.localtime(target_dt).date().isoformat()
        target_row = next(row for row in series if row['day'] == target_day)
        self.assertEqual(target_row['count'], 1)

        # Days other than the target should be zero.
        zero_days = [row for row in series if row['day'] != target_day]
        self.assertTrue(all(row['count'] == 0 for row in zero_days))

    def test_malware_by_log_type_returns_percentage(self):
        for i in range(3):
            UploadedLog.objects.create(
                reddit_username='redditor',
                original_filename=f'frst-{i}.txt',
                content='x',
                created_by=self.helper,
                log_type='FRST',
            )
        UploadedLog.objects.create(
            reddit_username='redditor',
            original_filename='addition.txt',
            content='x',
            created_by=self.helper,
            log_type='Addition',
        )
        UploadedLogStat.objects.filter(log_type='FRST').first() and \
            UploadedLogStat.objects.filter(log_type='FRST').update(count_malware=0)
        # Mark one of the three FRST logs as infected, plus the single Addition.
        first_frst = UploadedLogStat.objects.filter(log_type='FRST').order_by('source_id').first()
        UploadedLogStat.objects.filter(pk=first_frst.pk).update(count_malware=4)
        UploadedLogStat.objects.filter(log_type='Addition').update(count_malware=1)

        self.client.force_login(self.helper)
        response = self.client.get(reverse('statistics'))
        rows = {row['log_type']: row for row in response.context['malware_by_log_type']}

        self.assertEqual(rows['FRST']['total'], 3)
        self.assertEqual(rows['FRST']['infected'], 1)
        self.assertAlmostEqual(rows['FRST']['percent'], 33.3, places=1)

        self.assertEqual(rows['Addition']['total'], 1)
        self.assertEqual(rows['Addition']['infected'], 1)
        self.assertEqual(rows['Addition']['percent'], 100.0)

        self.assertEqual(rows['FRST&Addition']['total'], 0)
        self.assertEqual(rows['FRST&Addition']['percent'], 0.0)
