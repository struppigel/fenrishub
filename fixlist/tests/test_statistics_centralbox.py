from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from ..models import (
    CentralboxAutoQueue, CentralboxFreshLookup, CentralboxUsageMinute, HashAlias, HashVerdict, UploadedLog,
    UploadedLogFileHash,
)


def sha(n):
    return f'{n:064x}'


def md5(n):
    return f'{n:032x}'


class CentralboxStatsTestCase(TestCase):
    def setUp(self):
        self.helper = User.objects.create_user(username='alice', password='pw')
        self.client.force_login(self.helper)
        self.now = timezone.now()

    def get(self, **params):
        params.setdefault('tab', 'centralbox')
        return self.client.get(reverse('statistics'), params)

    def verdict(self, n, state='known', verdict='', family='', malware_type='', checked_at=None):
        checked_at = checked_at or self.now
        return HashVerdict.objects.create(
            sha256=sha(n), state=state, verdict=verdict, family=family, malware_type=malware_type,
            checked_at=checked_at, next_check_at=checked_at + timedelta(days=1),
        )

    def upload(self, days_ago=0):
        log = UploadedLog.objects.create(forum_username='user', original_filename='log.txt', content='x')
        if days_ago:
            UploadedLog.objects.filter(pk=log.pk).update(created_at=self.now - timedelta(days=days_ago))
        return log

    def file_hash(self, upload, source, sha256='', md5_value='', line_no=1):
        return UploadedLogFileHash.objects.create(
            upload=upload, sha256=sha256, md5=md5_value, line_no=line_no, anchor_line_no=line_no, source=source,
        )


class TabTests(CentralboxStatsTestCase):
    def test_anonymous_user_redirected(self):
        self.client.logout()
        response = self.get()
        self.assertEqual(response.status_code, 302)

    def test_default_tab_is_logs(self):
        response = self.client.get(reverse('statistics'))
        self.assertEqual(response.context['tab'], 'logs')
        self.assertIn('headline', response.context)
        self.assertNotIn('cb', response.context)

    def test_centralbox_tab_skips_the_log_stats(self):
        response = self.get()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['tab'], 'centralbox')
        self.assertIn('cb', response.context)
        self.assertNotIn('headline', response.context)
        self.assertContains(response, 'hashes checked')
        self.assertContains(response, '<input type="hidden" name="tab" value="centralbox">', html=True)
        self.assertContains(response, '?all=1&amp;tab=centralbox')

    def test_unknown_tab_falls_back_to_logs(self):
        response = self.get(tab='bogus')
        self.assertEqual(response.context['tab'], 'logs')

    def test_tag_choices_ride_along_on_the_centralbox_tab(self):
        response = self.get(tag_category='')
        self.assertEqual(response.context['carry_params'], [('tag_category', '')])
        self.assertContains(response, '<input type="hidden" name="tag_category" value="">', html=True)

    def test_empty_tab_shows_info_boxes_not_charts(self):
        response = self.get()
        self.assertContains(response, 'no hashes checked in the selected range.')
        self.assertNotContains(response, 'id="cbVerdictChart"')
        self.assertNotContains(response, 'id="cbFreshChart"')
        self.assertNotContains(response, 'id="cbUsageChart"')

    @override_settings(CENTRALBOX_API_KEY='cbt_secret_server_key')
    def test_api_key_is_never_shown(self):
        response = self.get()
        self.assertTrue(response.context['cb']['health']['key_set'])
        self.assertNotContains(response, 'cbt_secret_server_key')


class VerdictStatsTests(CentralboxStatsTestCase):
    def test_counts_outcomes_in_range_only(self):
        self.verdict(1, verdict='malicious', family='asyncrat', malware_type='rat')
        self.verdict(2, verdict='malicious', family='asyncrat', malware_type='rat')
        self.verdict(3, verdict='suspicious', family='', malware_type='miner')
        self.verdict(4, verdict='clean', family='ignored-clean-family')
        self.verdict(5, state='unknown')
        self.verdict(6, verdict='malicious', family='old', checked_at=self.now - timedelta(days=60))

        verdicts = self.get().context['cb']['verdicts']

        self.assertEqual(verdicts['total'], 5)
        self.assertEqual(verdicts['malicious'], 2)
        self.assertEqual(verdicts['suspicious'], 1)
        self.assertEqual(verdicts['clean'], 1)
        self.assertEqual(verdicts['unknown'], 1)
        self.assertEqual(verdicts['families'], [{'name': 'asyncrat', 'count': 2}])
        self.assertEqual(verdicts['malware_types'], [{'name': 'rat', 'count': 2}, {'name': 'miner', 'count': 1}])

    def test_series_is_per_day_with_zero_fill(self):
        self.verdict(1, verdict='malicious')
        self.verdict(2, verdict='clean', checked_at=self.now - timedelta(days=2))

        series = self.get().context['cb']['verdicts']['series']

        self.assertEqual(len(series['days']), 30)
        by_label = {s['label']: s['data'] for s in series['series']}
        self.assertEqual(list(by_label), ['malicious', 'suspicious', 'clean', 'not in centralbox'])
        self.assertEqual(by_label['malicious'][-1], 1)
        self.assertEqual(sum(by_label['malicious']), 1)
        self.assertEqual(by_label['clean'][-3], 1)
        self.assertEqual(sum(by_label['suspicious']), 0)


class FreshLookupStatsTests(CentralboxStatsTestCase):
    def lookup(self, n, user=None, auto=False, state='done', requested_at=None):
        return CentralboxFreshLookup.objects.create(
            sha256=sha(n), requested_by=user, auto=auto, state=state, requested_at=requested_at or self.now,
        )

    def test_manual_auto_states_and_requesters(self):
        bob = User.objects.create_user(username='bob', password='pw')
        gone = User.objects.create_user(username='gone', password='pw')
        self.lookup(1, user=self.helper)
        self.lookup(2, user=self.helper, state='not_found')
        self.lookup(3, user=bob, state='error')
        self.lookup(4, user=gone)
        gone.delete()
        self.lookup(5, auto=True)
        self.lookup(6, auto=True, state='running')
        self.lookup(7, auto=True, state='running', requested_at=self.now - timedelta(hours=2))
        self.lookup(8, user=self.helper, requested_at=self.now - timedelta(days=60))

        fresh = self.get().context['cb']['fresh']

        self.assertEqual((fresh['total'], fresh['manual'], fresh['auto']), (7, 4, 3))
        states = {row['state']: row['count'] for row in fresh['states']}
        self.assertEqual(states, {'done': 3, 'not_found': 1, 'error': 1, 'running': 1, 'timed out': 1})
        self.assertEqual(fresh['requesters'], [
            {'username': 'auto (Fenris)', 'count': 3},
            {'username': 'alice', 'count': 2},
            {'username': 'bob', 'count': 1},
            {'username': 'Unassigned', 'count': 1},
        ])
        series = {s['label']: s['data'] for s in fresh['series']['series']}
        self.assertEqual(sum(series['manual']), 4)
        self.assertEqual(sum(series['auto']), 3)

    def test_timed_out_state_is_left_out_when_there_is_none(self):
        self.lookup(1, user=self.helper)
        states = [row['state'] for row in self.get().context['cb']['fresh']['states']]
        self.assertNotIn('timed out', states)


class UsageStatsTests(CentralboxStatsTestCase):
    def test_last_seven_days_summed_per_day(self):
        minute = int(self.now.timestamp()) // 60
        CentralboxUsageMinute.objects.create(minute=minute, key_id='', calls=5, failures=1)
        CentralboxUsageMinute.objects.create(minute=minute - 1, key_id='', calls=7)
        CentralboxUsageMinute.objects.create(minute=minute, key_id='fresh', calls=2, failures=2)
        CentralboxUsageMinute.objects.create(minute=minute - 8 * 1440, key_id='', calls=100)

        usage = self.get(start='2000-01-01').context['cb']['usage']

        self.assertEqual((usage['reads'], usage['fresh'], usage['failures']), (12, 2, 3))
        self.assertEqual(usage['peak_reads_per_minute'], 7)
        self.assertEqual(len(usage['series']['days']), 7)
        self.assertEqual(usage['series']['days'][-1], timezone.localdate().isoformat())
        series = {s['label']: s['data'] for s in usage['series']['series']}
        self.assertEqual(sum(series['reads']), 12)
        self.assertEqual(sum(series['fresh lookups']), 2)
        self.assertEqual(sum(series['failures']), 3)


class CoverageStatsTests(CentralboxStatsTestCase):
    def test_coverage_per_source(self):
        log = self.upload()
        self.file_hash(log, 'malwarebytes', sha256=sha(1), line_no=1)
        self.file_hash(log, 'malwarebytes', sha256=sha(2), line_no=2)
        # The same hash twice in one source counts once.
        self.file_hash(log, 'malwarebytes', sha256=sha(2), line_no=3)
        self.file_hash(log, 'mau', sha256=sha(3), line_no=4)
        # MD5 resolved through centralbox's MD5 answer.
        self.file_hash(log, 'trojan_killer', md5_value=md5(1), line_no=5)
        HashAlias.objects.create(md5=md5(1), sha256=sha(4), checked_at=self.now, next_check_at=self.now)
        # MD5 centralbox did not know.
        self.file_hash(log, 'trojan_killer', md5_value=md5(2), line_no=6)
        HashAlias.objects.create(md5=md5(2), sha256='', checked_at=self.now, next_check_at=self.now)
        # MD5 never asked about.
        self.file_hash(log, 'trojan_killer', md5_value=md5(3), line_no=7)
        self.verdict(1, verdict='malicious')
        self.verdict(3, state='unknown')
        self.verdict(4, verdict='suspicious')

        old = self.upload(days_ago=60)
        self.file_hash(old, 'malwarebytes', sha256=sha(9))

        coverage = self.get().context['cb']['coverage']

        rows = {row['source']: row for row in coverage['sources']}
        self.assertEqual(set(rows), {'malwarebytes', 'mau', 'trojan_killer'})
        self.assertEqual(rows['malwarebytes']['label'], 'Malwarebytes')
        self.assertEqual(
            (rows['malwarebytes']['hashes'], rows['malwarebytes']['answered'], rows['malwarebytes']['flagged']),
            (2, 1, 1),
        )
        self.assertEqual(rows['malwarebytes']['percent'], 50.0)
        self.assertEqual((rows['mau']['hashes'], rows['mau']['answered'], rows['mau']['flagged']), (1, 1, 0))
        self.assertEqual(
            (rows['trojan_killer']['hashes'], rows['trojan_killer']['answered'], rows['trojan_killer']['flagged']),
            (3, 2, 1),
        )
        self.assertEqual(coverage['total'], {'hashes': 6, 'answered': 4, 'flagged': 2, 'percent': 66.7})


class QueueStatsTests(CentralboxStatsTestCase):
    def test_counts_per_priority(self):
        CentralboxAutoQueue.objects.create(hash=sha(1), priority=CentralboxAutoQueue.PRIORITY_SCANNER, enqueued_at=self.now)
        CentralboxAutoQueue.objects.create(hash=sha(2), priority=CentralboxAutoQueue.PRIORITY_SCANNER, enqueued_at=self.now)
        earliest = self.now - timedelta(hours=3)
        CentralboxAutoQueue.objects.create(hash=sha(3), priority=CentralboxAutoQueue.PRIORITY_MAU, enqueued_at=earliest)

        queue = self.get().context['cb']['queue']

        self.assertEqual(queue['total'], 3)
        counts = {row['priority']: row['count'] for row in queue['priorities']}
        self.assertEqual(counts, {
            CentralboxAutoQueue.PRIORITY_SCANNER: 2, CentralboxAutoQueue.PRIORITY_FRST_B: 0,
            CentralboxAutoQueue.PRIORITY_MAU: 1, CentralboxAutoQueue.PRIORITY_FRST_FLAGGED: 0,
        })
        self.assertEqual(queue['oldest'], earliest)
        self.assertFalse(queue['moving'])
