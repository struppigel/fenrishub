"""Tests for `manage.py reanalyze_logs` and the admin page that starts it in the background."""

from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..models import RuleTag, TagCategory, UploadedLog, UploadedLogAnalysis
from ..rule_sets import SHARED_RULE_SET_KEY
from .factories import make_rule


def _log(name, log_type='FRST', **extra):
    return UploadedLog.objects.create(
        forum_username='forum_user', original_filename=f'{name}.txt',
        content=f'Scan result of Farbar Recovery Scan Tool {name}', log_type=log_type, **extra,
    )


def _analysis(log, rule_ids=(), content_hash=None):
    payload = {
        'format': ANALYSIS_PAYLOAD_FORMAT,
        'lines': [{'line': 'line 0', 'rule_ids': list(rule_ids)}],
        'summary': {'total_lines': 1, 'status_counts': {}},
        'warnings': [],
        'wholelog_rule_ids': [],
    }
    UploadedLogAnalysis.objects.update_or_create(
        upload=log, rule_set_key=SHARED_RULE_SET_KEY,
        defaults={
            'payload': payload, 'tag_summary': None, 'line_tags': None,
            'source_content_hash': content_hash if content_hash is not None else log.content_hash,
        },
    )


class ReanalyzeLogsCommandTests(TestCase):
    def setUp(self):
        patcher = mock.patch('fixlist.management.commands.reanalyze_logs.lower_process_priority')
        self.lower_priority = patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, *args):
        out, err = StringIO(), StringIO()
        with mock.patch.object(UploadedLog, 'recalculate_analysis_stats', autospec=True) as recalc:
            call_command('reanalyze_logs', *args, stdout=out, stderr=err)
        return [call.args[0].pk for call in recalc.call_args_list], out.getvalue(), err.getvalue()

    def test_reanalyzes_only_logs_of_the_chosen_type(self):
        frst_a = _log('a')
        frst_b = _log('b')
        _log('c', log_type='Addition')

        pks, out, _err = self._run('--log-type', 'FRST')

        self.assertEqual(pks, [frst_a.pk, frst_b.pk])
        self.assertIn('Found 2 log(s) of type FRST.', out)
        self.assertIn('Reanalyzed 2 log(s)', out)
        self.lower_priority.assert_called_once()

    def test_skips_soft_deleted_logs(self):
        kept = _log('kept')
        _log('trashed', deleted_at=timezone.now())

        pks, _out, _err = self._run('--log-type', 'FRST')

        self.assertEqual(pks, [kept.pk])

    def test_only_untagged_skips_logs_with_any_tag(self):
        category = TagCategory.objects.create(name='family', color='#aa5555')
        noise = TagCategory.objects.create(name='noise', color='#555555', priority=0)
        tagged_rule = make_rule('C:\\miner.exe')
        tagged_rule.tags.add(RuleTag.objects.create(name='miner', category=category))
        noise_rule = make_rule('C:\\common.exe')
        noise_rule.tags.add(RuleTag.objects.create(name='common', category=noise))
        untagged_rule = make_rule('C:\\plain.exe')

        tagged = _log('tagged')
        _analysis(tagged, [tagged_rule.pk])
        # A tag of a priority-0 category is hidden on listings but is still a tag.
        noise_tagged = _log('noise')
        _analysis(noise_tagged, [noise_rule.pk])
        no_tags = _log('no-tags')
        _analysis(no_tags, [untagged_rule.pk])
        stale = _log('stale')
        _analysis(stale, [tagged_rule.pk], content_hash='outdated')
        never_analyzed = _log('never')
        UploadedLogAnalysis.objects.filter(upload=never_analyzed).delete()

        pks, out, _err = self._run('--log-type', 'FRST', '--only-untagged')

        self.assertEqual(pks, [no_tags.pk, stale.pk, never_analyzed.pk])
        self.assertIn('Found 3 log(s) of type FRST without tags.', out)

    def test_dry_run_reanalyzes_nothing(self):
        _log('a')
        _log('b')

        pks, out, _err = self._run('--log-type', 'FRST', '--dry-run')

        self.assertEqual(pks, [])
        self.assertIn('Found 2 log(s) of type FRST.', out)
        self.assertIn('dry-run', out)

    def test_failure_on_one_log_is_reported_and_the_rest_continue(self):
        first = _log('a')
        second = _log('b')
        seen = []

        def recalc(log):
            seen.append(log.pk)
            if log.pk == first.pk:
                raise RuntimeError('boom')

        out, err = StringIO(), StringIO()
        with mock.patch.object(UploadedLog, 'recalculate_analysis_stats', autospec=True, side_effect=recalc), \
                self.assertLogs('fixlist.management.commands.reanalyze_logs', level='ERROR'):
            call_command('reanalyze_logs', '--log-type', 'FRST', stdout=out, stderr=err)

        self.assertEqual(seen, [first.pk, second.pk])
        self.assertIn(f'failed for log id={first.pk}: boom', err.getvalue())
        self.assertIn('Reanalyzed 1 log(s) of type FRST, 1 failed', out.getvalue())

    def test_really_reanalyzes_the_log(self):
        log = _log('real')
        UploadedLogAnalysis.objects.filter(upload=log).delete()
        UploadedLog.objects.filter(pk=log.pk).update(total_line_count=0)

        call_command('reanalyze_logs', '--log-type', 'FRST', stdout=StringIO(), stderr=StringIO())

        log.refresh_from_db()
        self.assertEqual(log.total_line_count, 1)
        self.assertTrue(
            UploadedLogAnalysis.objects.filter(upload=log, rule_set_key=SHARED_RULE_SET_KEY).exists()
        )


class ReanalyzeAdminViewTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser(username='root', password='pw')
        self.client.force_login(self.admin)
        self.url = reverse('admin:fixlist_uploadedlog_reanalyze')
        _log('a')
        _log('b')
        _log('c', log_type='Addition')
        _log('gone', log_type='Fixlog', deleted_at=timezone.now())

    def test_changelist_links_to_the_page(self):
        response = self.client.get(reverse('admin:fixlist_uploadedlog_changelist'))
        self.assertContains(response, self.url)

    def test_get_lists_log_types_with_counts(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'FRST (2)')
        self.assertContains(response, 'Addition (1)')
        self.assertNotContains(response, 'Fixlog')

    def test_post_starts_the_background_process(self):
        with mock.patch('fixlist.admin.start_reanalysis_process', return_value=4242) as start:
            response = self.client.post(self.url, {'log_type': 'FRST', 'only_untagged': 'on'}, follow=True)

        start.assert_called_once_with('FRST', True)
        self.assertRedirects(response, reverse('admin:fixlist_uploadedlog_changelist'))
        self.assertContains(response, 'pid 4242')

    def test_post_without_untagged_flag(self):
        with mock.patch('fixlist.admin.start_reanalysis_process', return_value=1) as start:
            self.client.post(self.url, {'log_type': 'Addition'})

        start.assert_called_once_with('Addition', False)

    def test_post_with_unknown_type_starts_nothing(self):
        with mock.patch('fixlist.admin.start_reanalysis_process') as start:
            response = self.client.post(self.url, {'log_type': 'Nope'})

        start.assert_not_called()
        self.assertRedirects(response, self.url)

    def test_non_staff_user_is_sent_to_login(self):
        self.client.force_login(User.objects.create_user(username='alice', password='pw'))
        with mock.patch('fixlist.admin.start_reanalysis_process') as start:
            response = self.client.post(self.url, {'log_type': 'FRST'})

        start.assert_not_called()
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('admin:login'), response['Location'])
