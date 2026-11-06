"""Tag lookups on listings and searches read `tag_summary`, not the payload;
rule edits reach other worker processes; background refreshes coalesce.

Payloads are written by hand, so the analyzer never runs.
"""

from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from .. import analyzer, tagging
from ..models import RuleTag, SiteConfig, UploadedLogAnalysis
from ..rule_sets import SHARED_RULE_SET_KEY
from ..tagging import compute_line_tags, delete_tag, found_tags_by_upload, logs_with_tags, refresh_line_tags, tag_summary_of
from .factories import make_rule
from .test_line_tags import RENPY_PAYLOAD, LineTagSetupMixin, _line, _payload


def _selects_payload(queries):
    """Whether a captured query reads the payload column outright.

    The listing query names it only inside its CASE (taken for rows without
    a summary) and in the matching fallback filter, so it does not count.
    """
    return any(
        'payload' in query['sql'].lower() and 'case when' not in query['sql'].lower()
        for query in queries
    )


class TagSummaryTests(LineTagSetupMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.rule = make_rule('miner.exe', status='B')
        self.miner = RuleTag.objects.create(name='miner')
        self.rule.tags.add(self.miner)

    def test_saving_an_analysis_stores_its_summary(self):
        payload = _payload([_line('x', rule_ids=[self.rule.pk])], warnings=[{'code': 'low_memory'}])
        row = self._cache(self._log('a'), payload)
        self.assertEqual(row.tag_summary, tag_summary_of(payload))
        self.assertEqual(row.tag_summary['rule_ids'], [self.rule.pk])
        self.assertEqual(row.tag_summary['codes'], ['low_memory'])

    def test_listing_and_search_read_the_summary_not_the_payload(self):
        log = self._log('a')
        clean = _payload([_line('clean')])
        # Line matches are up to date, so no line tag needs the payload either.
        row = self._cache(log, clean, line_tags=compute_line_tags(clean))
        # A summary that disagrees with the payload: only it can produce the tag.
        UploadedLogAnalysis.objects.filter(pk=row.pk).update(
            tag_summary={'format': row.payload['format'], 'rule_ids': [self.rule.pk], 'codes': []},
        )
        with CaptureQueriesContext(connection) as ctx:
            found = found_tags_by_upload([log.pk], SHARED_RULE_SET_KEY)
            searched, _missed = logs_with_tags([self.miner.pk], SHARED_RULE_SET_KEY, type(log).objects.all())
        self.assertEqual([tag['name'] for tag in found[log.pk]], ['miner'])
        self.assertEqual(searched, [log.pk])
        self.assertFalse(_selects_payload(ctx.captured_queries))

    def test_row_without_summary_is_read_from_its_payload_and_backfilled(self):
        log = self._log('a')
        row = self._cache(log, _payload([_line('x', rule_ids=[self.rule.pk])]))
        UploadedLogAnalysis.objects.filter(pk=row.pk).update(tag_summary=None)
        found = found_tags_by_upload([log.pk], SHARED_RULE_SET_KEY)
        self.assertEqual([tag['name'] for tag in found[log.pk]], ['miner'])
        row.refresh_from_db()
        self.assertEqual(row.tag_summary, tag_summary_of(row.payload))

    def test_stale_format_in_summary_is_not_searched(self):
        log = self._log('a')
        row = self._cache(log, _payload([_line('x', rule_ids=[self.rule.pk])]))
        UploadedLogAnalysis.objects.filter(pk=row.pk).update(
            tag_summary={**row.tag_summary, 'format': row.payload['format'] - 1},
        )
        self.assertEqual(found_tags_by_upload([log.pk], SHARED_RULE_SET_KEY), {log.pk: []})

    def test_line_tag_still_found_when_its_matches_must_be_recomputed(self):
        log = self._log('a')
        self._cache(log, RENPY_PAYLOAD, line_tags=None)
        found = found_tags_by_upload([log.pk], SHARED_RULE_SET_KEY)
        self.assertEqual([tag['name'] for tag in found[log.pk]], ['renpy'])

    def test_deleting_a_line_tag_refreshes_without_reading_payloads(self):
        log = self._log('a')
        self._cache(log, RENPY_PAYLOAD)
        refresh_line_tags(None)
        with CaptureQueriesContext(connection) as ctx:
            delete_tag(self.renpy)
        self.assertFalse(any('"payload"' in q['sql'] for q in ctx.captured_queries))
        self.assertEqual(UploadedLogAnalysis.objects.get().line_tags['lines'], {})


class RulesVersionTests(TestCase):
    def setUp(self):
        analyzer.invalidate_rule_buckets_cache()
        self.addCleanup(analyzer.invalidate_rule_buckets_cache)

    def test_invalidating_bumps_the_shared_version(self):
        before = analyzer._current_rules_version()
        analyzer.invalidate_rule_buckets_cache(SHARED_RULE_SET_KEY)
        self.assertEqual(analyzer._current_rules_version(), before + 1)

    def test_a_bump_from_another_process_reloads_the_buckets(self):
        with mock.patch.object(analyzer, '_load_rule_buckets', side_effect=lambda key: object()) as load:
            first = analyzer._get_cached_rule_buckets(SHARED_RULE_SET_KEY)
            self.assertIs(analyzer._get_cached_rule_buckets(SHARED_RULE_SET_KEY), first)
            self.assertEqual(load.call_count, 1)
            # Another worker saved a rule: only the database row changes here.
            SiteConfig.get_solo()
            SiteConfig.objects.filter(pk=1).update(rules_version=analyzer._current_rules_version() + 1)
            self.assertIsNot(analyzer._get_cached_rule_buckets(SHARED_RULE_SET_KEY), first)
            self.assertEqual(load.call_count, 2)


class RefreshCoalescingTests(TestCase):
    def setUp(self):
        tagging._refresh_pending = None
        tagging._refresh_running = False
        self.addCleanup(setattr, tagging, '_refresh_pending', None)
        self.addCleanup(setattr, tagging, '_refresh_running', False)

    def test_requests_while_running_merge_into_one_next_run(self):
        self.assertTrue(tagging._queue_refresh([1]))
        self.assertEqual(tagging._take_queued_refresh(), (True, [1]))
        # A refresh is running now; two more saves only queue work.
        self.assertFalse(tagging._queue_refresh([2]))
        self.assertFalse(tagging._queue_refresh([3, 2]))
        self.assertEqual(tagging._take_queued_refresh(), (True, [2, 3]))
        self.assertEqual(tagging._take_queued_refresh(), (False, None))
        # Finished: the next request starts a thread again.
        self.assertTrue(tagging._queue_refresh([4]))

    def test_a_full_refresh_absorbs_tag_specific_ones(self):
        tagging._queue_refresh([1])
        tagging._queue_refresh(None)
        tagging._queue_refresh([2])
        self.assertEqual(tagging._take_queued_refresh(), (True, None))
