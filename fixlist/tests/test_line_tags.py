"""Tests for tags that also match log lines (RuleTag.match_log_lines).

Payloads are written by hand with chosen lines, verdicts and entry types, so
the analyzer never runs. Test regexes are plain literals (linear time).
"""

from datetime import timedelta
from io import StringIO

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT, analyze_log_text, invalidate_rule_buckets_cache
from ..models import ClassificationRule, RuleTag, UploadedLog, UploadedLogAnalysis, UploadedLogStat
from ..rule_sets import SHARED_RULE_SET_KEY
from ..tagging import (
    LineTagMatcher,
    TagConditions,
    attach_rule_tags,
    compute_line_tags,
    current_line_tags,
    delete_tag,
    first_tagged_line,
    found_tags_by_upload,
    fresh_line_tags,
    line_tag_hits,
    logs_with_tags,
    refresh_line_tags,
    save_tag,
)
from ..upload_utils import store_cached_analysis
from .factories import make_rule


def _line(text, status='?', entry_type='', rule_ids=(), parsed_entry_type=None):
    """A payload line; its own parsed entry type defaults to `entry_type`."""
    return {
        'line': text, 'dominant_status': status, 'entry_type': entry_type, 'rule_ids': list(rule_ids),
        'parsed_entry_type': entry_type if parsed_entry_type is None else parsed_entry_type,
    }


EXTENSION_LINE = (
    r"CHR Extension: (Coupon Helper) - "
    r"C:\Users\x\AppData\Local\Google\Chrome\User Data\Default"
    r"\Extensions\ghbmnnjooekpmoecnnnilnnbdlolhkhi [2026-04-01]"
)


def _payload(lines=(), warnings=()):
    return {
        'format': ANALYSIS_PAYLOAD_FORMAT,
        'lines': list(lines),
        'summary': {'total_lines': len(lines), 'status_counts': {}},
        'warnings': list(warnings),
        'wholelog_rule_ids': [],
    }


RENPY_PAYLOAD = _payload([
    _line('C:\\Games\\renpy\\launcher.exe', status='P', entry_type='process'),
    _line('C:\\Windows\\explorer.exe', status='C', entry_type='process'),
    _line('HKLM\\...\\Run: [renpy] C:\\renpy.exe', status='B', entry_type='runkey'),
])


class LineTagSetupMixin:
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='pw')
        self.renpy = RuleTag.objects.create(
            name='renpy', match_pattern='renpy', match_statuses=['P'], match_log_lines=True,
        )

    def _log(self, name, **kwargs):
        defaults = {
            'forum_username': 'forum_user', 'original_filename': f'{name}.txt', 'log_type': 'FRST',
            'content': f'Scan result of Farbar Recovery Scan Tool {name}',
        }
        defaults.update(kwargs)
        return UploadedLog.objects.create(upload_id=name, **defaults)

    def _cache(self, log, payload, line_tags=None, rule_set_key='shared'):
        return UploadedLogAnalysis.objects.create(
            upload=log, rule_set_key=rule_set_key, payload=payload,
            source_content_hash=log.content_hash, line_tags=line_tags,
        )


class MatchLineTests(TestCase):
    def test_status_entry_type_regex_and_exclude_all_must_hold(self):
        conditions = TagConditions(
            pattern='renpy', exclude_pattern='launcher', statuses=('P', 'B'),
            entry_types=('runkey',), lines=True,
        )
        self.assertTrue(conditions.match_line(_line('Run: [RenPy] x', status='B', entry_type='runkey')))
        self.assertFalse(conditions.match_line(_line('Run: renpy', status='C', entry_type='runkey')))
        self.assertFalse(conditions.match_line(_line('Run: renpy', status='B', entry_type='service')))
        self.assertFalse(conditions.match_line(_line('renpy launcher', status='B', entry_type='runkey')))
        self.assertFalse(conditions.match_line(_line('something else', status='B', entry_type='runkey')))

    def test_flag_off_or_no_condition_matches_no_line(self):
        self.assertFalse(TagConditions(pattern='renpy').match_line(_line('renpy', status='P')))
        self.assertFalse(TagConditions(lines=True).match_line(_line('renpy', status='P')))

    def test_status_only_tag_matches_every_line_with_that_verdict(self):
        conditions = TagConditions(statuses=('P',), lines=True)
        self.assertTrue(conditions.match_line(_line('anything', status='P')))
        self.assertFalse(conditions.match_line(_line('anything', status='C')))

    def test_entry_type_is_the_lines_own_parsed_entry_not_the_matchers(self):
        conditions = TagConditions(statuses=('P',), entry_types=('browser_extension',), lines=True)
        decided_by_substring = _line(
            EXTENSION_LINE, status='P', entry_type='substrings', parsed_entry_type='browser_extension',
        )
        self.assertTrue(conditions.match_line(decided_by_substring))
        self.assertFalse(conditions.match_line(
            _line('x', status='P', entry_type='browser_extension', parsed_entry_type=''),
        ))

    def test_older_payload_line_is_parsed_from_its_text(self):
        conditions = TagConditions(entry_types=('browser_extension',), lines=True)
        line = {'line': EXTENSION_LINE, 'dominant_status': 'P', 'entry_type': 'substrings', 'rule_ids': []}
        self.assertTrue(conditions.match_line(line))
        self.assertEqual(LineTagMatcher({1: conditions}).hits({'lines': [line]}), {1: [0]})

    def test_signature_changes_with_the_line_conditions_only(self):
        base = TagConditions(pattern='renpy', statuses=('P',), lines=True)
        self.assertEqual(base.line_signature, TagConditions(pattern='renpy', statuses=('P',), scope='source', lines=True).line_signature)
        self.assertNotEqual(base.line_signature, TagConditions(pattern='renpy', statuses=('B',), lines=True).line_signature)
        self.assertNotEqual(base.line_signature, TagConditions(pattern='ren', statuses=('P',), lines=True).line_signature)

    def test_matcher_finds_every_tags_lines_in_one_pass(self):
        matcher = LineTagMatcher({
            1: TagConditions(pattern='renpy', statuses=('P',), lines=True),
            2: TagConditions(pattern='explorer', lines=True),
            3: TagConditions(statuses=('B',), lines=True),
            4: TagConditions(pattern='nothing here', lines=True),
            5: TagConditions(pattern='renpy'),  # not a line tag
        })
        self.assertEqual(matcher.hits(RENPY_PAYLOAD), {1: [0], 2: [1], 3: [2]})


class AttachLineTagsTests(LineTagSetupMixin, TestCase):
    def test_line_gets_the_tag_without_a_tagged_rule(self):
        payload = attach_rule_tags(_payload(RENPY_PAYLOAD['lines']))

        self.assertEqual([line['tag_ids'] for line in payload['lines']], [[self.renpy.pk], [], []])
        self.assertEqual(
            [(tag['name'], tag['line_count']) for tag in payload['rule_tags']], [('renpy', 1)],
        )

    def test_rule_and_line_tags_are_merged(self):
        rule = make_rule('C:\\Windows\\explorer.exe')
        other = RuleTag.objects.create(name='windows')
        rule.tags.add(other)
        lines = [dict(line) for line in RENPY_PAYLOAD['lines']]
        lines[0]['rule_ids'] = [rule.pk]

        payload = attach_rule_tags(_payload(lines))

        self.assertEqual(payload['lines'][0]['tag_ids'], sorted([self.renpy.pk, other.pk]))

    def test_tag_without_the_flag_finds_no_lines(self):
        self.renpy.match_log_lines = False
        self.renpy.save()

        payload = attach_rule_tags(_payload(RENPY_PAYLOAD['lines']))

        self.assertEqual(payload['rule_tags'], [])

    def test_first_tagged_line_includes_line_tags(self):
        self.assertEqual(first_tagged_line(RENPY_PAYLOAD, [self.renpy.pk]), 'C:\\Games\\renpy\\launcher.exe')


class LineTagAnalyzerTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()

    def test_extension_line_made_pup_by_a_substring_rule_gets_the_tag(self):
        ClassificationRule.objects.create(
            source_text='ghbmnnjooekpmoecnnnilnnbdlolhkhi', status=ClassificationRule.STATUS_PUP,
            match_type=ClassificationRule.MATCH_SUBSTRING,
        )
        tag = RuleTag.objects.create(
            name='pup extension', match_statuses=['P'], match_entry_types=['browser_extension'],
            match_log_lines=True,
        )

        payload = analyze_log_text(EXTENSION_LINE, SHARED_RULE_SET_KEY)
        line = payload['lines'][0]
        self.assertEqual(
            (line['dominant_status'], line['entry_type'], line['parsed_entry_type']),
            ('P', 'substrings', 'browser_extension'),
        )

        attach_rule_tags(payload)

        self.assertEqual(payload['lines'][0]['tag_ids'], [tag.pk])


class StoredLineTagsTests(LineTagSetupMixin, TestCase):
    def test_caching_an_analysis_stores_its_line_tags(self):
        log = self._log('stored')

        store_cached_analysis(log, 'shared', _payload(RENPY_PAYLOAD['lines']))

        row = UploadedLogAnalysis.objects.get(upload=log)
        self.assertEqual(line_tag_hits(row.line_tags), {self.renpy.pk: [0]})
        self.assertEqual(row.line_tags, compute_line_tags(RENPY_PAYLOAD))

    def test_stale_signature_is_recomputed_and_unchanged_ones_reused(self):
        current = current_line_tags()
        stored = compute_line_tags(RENPY_PAYLOAD, current)
        self.assertEqual(fresh_line_tags(stored, RENPY_PAYLOAD, current), ({self.renpy.pk: [0]}, None))

        changed = {self.renpy.pk: TagConditions(pattern='renpy', statuses=('B',), lines=True)}
        hits, updated = fresh_line_tags(stored, RENPY_PAYLOAD, changed)

        self.assertEqual(hits, {self.renpy.pk: [2]})
        self.assertEqual(updated, compute_line_tags(RENPY_PAYLOAD, changed))

    def test_tags_no_longer_matching_lines_are_dropped(self):
        stored = compute_line_tags(RENPY_PAYLOAD)

        hits, updated = fresh_line_tags(stored, RENPY_PAYLOAD, {})

        self.assertEqual(hits, {})
        self.assertEqual(updated, {'sigs': {}, 'lines': {}})

    def test_search_and_listing_find_line_tags_and_store_missing_ones(self):
        log = self._log('found')
        self._cache(log, _payload(RENPY_PAYLOAD['lines']), line_tags=None)
        other = self._log('other')
        self._cache(other, _payload([_line('C:\\clean.exe', status='C')]), line_tags=None)

        self.assertEqual(logs_with_tags([self.renpy.pk], 'shared', UploadedLog.objects.all()), ([log.pk], 0))
        found = found_tags_by_upload([log.pk, other.pk], 'shared')

        self.assertEqual([tag['name'] for tag in found[log.pk]], ['renpy'])
        self.assertEqual(found[other.pk], [])
        attached = {tag['id'] for tag in attach_rule_tags(_payload(RENPY_PAYLOAD['lines']))['rule_tags']}
        self.assertEqual({tag['id'] for tag in found[log.pk]}, attached)
        # The matches computed on read were stored back.
        row = UploadedLogAnalysis.objects.get(upload=log)
        self.assertEqual(line_tag_hits(row.line_tags), {self.renpy.pk: [0]})

    def test_listing_reads_stored_matches(self):
        log = self._log('stored-only')
        stored = compute_line_tags(RENPY_PAYLOAD)
        # The payload no longer matches, but the stored signature is current:
        # listings trust the stored ids instead of matching again.
        self._cache(log, _payload([_line('C:\\clean.exe', status='C')]), line_tags=stored)

        found = found_tags_by_upload([log.pk], 'shared')

        self.assertEqual([tag['name'] for tag in found[log.pk]], ['renpy'])


class RefreshLineTagsTests(LineTagSetupMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.log = self._log('refresh')
        self.row = self._cache(self.log, _payload(RENPY_PAYLOAD['lines']), line_tags=compute_line_tags(RENPY_PAYLOAD))

    def _stored_hits(self):
        self.row.refresh_from_db()
        return line_tag_hits(self.row.line_tags)

    def _stat_line_tag_ids(self):
        return UploadedLogStat.objects.get(source_id=self.log.pk).line_tag_ids

    def test_editing_a_line_tag_refreshes_stored_analyses_and_stats(self):
        tag, error = save_tag(self.user, self.renpy, {'match_statuses': ['B']})

        self.assertIsNone(error)
        self.assertEqual(self._stored_hits(), {self.renpy.pk: [2]})
        self.assertEqual(self._stat_line_tag_ids(), [self.renpy.pk])

    def test_new_line_tag_is_stored_for_existing_analyses(self):
        tag, error = save_tag(self.user, None, {
            'name': 'explorer', 'match_pattern': 'explorer', 'match_log_lines': True,
        })

        self.assertIsNone(error)
        self.assertEqual(self._stored_hits(), {self.renpy.pk: [0], tag.pk: [1]})
        self.assertEqual(self._stat_line_tag_ids(), sorted([self.renpy.pk, tag.pk]))

    def test_deleting_a_line_tag_drops_its_matches(self):
        delete_tag(self.renpy)

        self.assertEqual(self._stored_hits(), {})
        self.assertEqual(self._stat_line_tag_ids(), [])

    def test_saving_without_a_line_change_leaves_stored_rows_alone(self):
        marker = {'sigs': {}, 'lines': {}, 'marker': True}
        UploadedLogAnalysis.objects.filter(pk=self.row.pk).update(line_tags=marker)

        save_tag(self.user, self.renpy, {'description': 'ren py games'})

        self.row.refresh_from_db()
        self.assertEqual(self.row.line_tags, marker)

    def test_full_refresh_recomputes_every_line_tag(self):
        UploadedLogAnalysis.objects.filter(pk=self.row.pk).update(line_tags=None)

        self.assertEqual(refresh_line_tags(None), 1)
        self.assertEqual(self._stored_hits(), {self.renpy.pk: [0]})
        self.assertEqual(self._stat_line_tag_ids(), [self.renpy.pk])

    def test_recompute_button_on_the_tags_page(self):
        UploadedLogAnalysis.objects.filter(pk=self.row.pk).update(line_tags=None)
        self.client.force_login(self.user)

        self.assertContains(self.client.get(reverse('rule_tags')), 'recompute log tags')
        response = self.client.post(reverse('rule_tags'), {'action': 'recompute_line_tags'})

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._stored_hits(), {self.renpy.pk: [0]})

    def test_recompute_command(self):
        UploadedLogAnalysis.objects.filter(pk=self.row.pk).update(line_tags=None)
        out = StringIO()

        call_command('recompute_line_tags', stdout=out)

        self.assertIn('Recomputed 1 line tag(s) for 1 cached analyses.', out.getvalue())
        self.assertEqual(self._stored_hits(), {self.renpy.pk: [0]})


class SaveLineTagValidationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='pw')

    def test_matching_log_lines_needs_a_condition(self):
        tag, error = save_tag(self.user, None, {'name': 'empty', 'match_log_lines': True})
        self.assertIsNone(tag)
        self.assertIn('Matching log lines needs a condition', error)

    def test_flag_must_be_a_boolean(self):
        tag, error = save_tag(self.user, None, {'name': 'x', 'match_pattern': 'x', 'match_log_lines': 'yes'})
        self.assertIsNone(tag)
        self.assertEqual(error, 'Field "match_log_lines" must be a boolean.')

    def test_serialized_tag_carries_the_flag(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse('rule_tag_save_api'),
            {'name': 'renpy', 'match_pattern': 'renpy', 'match_log_lines': True},
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['tag']['match_log_lines'])
        self.assertTrue(RuleTag.objects.get(name='renpy').match_log_lines)


class LineTagStatsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='pw')
        self.client.force_login(self.user)
        self.renpy = RuleTag.objects.create(name='renpy', match_pattern='renpy', match_log_lines=True)

    def _stat(self, source_id, line_tag_ids):
        return UploadedLogStat.objects.create(
            source_id=source_id, log_type='FRST', created_at=timezone.now() - timedelta(hours=1),
            total_line_count=10, rule_ids=[], warning_codes=[], line_tag_ids=line_tag_ids,
        )

    def test_stats_count_recorded_line_tags_and_skip_deleted_tags(self):
        self._stat(20001, [self.renpy.pk])
        self._stat(20002, [self.renpy.pk, 999999])
        self._stat(20003, None)

        response = self.client.get(reverse('statistics'))

        self.assertEqual(response.status_code, 200)
        rows = {row['name']: row['count'] for row in response.context['tag_stats']}
        self.assertEqual(rows, {'renpy': 2})
