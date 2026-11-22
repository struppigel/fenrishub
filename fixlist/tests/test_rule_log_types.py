"""Rules scoped to log types: "all log types" (including ones added later) or
a selection of exact names. Covers the scope helpers, the analyzer's per-type
rule buckets, the defaults of every way a rule is created, the editor and API
fields, analysis of every detected log type, and the stored-log preview."""

import importlib
import json

from django.apps import apps
from django.test import TestCase
from django.urls import reverse

from .. import analyzer
from ..analyzer import (
    _get_cached_rule_buckets, _load_rule_buckets, analyze_log_text, inspect_line_matches,
    invalidate_rule_buckets_cache, parse_rule_line,
)
from ..log_types import (
    DEFAULT_RULE_LOG_TYPES, default_rule_scope, is_analyzed_log_type, normalize_log_type_selection,
    rule_applies_to,
)
from ..models import ClassificationRule, LogTypeBadge, UploadedLog, UploadedLogAnalysis, count_fixlog_results
from ..rule_utils import _persist_selected_pending_rules
from ..upload_utils import get_fresh_cached_analysis
from .factories import make_rule, make_uploaded_log, make_user
from .test_llm_api_write import ApiWriteBase

FRST_TYPES = list(DEFAULT_RULE_LOG_TYPES)


def _verdict(analysis, line):
    return next(entry['dominant_status'] for entry in analysis['lines'] if entry['line'] == line)


class ScopeHelperTests(TestCase):
    def test_default_scope(self):
        self.assertEqual(default_rule_scope('exact'), (False, FRST_TYPES))
        self.assertEqual(default_rule_scope('filepath'), (True, []))
        self.assertEqual(default_rule_scope('filepath', 'Spor'), (True, []))
        self.assertEqual(default_rule_scope('substring', 'Spor'), (False, ['Spor']))
        self.assertEqual(default_rule_scope('substring', 'FRST'), (False, FRST_TYPES))
        self.assertEqual(default_rule_scope('substring', 'Unknown'), (False, FRST_TYPES))

    def test_normalize_selection(self):
        self.assertEqual(normalize_log_type_selection('all'), ((True, []), None))
        self.assertEqual(normalize_log_type_selection([' Spor', 'Spor', 'FRST']), ((False, ['Spor', 'FRST']), None))
        for bad in ([], ['  '], 'Spor', [3], ['Unknown'], ['bad"name']):
            scope, error = normalize_log_type_selection(bad)
            self.assertIsNone(scope, bad)
            self.assertTrue(error, bad)

    def test_exact_names_and_unknown_logs(self):
        self.assertTrue(rule_applies_to(False, ['FRST'], 'FRST'))
        self.assertFalse(rule_applies_to(False, ['FRST'], 'FRST&Addition'))
        self.assertTrue(rule_applies_to(True, [], 'Brand New Type'))
        # No log context, or text of no known type: every rule, as before scopes.
        self.assertTrue(rule_applies_to(False, ['Spor'], None))
        self.assertTrue(rule_applies_to(False, ['Spor'], 'Unknown'))

    def test_analyzed_log_types(self):
        self.assertTrue(is_analyzed_log_type('Spor'))
        self.assertTrue(is_analyzed_log_type('FRST'))
        self.assertFalse(is_analyzed_log_type('Unknown'))
        self.assertFalse(is_analyzed_log_type('Fixlog'))
        self.assertFalse(is_analyzed_log_type(''))


class RuleBucketScopeTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        make_rule('frst-line')  # model default: the FRST types
        make_rule('frst-only', log_types=['FRST'])
        make_rule('spor-line', log_types=['Spor'])
        make_rule('every-line', all_log_types=True, log_types=[])

    def texts(self, log_type):
        return {rule.source_text for rule in _load_rule_buckets('shared', log_type)['exact']}

    def test_scoped_rules_skip_other_types(self):
        self.assertEqual(self.texts('Spor'), {'spor-line', 'every-line'})
        self.assertEqual(self.texts('FRST'), {'frst-line', 'frst-only', 'every-line'})

    def test_combined_log_does_not_use_frst_only_rules(self):
        self.assertEqual(self.texts('FRST&Addition'), {'frst-line', 'every-line'})

    def test_all_rules_apply_to_a_type_never_seen(self):
        self.assertEqual(self.texts('Brand New Type'), {'every-line'})

    def test_unknown_and_no_type_load_every_rule(self):
        everything = {'frst-line', 'frst-only', 'spor-line', 'every-line'}
        self.assertEqual(self.texts('Unknown'), everything)
        self.assertEqual(self.texts(None), everything)

    def test_cache_is_per_type_and_invalidation_drops_every_type(self):
        spor = _get_cached_rule_buckets('shared', 'Spor')
        self.assertIs(_get_cached_rule_buckets('shared', 'Spor'), spor)
        self.assertIsNot(_get_cached_rule_buckets('shared', 'FRST'), spor)
        invalidate_rule_buckets_cache('shared')
        self.assertFalse([key for key in analyzer._rule_buckets_cache if key[0] == 'shared'])

    def test_analysis_and_inspection_use_the_logs_type(self):
        text = 'spor-line\nfrst-line'
        spor = analyze_log_text(text, 'shared', 'Spor')
        self.assertEqual(spor['log_type'], 'Spor')
        self.assertEqual(_verdict(spor, 'spor-line'), 'B')
        self.assertEqual(_verdict(spor, 'frst-line'), '?')
        self.assertEqual(inspect_line_matches('frst-line', log_type='Spor')['dominant_status'], '?')
        self.assertEqual(inspect_line_matches('frst-line', log_type='FRST')['dominant_status'], 'B')


class MigrationBackfillTests(TestCase):
    def test_existing_rules_get_the_frst_types_and_filepath_rules_all(self):
        migration = importlib.import_module('fixlist.migrations.0113_rule_log_types')
        exact = make_rule('x', all_log_types=True, log_types=[])
        path = make_rule(r'C:\x\y.exe', match_type=ClassificationRule.MATCH_FILEPATH, log_types=['FRST'])
        migration.backfill_rule_log_types(apps, None)
        exact.refresh_from_db()
        path.refresh_from_db()
        self.assertEqual((exact.all_log_types, exact.log_types), (False, FRST_TYPES))
        self.assertEqual((path.all_log_types, path.log_types), (True, []))


class RulePageScopeTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        self.user = make_user()
        self.client.login(username='alice', password='password123')

    def add(self, **fields):
        return self.client.post(reverse('add_rule'), {
            'status': 'B', 'match_type': 'substring', 'source_text': 'evil', **fields,
        })

    def test_add_with_all_and_with_a_selection(self):
        self.add(source_text='one', log_scope='all')
        self.add(source_text='two', log_scope='selected', log_types=['Spor', 'FRST'])
        one = ClassificationRule.objects.get(source_text='one')
        two = ClassificationRule.objects.get(source_text='two')
        self.assertEqual((one.all_log_types, one.log_types), (True, []))
        self.assertEqual((two.all_log_types, two.log_types), (False, ['Spor', 'FRST']))

    def test_add_with_an_empty_selection_is_refused(self):
        self.add(log_scope='selected')
        self.assertFalse(ClassificationRule.objects.filter(source_text='evil').exists())

    def test_add_without_a_picker_gets_the_default(self):
        self.add(source_text='plain')
        self.add(source_text=r'C:\bad\evil.exe', match_type='filepath')
        plain = ClassificationRule.objects.get(source_text='plain')
        path = ClassificationRule.objects.get(match_type='filepath')
        self.assertEqual((plain.all_log_types, plain.log_types), (False, FRST_TYPES))
        self.assertTrue(path.all_log_types)

    def test_editor_saves_the_scope(self):
        rule = make_rule('evil', owner=self.user)
        self.client.post(reverse('edit_rule', args=[rule.pk]), {
            'status': 'B', 'match_type': 'exact', 'source_text': 'evil', 'priority': str(rule.priority),
            'is_enabled': 'on', 'log_scope': 'selected', 'log_types': ['Spor'],
        })
        rule.refresh_from_db()
        self.assertEqual(rule.log_types, ['Spor'])

    def test_quick_edit_keeps_the_scope(self):
        rule = make_rule('evil', owner=self.user, log_types=['Spor'])
        self.client.post(reverse('rules'), {
            'action': 'edit', 'pk': rule.pk, 'status': 'P', 'match_type': 'exact', 'source_text': 'evil',
            'priority': str(rule.priority), 'is_enabled': 'on',
        })
        rule.refresh_from_db()
        self.assertEqual((rule.status, rule.log_types), ('P', ['Spor']))

    def test_open_full_editor_shows_the_rules_own_scope(self):
        rule = make_rule('evil', owner=self.user, log_types=['Spor'])
        response = self.client.post(reverse('edit_rule', args=[rule.pk]), {
            'open_editor': '1', 'status': 'B', 'match_type': 'exact', 'source_text': 'evil',
            'priority': str(rule.priority), 'is_enabled': 'on',
        })
        self.assertEqual(response.context['log_scope_picker']['value'], ['Spor'])
        self.assertTrue(response.context['log_scope_picker']['chosen'])


class AnalyzerPersistScopeTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        self.user = make_user()

    def persist(self, line, log_type=None, **change):
        _persist_selected_pending_rules(
            raw_pending_changes=[{'id': 'c1', 'line': line, 'new_status': 'B', 'original_status': '?', **change}],
            raw_selected_ids=['c1'], raw_conflict_resolutions=[], username='alice',
            source_prefix='test', owner=self.user, log_type=log_type,
        )
        parsed = parse_rule_line(line, status='B')
        return ClassificationRule.objects.get(
            owner=self.user, match_type=parsed['match_type'], source_text=parsed['source_text'],
        )

    def test_defaults(self):
        frst = self.persist('EXACT:frst line', 'FRST&Addition')
        spor = self.persist('EXACT:spor line', 'Spor')
        unknown = self.persist('EXACT:pasted line')
        path = self.persist(r'FILEPATH:C:\bad\evil.exe', 'Spor')
        self.assertEqual(frst.log_types, FRST_TYPES)
        self.assertEqual(spor.log_types, ['Spor'])
        self.assertEqual(unknown.log_types, FRST_TYPES)
        self.assertTrue(path.all_log_types)

    def test_review_pick_wins(self):
        rule = self.persist('EXACT:line', 'Spor', log_types='all')
        self.assertTrue(rule.all_log_types)

    def test_existing_scoped_rule_gains_the_open_logs_type(self):
        self.persist('EXACT:line', 'FRST')
        rule = self.persist('EXACT:line', 'Spor')
        self.assertEqual(rule.log_types, FRST_TYPES + ['Spor'])

    def test_empty_pick_is_invalid(self):
        _persist_selected_pending_rules(
            raw_pending_changes=[{'id': 'c1', 'line': 'EXACT:x', 'new_status': 'B', 'log_types': []}],
            raw_selected_ids=['c1'], raw_conflict_resolutions=[], username='alice',
            source_prefix='test', owner=self.user,
        )
        self.assertFalse(ClassificationRule.objects.filter(owner=self.user).exists())


class AnalyzeApiScopeTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        LogTypeBadge.objects.create(name='Spor')
        self.user = make_user()
        self.client.login(username='alice', password='password123')
        make_rule('frst-line')
        make_rule('spor-line', log_types=['Spor'])

    def test_analysis_of_an_upload_uses_its_type(self):
        content = 'spor-line\nfrst-line'
        make_uploaded_log('spor-log', content=content, log_type='Spor')
        data = self.client.post(
            reverse('analyze_log_api'), json.dumps({'log': content, 'upload_id': 'spor-log'}),
            content_type='application/json',
        ).json()
        self.assertEqual(data['log_type'], 'Spor')
        self.assertEqual(_verdict(data, 'spor-line'), 'B')
        self.assertEqual(_verdict(data, 'frst-line'), '?')

    def test_line_details_use_a_known_type_and_ignore_others(self):
        def status(log_type):
            return self.client.post(
                reverse('analyze_line_details_api'), json.dumps({'line': 'frst-line', 'log_type': log_type}),
                content_type='application/json',
            ).json()['inspection']['dominant_status']

        self.assertEqual(status('Spor'), '?')
        # A name no log type has is no context (every rule), and adds no cached buckets.
        self.assertEqual(status('made-up-type'), 'B')
        self.assertFalse([key for key in analyzer._rule_buckets_cache if key[1] == 'made-up-type'])


class EveryLogTypeAnalyzedTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        make_rule('frst-line')
        make_rule('spor-line', log_types=['Spor'])
        make_rule('every-line', all_log_types=True, log_types=[])

    def test_a_spor_upload_gets_stats_and_a_cache_from_its_rules(self):
        log = make_uploaded_log('spor-log', content='spor-line\nfrst-line\nevery-line', log_type='Spor')
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertEqual(log.count_malware, 2)
        payload = get_fresh_cached_analysis(log, 'shared')
        self.assertEqual(payload['log_type'], 'Spor')
        self.assertEqual(_verdict(payload, 'frst-line'), '?')

    def test_unknown_logs_are_still_not_analyzed(self):
        log = make_uploaded_log('odd-log', content='frst-line', log_type='Unknown')
        log.recalculate_analysis_stats()
        self.assertFalse(UploadedLogAnalysis.objects.filter(upload=log).exists())

    def test_a_fixlog_is_not_analyzed_and_keeps_its_fixlog_stats(self):
        # Its result lines name the removed files; a file path rule must not count them.
        make_rule(r'C:\bad\evil.exe', match_type=ClassificationRule.MATCH_FILEPATH, all_log_types=True)
        content = 'C:\\bad\\evil.exe => moved successfully\nC:\\bad\\gone.exe => not found\nfrst-line'
        log = make_uploaded_log('fix-log', content=content, log_type='Fixlog')
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertEqual(log.fixlog_total, count_fixlog_results(content)['total'])
        self.assertEqual(log.count_malware, 0)
        self.assertFalse(UploadedLogAnalysis.objects.filter(upload=log).exists())

    def test_cache_of_another_type_is_stale(self):
        log = make_uploaded_log('spor-log', content='spor-line', log_type='Spor')
        log.recalculate_analysis_stats()
        self.assertIsNotNone(get_fresh_cached_analysis(log, 'shared'))
        UploadedLog.objects.filter(pk=log.pk).update(log_type='MAU')
        log.refresh_from_db()
        self.assertIsNone(get_fresh_cached_analysis(log, 'shared'))


class StoredLogPreviewScopeTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        self.user = make_user()
        self.client.login(username='alice', password='password123')
        for upload_id, log_type in (('frst-log', 'FRST&Addition'), ('spor-log', 'Spor'), ('mau-log', 'MAU')):
            make_uploaded_log(upload_id, content='evil', log_type=log_type)

    def scanned(self, **payload):
        data = self.client.post(
            reverse('test_rule_logs_api'),
            json.dumps({'source_text': 'evil', 'match_type': 'substring', **payload}),
            content_type='application/json',
        ).json()
        return {ref['upload_id'] for ref in data['results'][0]['logs']}

    def test_scans_exactly_the_rules_types(self):
        self.assertEqual(self.scanned(log_types=['Spor']), {'spor-log'})
        self.assertEqual(self.scanned(log_types=['Spor', 'MAU']), {'spor-log', 'mau-log'})

    def test_all_scans_every_type(self):
        self.assertEqual(self.scanned(log_types='all'), {'frst-log', 'spor-log', 'mau-log'})

    def test_without_a_scope_scans_frst_and_addition_logs_as_before(self):
        self.assertEqual(self.scanned(), {'frst-log'})

    def test_existing_verdicts_use_the_rules_of_the_lines_log_type(self):
        make_rule('evil', log_types=['FRST'])
        data = self.client.post(
            reverse('test_rule_logs_api'),
            json.dumps({'source_text': 'evil', 'match_type': 'substring', 'status': 'C', 'log_types': ['Spor']}),
            content_type='application/json',
        ).json()
        self.assertEqual(data['results'][0]['existing_status'], '?')



class RuleApiScopeTests(ApiWriteBase):
    def create(self, **fields):
        return self.post('api_v1_rule_create', body={'status': 'B', 'match_type': 'substring',
                                                     'source_text': 'evil', **fields})

    def test_create_with_and_without_log_types(self):
        spor = self.create(source_text='one', log_types=['Spor']).json()['created'][0]
        plain = self.create(source_text='two').json()['created'][0]
        path = self.create(source_text=r'C:\bad\evil.exe', match_type='filepath').json()['created'][0]
        self.assertEqual(spor['log_types'], ['Spor'])
        self.assertEqual(plain['log_types'], FRST_TYPES)
        self.assertEqual(path['log_types'], 'all')

    def test_update_changes_or_keeps_log_types(self):
        rule = make_rule('evil', owner=self.admin, log_types=['Spor'])
        self.post('api_v1_rule_update', rule.pk, body={'description': 'x'})
        rule.refresh_from_db()
        self.assertEqual(rule.log_types, ['Spor'])
        self.post('api_v1_rule_update', rule.pk, body={'log_types': 'all'})
        rule.refresh_from_db()
        self.assertTrue(rule.all_log_types)

    def test_invalid_log_types_are_refused(self):
        self.assertEqual(self.create(log_types=[]).status_code, 400)
        self.assertEqual(self.create(log_types='some').status_code, 400)
        self.assertFalse(ClassificationRule.objects.filter(source_text='evil').exists())

    def test_list_filter_matches_the_analyzer(self):
        make_rule('frst-only', log_types=['FRST'])
        make_rule('spor-only', log_types=['Spor'])
        make_rule('everywhere', all_log_types=True, log_types=[])

        def listed(log_type):
            rules = self.get('api_v1_rules', data={'log_type': log_type}).json()['rules']
            return {rule['source_text'] for rule in rules}

        self.assertEqual(listed('Spor'), {'spor-only', 'everywhere'})
        self.assertEqual(listed('FRST&Addition'), {'everywhere'})
        self.assertEqual(listed('Unknown'), {'frst-only', 'spor-only', 'everywhere'})


class AnalyzeApiCacheTests(TestCase):
    """The analyzer caches its result as the upload's analysis only for the
    upload's own text, never for text edited in the analyzer."""

    def setUp(self):
        invalidate_rule_buckets_cache()
        self.addCleanup(invalidate_rule_buckets_cache)
        self.user = make_user()
        self.client.login(username='alice', password='password123')
        make_rule('evil-line')

    def analyze(self, text, upload_id):
        return self.client.post(
            reverse('analyze_log_api'), json.dumps({'log': text, 'upload_id': upload_id}),
            content_type='application/json',
        ).json()

    def test_edited_text_is_analyzed_but_not_cached_or_counted(self):
        log = make_uploaded_log('frst-log', content='clean-line', log_type='FRST')
        data = self.analyze('clean-line\nevil-line', 'frst-log')
        self.assertEqual(_verdict(data, 'evil-line'), 'B')
        self.assertFalse(UploadedLogAnalysis.objects.filter(upload=log).exists())
        log.refresh_from_db()
        self.assertEqual(log.count_malware, 0)

    def test_the_uploads_own_text_is_cached_whatever_its_line_endings(self):
        log = make_uploaded_log('crlf-log', content='evil-line\r\nclean-line\r\n', log_type='FRST')
        # A textarea hands the analyzer LF line endings.
        self.analyze('evil-line\nclean-line\n', 'crlf-log')
        self.assertIsNotNone(get_fresh_cached_analysis(log, 'shared'))
