"""Rule tags: pattern validation, the tags page APIs, the rule forms and the
analysis payload. Patterns here are deliberately simple - the suite runs as
Railway's preDeployCommand, so nothing that could backtrack."""

import json
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT, analyze_log_text, invalidate_rule_buckets_cache, parse_rule_line
from ..models import ClassificationRule, RuleTag, Speech
from ..rule_sets import SHARED_RULE_SET_KEY
from ..tagging import (
    TagConditions,
    attach_rule_tags,
    pattern_error,
    preview_conditions,
    preview_pattern,
    tag_fields_error,
    tag_rule_counts,
)
from ..upload_utils import store_cached_analysis
from .factories import make_rule, make_uploaded_log, make_user


def post_json(client, name, payload):
    return client.post(reverse(name), json.dumps(payload), content_type='application/json')


class PatternValidationTests(TestCase):
    def test_plain_alternation_is_fine(self):
        self.assertIsNone(pattern_error('renpy|renloader'))

    def test_empty_pattern_is_allowed(self):
        self.assertIsNone(pattern_error(''))

    def test_invalid_regex_is_rejected(self):
        self.assertIn('Invalid regex', pattern_error('(unclosed'))

    def test_lookaround_is_rejected(self):
        self.assertIsNotNone(pattern_error('(?=x)y'))

    def test_pattern_matching_empty_text_is_rejected(self):
        self.assertIn('every rule', pattern_error('x*'))

    def test_names_are_unique_regardless_of_case(self):
        RuleTag.objects.create(name='RenLoader')
        self.assertIn('already exists', tag_fields_error('renloader', '', ''))

    def test_name_characters_are_limited(self):
        self.assertIsNotNone(tag_fields_error('bad<name>', '', ''))


class PreviewTests(TestCase):
    def setUp(self):
        self.owner = make_user()
        self.renpy = make_rule('a', description='RenPy loader dropper', owner=self.owner)
        self.renloader = make_rule('b', description='renloader', owner=self.owner)
        self.other = make_rule('c', description='Kaspersky', owner=self.owner)

    def test_groups_new_tagged_and_stale(self):
        tag = RuleTag.objects.create(name='renloader')
        tag.rules.add(self.renloader, self.other)

        result = preview_pattern('renpy|renloader', tag=tag)

        ids = {key: [row['id'] for row in rows] for key, rows in result['groups'].items()}
        self.assertEqual(ids['new'], [self.renpy.pk])
        self.assertEqual(ids['tagged'], [self.renloader.pk])
        self.assertEqual(ids['stale'], [self.other.pk])
        self.assertEqual(result['counts'], {'new': 1, 'tagged': 1, 'stale': 1})

    def test_match_is_case_insensitive_and_highlighted(self):
        result = preview_pattern('RENPY')
        row = result['groups']['new'][0]
        self.assertEqual(row['description'][row['span'][0]:row['span'][1]], 'RenPy')

    def test_most_common_description_is_suggested(self):
        make_rule('d', description='renloader', owner=self.owner)
        result = preview_pattern('renpy|renloader')
        self.assertEqual(result['suggested_description'], 'renloader')


class TagApiTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.rule_a = make_rule('a', description='renpy one', owner=self.user)
        self.rule_b = make_rule('b', description='renpy two', owner=self.user)

    def test_save_creates_tag_and_applies_it(self):
        response = post_json(self.client, 'rule_tag_save_api', {
            'name': 'renloader', 'match_pattern': 'renpy', 'add_rule_ids': [self.rule_a.pk],
        })

        self.assertEqual(response.status_code, 200)
        tag = RuleTag.objects.get(name='renloader')
        self.assertEqual(list(tag.rules.all()), [self.rule_a])
        self.assertEqual(tag.created_by, self.user)
        self.assertEqual(response.json()['added'], 1)

    def test_partial_update_keeps_pattern(self):
        tag = RuleTag.objects.create(name='renloader', match_pattern='renpy')
        post_json(self.client, 'rule_tag_save_api', {'id': tag.pk, 'description': 'notes'})
        tag.refresh_from_db()
        self.assertEqual((tag.match_pattern, tag.description), ('renpy', 'notes'))

    def test_save_removes_only_listed_rules(self):
        tag = RuleTag.objects.create(name='renloader')
        tag.rules.add(self.rule_a, self.rule_b)
        post_json(self.client, 'rule_tag_save_api', {'id': tag.pk, 'remove_rule_ids': [self.rule_a.pk]})
        self.assertEqual(list(tag.rules.all()), [self.rule_b])

    def test_save_rejects_bad_pattern(self):
        response = post_json(self.client, 'rule_tag_save_api', {'name': 'x', 'match_pattern': '(?=a)b'})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(RuleTag.objects.filter(builtin_code=None).exists())

    def test_preview_rejects_bad_pattern(self):
        response = post_json(self.client, 'rule_tag_preview_api', {'pattern': '(unclosed'})
        self.assertEqual(response.status_code, 400)

    def test_suggest_returns_matching_tags(self):
        RuleTag.objects.create(name='renloader', match_pattern='renpy|renloader')
        RuleTag.objects.create(name='other', match_pattern='kaspersky')
        response = post_json(self.client, 'rule_tag_suggest_api', {'description': 'RenPy Loader'})
        self.assertEqual([tag['name'] for tag in response.json()['tags']], ['renloader'])

    def test_tags_page_shows_pending_and_unmatched_counts(self):
        tag = RuleTag.objects.create(name='renloader', match_pattern='renpy')
        stale = make_rule('c', description='something else', owner=self.user)
        tag.rules.add(self.rule_a, stale)
        response = self.client.get(reverse('rule_tags'))
        self.assertEqual(response.status_code, 200)
        counts = {
            t.name: (t.pending_count, t.unmatched_count)
            for t in response.context['tags'] if t.builtin_code is None
        }
        self.assertEqual(counts, {'renloader': (1, 1)})

    def test_delete_removes_tag_from_rules(self):
        tag = RuleTag.objects.create(name='renloader')
        tag.rules.add(self.rule_a)
        self.client.post(reverse('rule_tags'), {'action': 'delete', 'pk': tag.pk})
        self.assertFalse(RuleTag.objects.filter(pk=tag.pk).exists())
        self.assertFalse(self.rule_a.tags.exists())

    def test_guests_cannot_use_the_api(self):
        self.client.logout()
        response = self.client.get(reverse('rule_tags_api'))
        self.assertEqual(response.status_code, 302)


class RuleFormTagTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.tag = RuleTag.objects.create(name='renloader', match_pattern='renpy')

    def test_add_rule_links_chosen_tags_to_every_created_rule(self):
        self.client.post(reverse('add_rule'), {
            'status': 'B', 'match_type': 'exact', 'source_text': 'line one\nline two',
            'description': 'renpy', 'tags_present': '1', 'tag_ids': [str(self.tag.pk)],
        })
        rules = ClassificationRule.objects.filter(owner=self.user)
        self.assertEqual(rules.count(), 2)
        self.assertTrue(all(list(rule.tags.all()) == [self.tag] for rule in rules))

    def test_matching_description_alone_does_not_tag(self):
        self.client.post(reverse('add_rule'), {
            'status': 'B', 'match_type': 'exact', 'source_text': 'line one',
            'description': 'renpy', 'tags_present': '1',
        })
        self.assertFalse(ClassificationRule.objects.get(owner=self.user).tags.exists())

    def _edit(self, rule, **extra):
        data = {
            'action': 'edit', 'pk': rule.pk, 'status': 'B', 'match_type': 'exact',
            'source_text': rule.source_text, 'description': '', 'is_enabled': 'on', **extra,
        }
        return self.client.post(reverse('rules'), data)

    def test_quick_edit_without_picker_keeps_tags(self):
        rule = make_rule('line', owner=self.user)
        rule.tags.add(self.tag)
        self._edit(rule)
        self.assertEqual(list(rule.tags.all()), [self.tag])

    def test_edit_with_empty_picker_clears_tags(self):
        rule = make_rule('line', owner=self.user)
        rule.tags.add(self.tag)
        self._edit(rule, tags_present='1')
        self.assertFalse(rule.tags.exists())

    def test_rules_list_filters_by_tag(self):
        tagged = make_rule('tagged', owner=self.user)
        make_rule('untagged', owner=self.user)
        tagged.tags.add(self.tag)
        response = self.client.get(reverse('rules'), {'filter': 'all', 'tag': self.tag.pk})
        self.assertEqual([rule.pk for rule in response.context['page_obj']], [tagged.pk])

    def test_analyzer_review_adds_tags_to_persisted_rules(self):
        line = 'HKLM\\...\\Run: [Evil] => C:\\evil.exe'
        response = post_json(self.client, 'persist_pending_rule_changes_api', {
            'pending_changes': [{
                'id': 'c1', 'order': 0, 'line': line, 'original_status': '?',
                'new_status': 'B', 'tag_ids': [self.tag.pk],
            }],
            'selected_rule_change_ids': ['c1'],
            'conflict_resolutions': [],
        })
        self.assertEqual(response.status_code, 200)
        rule = ClassificationRule.objects.get(owner=self.user)
        self.assertEqual(list(rule.tags.all()), [self.tag])


class AnalysisPayloadTagTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = make_user()
        self.tag = RuleTag.objects.create(name='renloader')

    def test_rule_ids_name_the_deciding_rules_only(self):
        winner = make_rule('EXACT LINE', owner=self.user)
        shadowed = make_rule('EXACT', owner=self.user, match_type=ClassificationRule.MATCH_SUBSTRING,
                             status=ClassificationRule.STATUS_CLEAN)

        payload = analyze_log_text('EXACT LINE', SHARED_RULE_SET_KEY)

        self.assertEqual(payload['lines'][0]['rule_ids'], [winner.pk])
        self.assertNotIn(shadowed.pk, payload['lines'][0]['rule_ids'])

    def test_wholelog_rules_that_fire_are_listed(self):
        rule = make_rule('needle', owner=self.user, status=ClassificationRule.STATUS_ALERT,
                         match_type=ClassificationRule.MATCH_REGEX, whole_log=True,
                         description='needle found')
        payload = analyze_log_text('hay\nneedle\nhay', SHARED_RULE_SET_KEY)
        self.assertEqual(payload['wholelog_rule_ids'], [rule.pk])

    def test_tags_are_attached_with_line_counts(self):
        rule = make_rule('BAD ONE', owner=self.user)
        rule.tags.add(self.tag)
        payload = attach_rule_tags(analyze_log_text('BAD ONE\nBAD ONE\nclean', SHARED_RULE_SET_KEY))
        self.assertEqual(payload['lines'][0]['tag_ids'], [self.tag.pk])
        self.assertEqual(payload['lines'][2]['tag_ids'], [])
        self.assertEqual(
            [(t['name'], t['line_count']) for t in payload['rule_tags']], [('renloader', 2)],
        )

    def test_cached_analysis_sees_a_rule_tagged_after_caching(self):
        rule = make_rule('BAD ONE', owner=self.user)
        upload = make_uploaded_log(content='BAD ONE')
        store_cached_analysis(upload, SHARED_RULE_SET_KEY, analyze_log_text('BAD ONE', SHARED_RULE_SET_KEY))

        rule.tags.add(self.tag)
        self.client.force_login(self.user)
        response = self.client.get(reverse('uploaded_log_cached_analysis_api', args=[upload.upload_id]))

        payload = response.json()['payload']
        self.assertEqual([t['name'] for t in payload['rule_tags']], ['renloader'])

    def test_analyze_api_reports_tags(self):
        rule = make_rule('BAD ONE', owner=self.user)
        rule.tags.add(self.tag)
        self.client.force_login(self.user)
        response = post_json(self.client, 'analyze_log_api', {'log': 'BAD ONE'})
        body = response.json()
        self.assertEqual([t['name'] for t in body['rule_tags']], ['renloader'])


class TagEditorPageTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)

    def test_add_page_renders(self):
        response = self.client.get(reverse('rule_tag_add'))
        self.assertContains(response, 'regex')
        self.assertNotContains(response, 'pattern</label>')

    def test_edit_page_renders_with_tag(self):
        tag = RuleTag.objects.create(name='renloader', match_pattern='renpy')
        response = self.client.get(reverse('rule_tag_edit', args=[tag.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['tag_json']['name'], 'renloader')
        self.assertTrue(response.context['run_preview'])

    def test_old_edit_links_redirect_to_the_editor(self):
        tag = RuleTag.objects.create(name='renloader')
        response = self.client.get(reverse('rule_tags'), {'edit': tag.pk})
        self.assertRedirects(response, reverse('rule_tag_edit', args=[tag.pk]))


class RemoveUnmatchedTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)

    def test_removes_tag_from_every_unmatched_rule_beyond_the_preview_cap(self):
        tag = RuleTag.objects.create(name='renloader', match_pattern='renpy')
        matching = make_rule('m', description='renpy', owner=self.user)
        unmatched = [make_rule(f'u{i}', description='other', owner=self.user) for i in range(3)]
        tag.rules.add(matching, *unmatched)

        with patch('fixlist.tagging.PREVIEW_GROUP_LIMIT', 1):
            response = post_json(self.client, 'rule_tag_save_api', {'id': tag.pk, 'remove_unmatched': True})

        self.assertEqual(response.json()['removed'], 3)
        self.assertEqual(list(tag.rules.all()), [matching])


class BuiltinTagTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.builtin = RuleTag.objects.get(builtin_code='multiple_enabled_av')

    def test_cannot_be_deleted(self):
        self.client.post(reverse('rule_tags'), {'action': 'delete', 'pk': self.builtin.pk})
        self.assertTrue(RuleTag.objects.filter(pk=self.builtin.pk).exists())

    def test_can_be_put_on_rules(self):
        rule = make_rule('x', owner=self.user)
        response = post_json(self.client, 'rule_tag_save_api', {
            'id': self.builtin.pk, 'add_rule_ids': [rule.pk],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(rule.tags.all()), [self.builtin])

    def test_rule_forms_accept_builtin_tags(self):
        self.client.post(reverse('add_rule'), {
            'status': 'B', 'match_type': 'exact', 'source_text': 'line one',
            'tags_present': '1', 'tag_ids': [str(self.builtin.pk)],
        })
        self.assertEqual(list(ClassificationRule.objects.get(owner=self.user).tags.all()), [self.builtin])

    def test_tag_list_includes_builtin_tags(self):
        names = [t['name'] for t in self.client.get(reverse('rule_tags_api')).json()['tags']]
        self.assertIn(self.builtin.name, names)

    def test_can_get_a_regex_and_auto_apply(self):
        response = post_json(self.client, 'rule_tag_save_api', {
            'id': self.builtin.pk, 'match_pattern': 'two antivirus', 'auto_apply': True,
        })
        self.assertEqual(response.status_code, 200)
        rule = make_rule('y', description='Two antivirus products active', owner=self.user)
        self.assertEqual(list(rule.tags.all()), [self.builtin])

    def test_tag_list_with_only_builtin_tags_is_not_empty(self):
        response = self.client.get(reverse('rule_tags'))
        self.assertContains(response, self.builtin.name)
        self.assertNotContains(response, 'no tags yet')
        self.assertContains(response, f'built-in: <code>{self.builtin.builtin_code}</code>')

    def test_description_can_be_edited(self):
        post_json(self.client, 'rule_tag_save_api', {'id': self.builtin.pk, 'description': 'two AVs'})
        self.builtin.refresh_from_db()
        self.assertEqual(self.builtin.description, 'two AVs')


class WarningTagTests(TestCase):
    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = make_user()

    def test_builtin_warning_brings_its_tag(self):
        payload = {'lines': [], 'warnings': [{'code': 'multiple_enabled_av'}], 'wholelog_rule_ids': []}
        attach_rule_tags(payload)
        builtin = RuleTag.objects.get(builtin_code='multiple_enabled_av')
        self.assertEqual(payload['warnings'][0]['tag_ids'], [builtin.pk])
        self.assertEqual([t['id'] for t in payload['rule_tags']], [builtin.pk])
        self.assertTrue(payload['rule_tags'][0]['builtin'])

    def test_alert_rule_warning_carries_rule_ids_and_their_tags(self):
        tag = RuleTag.objects.create(name='needle family')
        rule = make_rule('NEEDLE', owner=self.user, status=ClassificationRule.STATUS_ALERT,
                         description='needle found')
        rule.tags.add(tag)

        payload = attach_rule_tags(analyze_log_text('NEEDLE', SHARED_RULE_SET_KEY))

        alert = next(w for w in payload['warnings'] if w['title'] == 'Alert rule matched')
        self.assertEqual(alert['rule_ids'], [rule.pk])
        self.assertEqual(alert['tag_ids'], [tag.pk])

    def test_alert_rule_with_builtin_tag_shares_its_speeches(self):
        builtin = RuleTag.objects.get(builtin_code='multiple_enabled_av')
        rule = make_rule('SECOND AV', owner=self.user, status=ClassificationRule.STATUS_ALERT,
                         description='another AV found')
        rule.tags.add(builtin)

        payload = attach_rule_tags(analyze_log_text('SECOND AV', SHARED_RULE_SET_KEY))

        self.assertEqual(payload['lines'][0]['tag_ids'], [builtin.pk])
        self.assertIn(builtin.pk, [t['id'] for t in payload['rule_tags']])
        alert = next(w for w in payload['warnings'] if w['title'] == 'Alert rule matched')
        self.assertEqual(alert['tag_ids'], [builtin.pk])

    def test_wholelog_alert_warning_carries_rule_ids(self):
        rule = make_rule('needle', owner=self.user, status=ClassificationRule.STATUS_ALERT,
                         match_type=ClassificationRule.MATCH_REGEX, whole_log=True,
                         description='needle in log')
        payload = analyze_log_text('hay\nneedle', SHARED_RULE_SET_KEY)
        alert = next(w for w in payload['warnings'] if w['message'] == 'needle in log')
        self.assertEqual(alert['rule_ids'], [rule.pk])

    def test_line_details_api_lists_tags_per_match(self):
        tag = RuleTag.objects.create(name='renloader')
        winner = make_rule('EXACT LINE', owner=self.user)
        shadowed = make_rule('EXACT', owner=self.user, match_type=ClassificationRule.MATCH_SUBSTRING,
                             status=ClassificationRule.STATUS_CLEAN)
        winner.tags.add(tag)
        shadowed.tags.add(tag)
        self.client.force_login(self.user)

        body = post_json(self.client, 'analyze_line_details_api', {'line': 'EXACT LINE'}).json()

        inspection = body['inspection']
        for match in inspection['matches'] + inspection['shadowed_matches']:
            self.assertEqual(match['tags'], [{'id': tag.pk, 'name': 'renloader', 'category_id': tag.category_id}])


class AutoApplyTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.auto = RuleTag.objects.create(name='renloader', match_pattern='renpy', auto_apply=True)
        self.manual = RuleTag.objects.create(name='manual', match_pattern='renpy')

    def test_new_rule_gets_matching_auto_tag_only(self):
        rule = make_rule('x', description='RenPy loader', owner=self.user)
        self.assertEqual(list(rule.tags.all()), [self.auto])

    def test_non_matching_rule_gets_nothing(self):
        rule = make_rule('x', description='something else', owner=self.user)
        self.assertFalse(rule.tags.exists())

    def test_add_rule_form_and_quick_create(self):
        self.client.post(reverse('add_rule'), {
            'status': 'B', 'match_type': 'exact', 'source_text': 'form line', 'description': 'renpy',
        })
        self.client.post(reverse('rules'), {
            'action': 'create', 'status': 'B', 'match_type': 'exact',
            'source_text': 'quick line', 'description': 'renpy',
        })
        for source in ('form line', 'quick line'):
            rule = ClassificationRule.objects.get(source_text=source)
            self.assertEqual(list(rule.tags.all()), [self.auto], source)

    def test_analyzer_persist(self):
        line = 'HKLM\\...\\Run: [Evil] => C:\\evil.exe'
        post_json(self.client, 'persist_pending_rule_changes_api', {
            'pending_changes': [{
                'id': 'c1', 'order': 0, 'line': line, 'original_status': '?',
                'new_status': 'B', 'description': 'renpy dropper',
            }],
            'selected_rule_change_ids': ['c1'],
            'conflict_resolutions': [],
        })
        rule = ClassificationRule.objects.get(owner=self.user)
        self.assertEqual(list(rule.tags.all()), [self.auto])

    def test_admin_malext_import(self):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from .factories import make_superuser
        self.auto.match_pattern = 'malext'
        self.auto.save()
        make_superuser()
        self.client.login(username='admin', password='password123')
        csv = SimpleUploadedFile(
            'malext.csv',
            ('extension_id,name,reason,source,date,blocklist,store\n'
             + 'a' * 32 + ',Thing,Malware,,,,Chrome').encode(),
            content_type='text/csv',
        )
        self.client.post(reverse('admin:fixlist_classificationrule_import_malext_extensions'), {'csv_file': csv})
        rule = ClassificationRule.objects.get(source_text='a' * 32)
        self.assertEqual(list(rule.tags.all()), [self.auto])

    def test_editing_description_to_match_adds_it(self):
        rule = make_rule('x', description='other', owner=self.user)
        rule.description = 'renpy now'
        rule.save()
        self.assertEqual(list(rule.tags.all()), [self.auto])

    def test_manual_removal_sticks_when_description_is_unchanged(self):
        rule = make_rule('x', description='renpy', owner=self.user)
        rule.tags.remove(self.auto)
        rule.is_enabled = False
        rule.save()
        self.assertFalse(rule.tags.exists())

    def test_auto_apply_needs_a_regex(self):
        response = post_json(self.client, 'rule_tag_save_api', {'name': 'no regex', 'auto_apply': True})
        self.assertEqual(response.status_code, 400)

    def test_suggest_api_reports_auto_apply(self):
        body = post_json(self.client, 'rule_tag_suggest_api', {'description': 'renpy'}).json()
        flags = {t['name']: t['auto_apply'] for t in body['tags']}
        self.assertEqual(flags, {'renloader': True, 'manual': False})


class TagConditionTests(TestCase):
    """Scope, statuses, entry types and the exclude regex. Plain regexes only:
    the suite runs as Railway's preDeployCommand."""

    def setUp(self):
        invalidate_rule_buckets_cache()
        self.user = make_user()
        self.client.force_login(self.user)

    def _rule(self, source, status='P', entry_type='', description=''):
        return make_rule(source, status=status, owner=self.user, entry_type=entry_type, description=description)

    def test_scope_source_line_matches_source_not_description(self):
        conditions = TagConditions(pattern='evilapp', scope=RuleTag.SCOPE_SOURCE)
        in_source = self._rule('EvilApp installer', description='x')
        in_description = self._rule('something', description='evilapp')
        self.assertTrue(conditions.matches_rule(in_source))
        self.assertFalse(conditions.matches_rule(in_description))

    def test_scope_anywhere_matches_either(self):
        conditions = TagConditions(pattern='evilapp', scope=RuleTag.SCOPE_ANY)
        self.assertTrue(conditions.matches_rule(self._rule('EvilApp', description='x')))
        self.assertTrue(conditions.matches_rule(self._rule('y', description='evilapp')))

    def test_status_and_entry_type_without_regex(self):
        conditions = TagConditions(statuses=('P',), entry_types=('installed_software',))
        self.assertTrue(conditions.matches_rule(self._rule('a', 'P', 'installed_software')))
        self.assertFalse(conditions.matches_rule(self._rule('b', 'B', 'installed_software')))
        self.assertFalse(conditions.matches_rule(self._rule('c', 'P', 'service')))

    def test_no_conditions_match_nothing(self):
        rule = self._rule('a')
        self.assertFalse(TagConditions().matches_rule(rule))
        self.assertFalse(TagConditions(exclude_pattern='zzz').matches_rule(rule))

    def test_exclude_regex_leaves_rules_out(self):
        conditions = TagConditions(
            statuses=('P',), entry_types=('installed_software',),
            exclude_pattern='microsoft', scope=RuleTag.SCOPE_ANY,
        )
        self.assertFalse(conditions.matches_rule(self._rule('Microsoft Edge', 'P', 'installed_software')))
        self.assertTrue(conditions.matches_rule(self._rule('Toolbar', 'P', 'installed_software')))

    def test_preview_without_regex_and_counts(self):
        matching = self._rule('a', 'P', 'installed_software')
        self._rule('b', 'B', 'installed_software')
        tag = RuleTag.objects.create(
            name='installed PUP program', match_statuses=['P'], match_entry_types=['installed_software'],
        )
        stale = self._rule('c', 'B', 'service')
        tag.rules.add(stale)

        result = preview_conditions(TagConditions.of(tag), tag=tag)

        self.assertEqual([row['id'] for row in result['groups']['new']], [matching.pk])
        self.assertEqual([row['id'] for row in result['groups']['stale']], [stale.pk])
        self.assertEqual(tag_rule_counts([tag])[tag.pk], (1, 1))

    def test_auto_apply_by_status_and_entry_type(self):
        tag = RuleTag.objects.create(
            name='installed PUP program', match_statuses=['P'],
            match_entry_types=['installed_software'], auto_apply=True,
        )
        pup = self._rule('pup', 'P', 'installed_software')
        bad = self._rule('bad', 'B', 'installed_software')
        self.assertEqual(list(pup.tags.all()), [tag])
        self.assertFalse(bad.tags.exists())

        bad.status = 'P'
        bad.save()
        self.assertEqual(list(bad.tags.all()), [tag])

    def test_suggest_api_derives_entry_type_and_checks_status(self):
        RuleTag.objects.create(
            name='installed PUP program', match_statuses=['P'], match_entry_types=['installed_software'],
        )
        line = 'Some Toolbar (HKLM\\...\\{1234}) (Version: 1.0 - Toolbar Inc.)'
        entry_type = (parse_rule_line(line, status='P') or {}).get('entry_type')
        self.assertEqual(entry_type, 'installed_software')

        def names(status):
            body = post_json(self.client, 'rule_tag_suggest_api', {
                'description': '', 'source_text': line, 'status': status, 'match_type': 'parsed',
            }).json()
            return [tag['name'] for tag in body['tags']]

        self.assertEqual(names('P'), ['installed PUP program'])
        self.assertEqual(names('B'), [])

    def test_only_rules_deciding_the_verdict_bring_tags(self):
        self.assertEqual(ANALYSIS_PAYLOAD_FORMAT, 4)
        pup_tag = RuleTag.objects.create(name='pup tag')
        bad_rule = make_rule('SAME LINE', status='B', owner=self.user)
        pup_rule = make_rule('SAME LINE', status='P', owner=self.user)
        pup_rule.tags.add(pup_tag)
        only_pup = make_rule('PUP LINE', status='P', owner=self.user)
        only_pup.tags.add(pup_tag)

        payload = attach_rule_tags(analyze_log_text('SAME LINE\nPUP LINE', SHARED_RULE_SET_KEY))

        self.assertEqual(payload['lines'][0]['rule_ids'], [bad_rule.pk])
        self.assertEqual(payload['lines'][0]['tag_ids'], [])
        self.assertEqual(payload['lines'][1]['tag_ids'], [pup_tag.pk])

    def test_invalid_conditions_are_rejected(self):
        for body in (
            {'name': 'x', 'match_statuses': ['?']},
            {'name': 'x', 'match_entry_types': ['Bad Type']},
            {'name': 'x', 'match_scope': 'everywhere'},
            {'name': 'x', 'match_statuses': ['P'], 'exclude_pattern': '(?=a)b'},
            {'name': 'x', 'match_statuses': ['P'], 'exclude_pattern': 'x*'},
        ):
            response = post_json(self.client, 'rule_tag_save_api', body)
            self.assertEqual(response.status_code, 400, body)

    def test_editor_saves_conditions(self):
        response = post_json(self.client, 'rule_tag_save_api', {
            'name': 'installed PUP program', 'match_statuses': ['P'],
            'match_entry_types': ['installed_software'], 'exclude_pattern': 'microsoft',
            'match_scope': 'any', 'auto_apply': True,
        })
        self.assertEqual(response.status_code, 200)
        tag = RuleTag.objects.get(name='installed PUP program')
        self.assertEqual(
            (tag.match_statuses, tag.match_entry_types, tag.exclude_pattern, tag.match_scope, tag.auto_apply),
            (['P'], ['installed_software'], 'microsoft', 'any', True),
        )

    def test_editor_page_offers_condition_fields(self):
        self._rule('a', 'P', 'installed_software')
        response = self.client.get(reverse('rule_tag_add'))
        self.assertContains(response, 'exclude regex')
        self.assertContains(response, 'value="installed_software"')


class TagSpeechLinkTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.other = make_user('bob')
        self.client.force_login(self.user)
        self.tag = RuleTag.objects.create(name='renloader')
        self.mine = Speech.objects.create(owner=self.user, name='mine', content='x')
        self.theirs = Speech.objects.create(owner=self.other, name='theirs', content='x', is_shared=True)
        self.theirs.trigger_tags.add(self.tag)

    def test_links_own_speeches_from_the_tag_editor(self):
        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'speech_ids': [self.mine.pk]})
        self.assertEqual(list(self.mine.trigger_tags.all()), [self.tag])

    def test_unticking_removes_only_own_links(self):
        self.mine.trigger_tags.add(self.tag)
        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'speech_ids': [self.theirs.pk]})
        self.assertFalse(self.mine.trigger_tags.exists())
        self.assertEqual(list(self.theirs.trigger_tags.all()), [self.tag])

    def test_saving_without_speech_ids_keeps_links(self):
        self.mine.trigger_tags.add(self.tag)
        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'description': 'notes'})
        self.assertEqual(list(self.mine.trigger_tags.all()), [self.tag])

    def test_editor_lists_own_and_others_speeches(self):
        self.mine.trigger_tags.add(self.tag)
        response = self.client.get(reverse('rule_tag_edit', args=[self.tag.pk]))
        self.assertIn(
            {'id': self.mine.pk, 'name': 'mine', 'category': self.mine.category, 'linked': True},
            response.context['linkable_speeches_json'],
        )
        self.assertEqual(list(response.context['others_speeches']), [self.theirs])

    def test_selected_shared_speech_of_another_helper_can_be_linked(self):
        selected = Speech.objects.create(owner=self.other, name='selected', content='x', is_shared=True)
        selected.analyzer_users.add(self.user)

        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'speech_ids': [selected.pk]})
        self.assertEqual(list(selected.trigger_tags.all()), [self.tag])

        response = self.client.get(reverse('rule_tag_edit', args=[self.tag.pk]))
        names = [entry['name'] for entry in response.context['linkable_speeches_json']]
        self.assertIn('selected (bob)', names)

        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'speech_ids': []})
        self.assertFalse(selected.trigger_tags.exists())
        # A speech the user has not selected keeps its link.
        self.assertEqual(list(self.theirs.trigger_tags.all()), [self.tag])


class PickerIsTheSourceOfTruthTests(TestCase):
    """Where a rule form shows the tag picker, auto tags are filled in there, so
    the tags it posts are the rule's tags: an auto tag removed in the picker
    stays off. Without a picker, auto-apply alone decides."""

    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.auto = RuleTag.objects.create(name='renloader', match_pattern='renpy', auto_apply=True)

    def _add(self, source, **extra):
        self.client.post(reverse('add_rule'), {
            'status': 'B', 'match_type': 'exact', 'source_text': source, 'description': 'renpy', **extra,
        })
        return ClassificationRule.objects.get(source_text=source)

    def test_auto_tag_removed_in_the_picker_stays_off(self):
        rule = self._add('removed', tags_present='1')
        self.assertFalse(rule.tags.exists())

    def test_auto_tag_kept_in_the_picker_is_on(self):
        rule = self._add('kept', tags_present='1', tag_ids=[str(self.auto.pk)])
        self.assertEqual(list(rule.tags.all()), [self.auto])

    def test_without_picker_auto_apply_decides(self):
        rule = self._add('no picker')
        self.assertEqual(list(rule.tags.all()), [self.auto])

    def _persist(self, line, **change):
        return post_json(self.client, 'persist_pending_rule_changes_api', {
            'pending_changes': [{
                'id': 'c1', 'order': 0, 'line': line, 'original_status': '?',
                'new_status': 'B', 'description': 'renpy dropper', **change,
            }],
            'selected_rule_change_ids': ['c1'],
            'conflict_resolutions': [],
        })

    def test_review_new_rule_gets_exactly_the_picked_tags(self):
        self._persist('HKLM\\...\\Run: [Evil] => C:\\evil.exe', tag_ids=[])
        self.assertFalse(ClassificationRule.objects.get(owner=self.user).tags.exists())

    def test_review_without_picker_keeps_auto_apply(self):
        self._persist('HKLM\\...\\Run: [Evil] => C:\\evil.exe')
        self.assertEqual(list(ClassificationRule.objects.get(owner=self.user).tags.all()), [self.auto])

    def test_review_existing_rule_keeps_its_other_tags(self):
        line = 'HKLM\\...\\Run: [Evil] => C:\\evil.exe'
        self._persist(line, tag_ids=[])
        rule = ClassificationRule.objects.get(owner=self.user)
        other = RuleTag.objects.create(name='other')
        rule.tags.add(other)
        picked = RuleTag.objects.create(name='picked')

        self._persist(line, tag_ids=[picked.pk])

        self.assertEqual(set(rule.tags.all()), {other, picked})

    def test_rule_and_speech_forms_cannot_create_tags(self):
        # Tags are made in the tag editor only; the pickers get no save URL.
        for name in ('add_rule', 'speeches'):
            response = self.client.get(reverse(name))
            self.assertNotContains(response, reverse('rule_tag_save_api'), msg_prefix=name)


class ApplyToExistingTests(TestCase):
    """Saving an auto-apply tag can tag the existing rules that meet its
    conditions; the editor asks before it sends apply_to_existing."""

    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.pup = make_rule('pup', status='P', owner=self.user, entry_type='installed_software')
        self.bad = make_rule('bad', status='B', owner=self.user, entry_type='installed_software')

    def _save(self, **extra):
        return post_json(self.client, 'rule_tag_save_api', {
            'name': 'installed PUP program', 'match_statuses': ['P'],
            'match_entry_types': ['installed_software'], 'auto_apply': True, **extra,
        })

    def test_confirmed_save_tags_existing_matching_rules(self):
        response = self._save(apply_to_existing=True)
        tag = RuleTag.objects.get(name='installed PUP program')
        self.assertEqual(response.json()['added'], 1)
        self.assertEqual(list(tag.rules.all()), [self.pup])

    def test_plain_save_leaves_existing_rules_alone(self):
        self._save()
        self.assertFalse(RuleTag.objects.get(name='installed PUP program').rules.exists())


class BasicTagEditorTests(TestCase):
    """The tag editor starts basic - name, regex, description, auto-apply and
    speeches - with the other conditions behind "more options"."""

    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)

    def test_add_page_has_more_options_collapsed(self):
        response = self.client.get(reverse('rule_tag_add'))
        self.assertContains(response, 'id="tagAdvancedToggle"')
        self.assertContains(response, 'id="tagAdvanced" hidden')
        self.assertFalse(response.context['advanced_open'])
        self.assertNotContains(response, 'tagPreviewButton')

    def test_new_tag_defaults_to_anywhere(self):
        response = self.client.get(reverse('rule_tag_add'))
        self.assertContains(response, '<option value="any" selected>')

    def test_more_options_open_when_the_tag_uses_them(self):
        tag = RuleTag.objects.create(name='pups', match_statuses=['P'])
        response = self.client.get(reverse('rule_tag_edit', args=[tag.pk]))
        self.assertTrue(response.context['advanced_open'])

    def test_more_options_stay_closed_for_a_plain_regex_tag(self):
        tag = RuleTag.objects.create(name='renloader', match_pattern='renpy')
        response = self.client.get(reverse('rule_tag_edit', args=[tag.pk]))
        self.assertFalse(response.context['advanced_open'])

    def test_tags_saved_without_scope_look_anywhere(self):
        post_json(self.client, 'rule_tag_save_api', {'name': 'renloader', 'match_pattern': 'renpy'})
        self.assertEqual(RuleTag.objects.get(name='renloader').match_scope, RuleTag.SCOPE_ANY)
