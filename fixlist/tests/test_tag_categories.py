"""Tests for tag categories: the category page, picking one for a tag, and the
colour class every tag badge gets from it."""

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import RequestFactory, TestCase
from django.urls import reverse

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..context_processors import tag_category_colors
from ..models import (
    InfectionCase, InfectionCaseLog, RuleTag, Speech, TagCategory, UploadedLog, UploadedLogAnalysis,
)
from ..tagging import attach_rule_tags, found_tags_by_upload, save_tag, serialize_tag
from ..templatetags.rule_tags import tag_category_class
from .factories import make_rule


class TagCategorySetupMixin:
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username='alice', password='pw')
        self.client.login(username='alice', password='pw')
        self.default = TagCategory.get_default()
        self.malware = TagCategory.objects.create(name='malware', color='#ff4444')
        self.tag = RuleTag.objects.create(name='miner', category=self.malware)
        # Created without a category: it lands in the default one.
        self.plain = RuleTag.objects.create(name='plain')
        self.rule = make_rule('C:\\miner.exe')
        self.rule.tags.add(self.tag, self.plain)


class TagCategoryPageTests(TagCategorySetupMixin, TestCase):

    def _post(self, **data):
        return self.client.post(reverse('tag_categories'), data)

    def test_lists_the_default_first_with_tag_counts(self):
        response = self.client.get(reverse('tag_categories'))

        self.assertContains(response, 'value="malware"')
        categories = list(response.context['categories'])
        self.assertEqual([category.pk for category in categories], [self.default.pk, self.malware.pk])
        # The default also holds the built-in tags seeded by migration 0079.
        self.assertEqual(
            [category.tag_count for category in categories],
            [RuleTag.objects.filter(category=self.default).count(), 1],
        )

    def test_migration_seeds_the_default_category(self):
        self.assertEqual(TagCategory.objects.filter(is_default=True).count(), 1)
        self.assertEqual(self.default.color, '#8eb6d8')
        self.assertEqual(self.plain.category_id, self.default.pk)

    def test_add_category(self):
        response = self._post(action='add', name='adware', color='#33AA33')

        self.assertRedirects(response, reverse('tag_categories'))
        self.assertEqual(TagCategory.objects.get(name='adware').color, '#33aa33')

    def test_edit_category(self):
        self._post(action='edit', pk=self.malware.pk, name='bad stuff', color='#000000')

        self.malware.refresh_from_db()
        self.assertEqual((self.malware.name, self.malware.color), ('bad stuff', '#000000'))
        self.assertEqual(self.malware.updated_by, self.user)

    def test_rejects_duplicate_name_ignoring_case(self):
        self._post(action='add', name='MALWARE', color='#123456')

        self.assertEqual(TagCategory.objects.count(), 2)

    def test_rejects_bad_color_and_empty_name(self):
        self._post(action='add', name='x', color='red')
        self._post(action='add', name='', color='#123456')
        self._post(action='edit', pk=self.malware.pk, name='malware', color='#12345')

        self.assertEqual(TagCategory.objects.count(), 2)
        self.malware.refresh_from_db()
        self.assertEqual(self.malware.color, '#ff4444')

    def test_delete_moves_tags_to_the_default_category(self):
        self._post(action='delete', pk=self.malware.pk)

        self.assertFalse(TagCategory.objects.filter(pk=self.malware.pk).exists())
        self.tag.refresh_from_db()
        self.assertEqual(self.tag.category_id, self.default.pk)

    def test_the_default_category_cannot_be_deleted_but_can_be_recoloured(self):
        self._post(action='delete', pk=self.default.pk)
        self.assertTrue(TagCategory.objects.filter(pk=self.default.pk).exists())

        self._post(action='edit', pk=self.default.pk, name='standard', color='#abcdef')
        self.default.refresh_from_db()
        self.assertEqual(
            (self.default.name, self.default.color, self.default.is_default), ('standard', '#abcdef', True),
        )

    def test_default_row_has_no_delete_button(self):
        response = self.client.get(reverse('tag_categories'))

        self.assertContains(response, 'value="delete"', count=1)

    def test_requires_login(self):
        self.client.logout()

        response = self.client.get(reverse('tag_categories'))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response['Location'])

    def test_tag_overview_links_to_categories_and_colours_the_names(self):
        response = self.client.get(reverse('rule_tags'))

        self.assertContains(response, reverse('tag_categories'))
        self.assertContains(response, f'tag-chip tag-row-name tag-cat-{self.malware.pk}')


class SaveTagCategoryTests(TagCategorySetupMixin, TestCase):

    def test_sets_the_category_and_null_means_the_default(self):
        tag, error = save_tag(self.user, self.plain, {'category_id': self.malware.pk})
        self.assertIsNone(error)
        self.assertEqual(tag.category_id, self.malware.pk)

        tag, error = save_tag(self.user, self.plain, {'category_id': None})
        self.assertIsNone(error)
        self.assertEqual(tag.category_id, self.default.pk)

    def test_a_new_tag_without_a_category_gets_the_default(self):
        tag, error = save_tag(self.user, None, {'name': 'fresh'})

        self.assertIsNone(error)
        self.assertEqual(tag.category_id, self.default.pk)

    def test_keeps_the_category_when_absent(self):
        tag, error = save_tag(self.user, self.tag, {'description': 'coin miners'})

        self.assertIsNone(error)
        self.assertEqual(tag.category_id, self.malware.pk)

    def test_rejects_an_unknown_or_malformed_category(self):
        self.assertEqual(save_tag(self.user, self.plain, {'category_id': 99999})[1], 'That tag category does not exist.')
        self.assertIn('integer or null', save_tag(self.user, self.plain, {'category_id': '1'})[1])
        self.assertIn('integer or null', save_tag(self.user, self.plain, {'category_id': True})[1])

    def test_editor_save_api_sets_the_category(self):
        response = self.client.post(
            reverse('rule_tag_save_api'),
            {'id': self.plain.pk, 'name': 'plain', 'category_id': self.malware.pk},
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['tag']['category'], {'id': self.malware.pk, 'name': 'malware', 'color': '#ff4444'})

    def test_editor_offers_the_categories_in_its_basic_fields(self):
        response = self.client.get(reverse('rule_tag_edit', args=[self.tag.pk]))

        self.assertContains(response, f'<option value="{self.default.pk}">default</option>', html=True)
        self.assertContains(
            response, f'<option value="{self.malware.pk}" selected>malware</option>', html=True,
        )
        content = response.content.decode()
        self.assertLess(content.index('id="tagCategory"'), content.index('id="tagAdvanced"'))

    def test_new_tag_preselects_the_default_category(self):
        response = self.client.get(reverse('rule_tag_add'))

        self.assertContains(
            response, f'<option value="{self.default.pk}" selected>default</option>', html=True,
        )


class TagCategoryColourTests(TagCategorySetupMixin, TestCase):

    def test_context_processor_emits_valid_colours_only(self):
        broken = TagCategory.objects.create(name='broken', color='#000000')
        TagCategory.objects.filter(pk=broken.pk).update(color='red;}a{')

        with self.assertLogs('fixlist.context_processors', level='WARNING'):
            colours = tag_category_colors(RequestFactory().get('/'))['tag_category_colors']

        self.assertEqual(
            sorted(colours, key=lambda colour: colour['id']),
            [{'id': self.default.pk, 'color': '#8eb6d8'}, {'id': self.malware.pk, 'color': '#ff4444'}],
        )

    def test_base_template_writes_the_colour_rule(self):
        response = self.client.get(reverse('rule_tags'))

        self.assertContains(
            response,
            f'.tag-chip.tag-cat-{self.malware.pk}, .line-tag-chip.tag-cat-{self.malware.pk} '
            '{ color: #ff4444; border-color: #ff4444; }',
        )

    def test_filter_takes_models_and_dicts(self):
        self.assertEqual(tag_category_class(self.tag), f' tag-cat-{self.malware.pk}')
        self.assertEqual(tag_category_class(self.plain), f' tag-cat-{self.default.pk}')
        self.assertEqual(tag_category_class({'category_id': self.malware.pk}), f' tag-cat-{self.malware.pk}')
        self.assertEqual(tag_category_class({'category_id': None}), '')

    def test_tag_dicts_carry_the_category(self):
        self.assertEqual(serialize_tag(self.tag)['category_id'], self.malware.pk)
        self.assertEqual(
            serialize_tag(self.plain)['category'], {'id': self.default.pk, 'name': 'default', 'color': '#8eb6d8'},
        )

        payload = {
            'format': ANALYSIS_PAYLOAD_FORMAT,
            'lines': [{'line': 'x', 'rule_ids': [self.rule.pk]}],
            'warnings': [],
        }
        by_id = {tag['id']: tag for tag in attach_rule_tags(payload)['rule_tags']}
        self.assertEqual(by_id[self.tag.pk]['category_id'], self.malware.pk)
        self.assertEqual(by_id[self.plain.pk]['category_id'], self.default.pk)

    def _tagged_log(self, upload_id='coloured', content='needle'):
        log = UploadedLog.objects.create(
            upload_id=upload_id, forum_username='poster', original_filename='x.txt',
            content=content, log_type='FRST', recipient_user=self.user,
        )
        UploadedLogAnalysis.objects.create(
            upload=log, rule_set_key='shared', source_content_hash=log.content_hash,
            payload={
                'format': ANALYSIS_PAYLOAD_FORMAT,
                'lines': [{'line': content, 'rule_ids': [self.rule.pk]}],
                'warnings': [],
            },
        )
        return log

    def test_found_tags_carry_the_category(self):
        log = self._tagged_log()

        by_name = {tag['name']: tag for tag in found_tags_by_upload([log.pk], 'shared')[log.pk]}

        self.assertEqual(by_name['miner']['category_id'], self.malware.pk)
        self.assertEqual(by_name['plain']['category_id'], self.default.pk)

    def test_uploads_list_and_log_search_colour_the_tag_text(self):
        self._tagged_log()
        tags_line = (
            '<div class="fixlist-meta upload-tags">tags: '
            f'<span class="tag-text tag-cat-{self.malware.pk}" title="">miner</span>, '
            f'<span class="tag-text tag-cat-{self.default.pk}" title="">plain</span></div>'
        )

        for response in (
            self.client.get(reverse('uploaded_logs')),
            self.client.get(reverse('log_search'), {'q': 'needle'}),
        ):
            self.assertContains(response, tags_line, html=True)

        self.assertNotContains(self.client.get(reverse('uploaded_logs')), 'class="tag-chip')

    def test_base_colours_tag_text_by_category(self):
        response = self.client.get(reverse('uploaded_logs'))

        self.assertContains(response, f'.tag-text.tag-cat-{self.malware.pk} {{ color: #ff4444; }}')

    def test_rules_list_colours_the_badges(self):
        response = self.client.get(reverse('rules'), {'filter': 'all'})

        self.assertContains(response, f'class="tag-chip tag-cat-{self.malware.pk}"')

    def test_speeches_page_colours_trigger_badges(self):
        speech = Speech.objects.create(owner=self.user, name='mining speech', content='Remove the miner.')
        speech.trigger_tags.add(self.tag)

        response = self.client.get(reverse('speeches'))

        self.assertContains(response, f'class="tag-chip tag-cat-{self.malware.pk}"')


class TagCategoryPriorityTests(TagCategorySetupMixin, TestCase):

    def _post(self, **data):
        return self.client.post(reverse('tag_categories'), data)

    def _tags_line(self, *tags):
        spans = ', '.join(f'<span class="tag-text tag-cat-{tag.category_id}" title="">{tag.name}</span>' for tag in tags)
        return f'<div class="fixlist-meta upload-tags">tags: {spans}</div>'

    def _tagged_case_log(self):
        log = UploadedLog.objects.create(
            upload_id='prioritised', forum_username='poster', original_filename='x.txt',
            content='needle', log_type='FRST', recipient_user=self.user,
        )
        UploadedLogAnalysis.objects.create(
            upload=log, rule_set_key='shared', source_content_hash=log.content_hash,
            payload={
                'format': ANALYSIS_PAYLOAD_FORMAT,
                'lines': [{'line': 'needle', 'rule_ids': [self.rule.pk]}],
                'warnings': [],
            },
        )
        # Linked by hand; auto-assign would link the log itself.
        case = InfectionCase.objects.create(owner=self.user, username='poster', auto_assign_new_items=False)
        InfectionCaseLog.objects.create(case=case, uploaded_log=log, added_by=self.user)
        return case

    def test_categories_default_to_priority_5(self):
        self.assertEqual((self.default.priority, self.malware.priority), (5, 5))
        self._post(action='add', name='adware', color='#33aa33')
        self.assertEqual(TagCategory.objects.get(name='adware').priority, 5)

    def test_add_and_edit_set_the_priority(self):
        self._post(action='add', name='adware', color='#33aa33', priority='0')
        self._post(action='edit', pk=self.malware.pk, name='malware', color='#ff4444', priority='9')

        self.assertEqual(TagCategory.objects.get(name='adware').priority, 0)
        self.malware.refresh_from_db()
        self.assertEqual(self.malware.priority, 9)

    def test_edit_without_priority_keeps_it(self):
        TagCategory.objects.filter(pk=self.malware.pk).update(priority=2)

        self._post(action='edit', pk=self.malware.pk, name='renamed', color='#ff4444')

        self.malware.refresh_from_db()
        self.assertEqual((self.malware.name, self.malware.priority), ('renamed', 2))

    def test_rejects_invalid_priorities(self):
        for priority in ('11', '-1', 'abc', '2.5'):
            self._post(action='edit', pk=self.malware.pk, name='changed', color='#ff4444', priority=priority)
            self._post(action='add', name='adware', color='#33aa33', priority=priority)

        self.malware.refresh_from_db()
        self.assertEqual((self.malware.name, self.malware.priority), ('malware', 5))
        self.assertFalse(TagCategory.objects.filter(name='adware').exists())

    def test_page_offers_priorities_0_to_10(self):
        response = self.client.get(reverse('tag_categories'))

        self.assertContains(response, '<option value="0">priority 0 (hidden in uploads and cases)</option>', html=True)
        self.assertContains(response, '<option value="10">priority 10</option>', html=True)

    def test_priority_0_hides_tags_in_uploads_and_cases_but_not_log_search(self):
        TagCategory.objects.filter(pk=self.default.pk).update(priority=0)
        case = self._tagged_case_log()

        for response in (
            self.client.get(reverse('uploaded_logs')),
            self.client.get(reverse('view_infection_case', args=[case.case_id])),
        ):
            self.assertContains(response, self._tags_line(self.tag), html=True)
            self.assertNotContains(response, '>plain</span>')

        search = self.client.get(reverse('log_search'), {'q': 'needle'})
        self.assertContains(search, self._tags_line(self.tag, self.plain), html=True)

    def test_higher_priority_tags_come_first(self):
        TagCategory.objects.filter(pk=self.default.pk).update(priority=9)
        case = self._tagged_case_log()

        for response in (
            self.client.get(reverse('uploaded_logs')),
            self.client.get(reverse('view_infection_case', args=[case.case_id])),
        ):
            self.assertContains(response, self._tags_line(self.plain, self.tag), html=True)

    def test_found_tags_carry_the_category_priority(self):
        TagCategory.objects.filter(pk=self.malware.pk).update(priority=3)
        self._tagged_case_log()
        log = UploadedLog.objects.get(upload_id='prioritised')

        by_name = {tag['name']: tag for tag in found_tags_by_upload([log.pk], 'shared')[log.pk]}

        self.assertEqual((by_name['miner']['category_priority'], by_name['plain']['category_priority']), (3, 5))
