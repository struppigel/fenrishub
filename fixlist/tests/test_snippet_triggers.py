"""Snippets linked to rule tags, so the log analyzer suggests them.

Mirrors the speech triggers: set on the snippet editor or from the tag editor,
handed to the analyzer with the snippet, with other helpers' shared snippets
as the fallback, and visible through the token API.
"""

import json

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from ..models import ApiToken, FixlistSnippet, RuleTag
from .factories import make_user
from .test_llm_api import enable_api


def post_json(client, name, payload):
    return client.post(reverse(name), json.dumps(payload), content_type='application/json')


class SnippetTriggerFormTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.tag = RuleTag.objects.create(name='renloader')
        self.builtin = RuleTag.objects.get(builtin_code='multiple_enabled_av')

    def _snippet(self, **extra):
        return FixlistSnippet.objects.create(owner=self.user, name='cleanup', content='x', **extra)

    def test_add_saves_trigger_tags_including_builtin(self):
        self.client.post(reverse('add_snippet'), {
            'name': 'cleanup', 'content': 'x',
            'tags_present': '1', 'trigger_tag_ids': [str(self.tag.pk), str(self.builtin.pk)],
        })
        snippet = FixlistSnippet.objects.get(name='cleanup')
        self.assertEqual(set(snippet.trigger_tags.all()), {self.tag, self.builtin})

    def test_edit_replaces_trigger_tags(self):
        snippet = self._snippet()
        snippet.trigger_tags.add(self.tag)
        self.client.post(reverse('edit_snippet', args=[snippet.pk]), {
            'name': 'cleanup', 'content': 'x',
            'tags_present': '1', 'trigger_tag_ids': [str(self.builtin.pk)],
        })
        self.assertEqual(list(snippet.trigger_tags.all()), [self.builtin])

    def test_edit_without_picker_keeps_trigger_tags(self):
        snippet = self._snippet()
        snippet.trigger_tags.add(self.tag)
        self.client.post(reverse('edit_snippet', args=[snippet.pk]), {'name': 'cleanup', 'content': 'y'})
        snippet.refresh_from_db()
        self.assertEqual(snippet.content, 'y')
        self.assertEqual(list(snippet.trigger_tags.all()), [self.tag])

    def test_edit_page_seeds_the_picker(self):
        snippet = self._snippet()
        snippet.trigger_tags.add(self.tag)
        response = self.client.get(reverse('edit_snippet', args=[snippet.pk]))
        self.assertEqual([tag['id'] for tag in response.context['trigger_tags_json']], [self.tag.pk])
        self.assertContains(response, 'id="snippetTagPicker"')

    def test_rerender_after_an_error_keeps_the_picked_tags(self):
        response = self.client.post(reverse('add_snippet'), {
            'name': '', 'content': 'x', 'tags_present': '1', 'trigger_tag_ids': [str(self.tag.pk)],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual([tag['id'] for tag in response.context['trigger_tags_json']], [self.tag.pk])
        self.assertFalse(FixlistSnippet.objects.exists())

    def test_snippets_list_shows_the_tags(self):
        snippet = self._snippet()
        snippet.trigger_tags.add(self.tag)
        response = self.client.get(reverse('snippets'))
        self.assertContains(response, 'suggested for:')
        self.assertContains(response, 'renloader')

    def test_analyzer_config_and_api_share_the_snippet_shape(self):
        snippet = self._snippet()
        snippet.trigger_tags.add(self.tag)
        snippet.analyzer_users.add(self.user)

        from_api = self.client.get(reverse('snippets_api')).json()['snippets']
        page = self.client.get(reverse('log_analyzer'))
        from_page = json.loads(str(page.context['snippets_json']))

        self.assertEqual(from_api, from_page)
        self.assertEqual(from_api, [{
            'id': snippet.pk, 'name': 'cleanup', 'category': snippet.category,
            'content': 'x', 'trigger_tag_ids': [self.tag.pk],
        }])


class SharedTagSnippetFallbackTests(TestCase):
    """Other helpers' shared, tagged snippets the analyst has not selected are
    handed to the analyzer as a fallback for tags without an own snippet."""

    def setUp(self):
        self.user = make_user()
        self.other = make_user('bob')
        self.client.force_login(self.user)
        self.tag = RuleTag.objects.create(name='renloader')

        def snippet(name, **extra):
            return FixlistSnippet.objects.create(owner=self.other, name=name, content='x', **extra)

        self.offered = snippet('shared tagged', is_shared=True)
        self.offered.trigger_tags.add(self.tag)
        self.private = snippet('private tagged')
        self.private.trigger_tags.add(self.tag)
        self.untagged = snippet('shared untagged', is_shared=True)
        self.selected = snippet('shared tagged selected', is_shared=True)
        self.selected.trigger_tags.add(self.tag)
        self.selected.analyzer_users.add(self.user)

    def _names(self, snippets):
        return sorted(entry['name'] for entry in snippets)

    def test_snippets_api_lists_only_others_shared_tagged_unselected(self):
        body = self.client.get(reverse('snippets_api')).json()
        self.assertEqual(self._names(body['shared_tag_snippets']), ['shared tagged (bob)'])
        self.assertEqual(body['shared_tag_snippets'][0]['trigger_tag_ids'], [self.tag.pk])

    def test_analyzer_page_config_has_the_same_list(self):
        page = self.client.get(reverse('log_analyzer'))
        from_page = json.loads(str(page.context['shared_tag_snippets_json']))
        self.assertEqual(self._names(from_page), ['shared tagged (bob)'])
        self.assertContains(page, 'sharedTagSnippets:')


class TagSnippetLinkTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.other = make_user('bob')
        self.client.force_login(self.user)
        self.tag = RuleTag.objects.create(name='renloader')
        self.mine = FixlistSnippet.objects.create(owner=self.user, name='mine', content='x')
        self.theirs = FixlistSnippet.objects.create(owner=self.other, name='theirs', content='x', is_shared=True)
        self.theirs.trigger_tags.add(self.tag)

    def test_links_own_snippets_from_the_tag_editor(self):
        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'snippet_ids': [self.mine.pk]})
        self.assertEqual(list(self.mine.trigger_tags.all()), [self.tag])

    def test_unticking_removes_only_own_links(self):
        self.mine.trigger_tags.add(self.tag)
        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'snippet_ids': [self.theirs.pk]})
        self.assertFalse(self.mine.trigger_tags.exists())
        self.assertEqual(list(self.theirs.trigger_tags.all()), [self.tag])

    def test_saving_without_snippet_ids_keeps_links(self):
        self.mine.trigger_tags.add(self.tag)
        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'speech_ids': []})
        self.assertEqual(list(self.mine.trigger_tags.all()), [self.tag])

    def test_rejects_non_integer_snippet_ids(self):
        response = post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'snippet_ids': ['1']})
        self.assertEqual(response.status_code, 400)
        self.assertIn('snippet_ids', response.json()['error'])

    def test_editor_lists_own_and_others_snippets(self):
        self.mine.trigger_tags.add(self.tag)
        response = self.client.get(reverse('rule_tag_edit', args=[self.tag.pk]))
        self.assertIn(
            {'id': self.mine.pk, 'name': 'mine', 'category': self.mine.category, 'linked': True},
            response.context['linkable_snippets_json'],
        )
        self.assertEqual(list(response.context['others_snippets']), [self.theirs])
        self.assertContains(response, 'id="tagSnippetSearch"')

    def test_selected_shared_snippet_of_another_helper_can_be_linked(self):
        selected = FixlistSnippet.objects.create(owner=self.other, name='selected', content='x', is_shared=True)
        selected.analyzer_users.add(self.user)

        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'snippet_ids': [selected.pk]})
        self.assertEqual(list(selected.trigger_tags.all()), [self.tag])

        post_json(self.client, 'rule_tag_save_api', {'id': self.tag.pk, 'snippet_ids': []})
        self.assertFalse(selected.trigger_tags.exists())
        # A snippet the user has not selected keeps its link.
        self.assertEqual(list(self.theirs.trigger_tags.all()), [self.tag])

    def test_tags_list_counts_snippets(self):
        response = self.client.get(reverse('rule_tags'))
        self.assertContains(response, '1 snippet')


class SnippetTagApiTests(TestCase):
    def setUp(self):
        cache.clear()
        enable_api()
        self.admin = User.objects.create_superuser(username='root', password='pw')
        self.helper = make_user('alice')
        _token, self.write_raw = ApiToken.issue(self.admin, 'write', can_write=True)
        _token, self.helper_raw = ApiToken.issue(self.helper, 'read')
        self.tag = RuleTag.objects.create(name='renloader')

    def get(self, name, *args):
        return self.client.get(
            reverse(name, args=args), secure=True, HTTP_AUTHORIZATION=f'Bearer {self.helper_raw}',
        )

    def post(self, name, *args, body=None):
        return self.client.post(
            reverse(name, args=args), json.dumps(body or {}), content_type='application/json',
            secure=True, HTTP_AUTHORIZATION=f'Bearer {self.write_raw}',
        )

    def test_snippet_payload_names_its_trigger_tags(self):
        snippet = FixlistSnippet.objects.create(owner=self.helper, name='cleanup', content='x')
        snippet.trigger_tags.add(self.tag)
        body = self.get('api_v1_snippet', snippet.pk).json()
        self.assertEqual(body['trigger_tags'], [{'tag_id': self.tag.pk, 'name': 'renloader'}])
        self.assertNotIn('is_fix_message', body)
        listed = self.get('api_v1_snippets').json()['snippets']
        self.assertEqual(listed[0]['trigger_tags'], [{'tag_id': self.tag.pk, 'name': 'renloader'}])

    def test_tag_lists_its_visible_snippets_and_counts_all(self):
        private = FixlistSnippet.objects.create(owner=self.admin, name='private', content='x')
        shared = FixlistSnippet.objects.create(owner=self.admin, name='shared', content='x', is_shared=True)
        self.tag.snippets.add(private, shared)

        body = self.get('api_v1_tag', self.tag.pk).json()
        self.assertEqual(body['snippet_count'], 2)
        self.assertEqual(body['snippets'], [{'snippet_id': shared.pk, 'name': 'shared', 'owner': 'root'}])
        summary = next(tag for tag in self.get('api_v1_tags').json()['tags'] if tag['tag_id'] == self.tag.pk)
        self.assertEqual(summary['snippet_count'], 2)

    def test_tag_write_links_snippets(self):
        own = FixlistSnippet.objects.create(owner=self.admin, name='own', content='x')
        self.post('api_v1_tag_update', self.tag.pk, body={'snippet_ids': [own.pk]})
        self.assertEqual(list(own.trigger_tags.all()), [self.tag])

        response = self.post('api_v1_tag_create', body={'name': 'adware', 'snippet_ids': [own.pk]})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(sorted(tag.name for tag in own.trigger_tags.all()), ['adware', 'renloader'])
