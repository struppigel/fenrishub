import json

from django.test import TestCase
from django.urls import reverse

from ..models import RuleTag, Speech
from .factories import make_user


class SpeechTriggerFormTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.tag = RuleTag.objects.create(name='renloader')
        self.builtin = RuleTag.objects.get(builtin_code='multiple_enabled_av')

    def _create(self, **extra):
        data = {'action': 'create', 'name': 'greeting', 'content': 'Hi {USERNAME}', **extra}
        return self.client.post(reverse('speeches'), data)

    def test_create_saves_trigger_tags_including_builtin(self):
        self._create(tags_present='1', trigger_tag_ids=[str(self.tag.pk), str(self.builtin.pk)])
        speech = Speech.objects.get(name='greeting')
        self.assertEqual(set(speech.trigger_tags.all()), {self.tag, self.builtin})

    def test_edit_replaces_trigger_tags(self):
        speech = Speech.objects.create(owner=self.user, name='greeting', content='x')
        speech.trigger_tags.add(self.tag)
        self.client.post(reverse('speeches'), {
            'action': 'edit', 'pk': speech.pk, 'name': 'greeting', 'content': 'x',
            'tags_present': '1', 'trigger_tag_ids': [str(self.builtin.pk)],
        })
        self.assertEqual(list(speech.trigger_tags.all()), [self.builtin])

    def test_edit_without_picker_keeps_trigger_tags(self):
        speech = Speech.objects.create(owner=self.user, name='greeting', content='x')
        speech.trigger_tags.add(self.tag)
        self.client.post(reverse('speeches'), {
            'action': 'edit', 'pk': speech.pk, 'name': 'greeting', 'content': 'y',
        })
        self.assertEqual(list(speech.trigger_tags.all()), [self.tag])

    def test_analyzer_config_and_api_share_the_speech_shape(self):
        speech = Speech.objects.create(owner=self.user, name='greeting', content='x')
        speech.trigger_tags.add(self.tag)
        speech.analyzer_users.add(self.user)

        from_api = self.client.get(reverse('speeches_api')).json()['speeches']
        page = self.client.get(reverse('log_analyzer'))
        from_page = json.loads(str(page.context['speeches_json']))

        self.assertEqual(from_api, from_page)
        greeting = next(s for s in from_api if s['name'] == 'greeting')
        self.assertEqual(greeting['trigger_tag_ids'], [self.tag.pk])
        self.assertEqual(
            set(greeting), {'id', 'name', 'category', 'content', 'trigger_tag_ids'},
        )


class SharedTagSpeechFallbackTests(TestCase):
    """Other helpers' shared, tagged speeches the analyst has not selected are
    handed to the analyzer as a fallback for tags without an own speech."""

    def setUp(self):
        self.user = make_user()
        self.other = make_user('bob')
        self.client.force_login(self.user)
        self.tag = RuleTag.objects.create(name='renloader')

        def speech(name, **extra):
            created = Speech.objects.create(owner=self.other, name=name, content='x', **extra)
            return created

        self.offered = speech('shared tagged', is_shared=True)
        self.offered.trigger_tags.add(self.tag)
        self.private = speech('private tagged')
        self.private.trigger_tags.add(self.tag)
        self.untagged = speech('shared untagged', is_shared=True)
        self.selected = speech('shared tagged selected', is_shared=True)
        self.selected.trigger_tags.add(self.tag)
        self.selected.analyzer_users.add(self.user)

    def _names(self, speeches):
        return sorted(entry['name'] for entry in speeches)

    def test_speeches_api_lists_only_others_shared_tagged_unselected(self):
        body = self.client.get(reverse('speeches_api')).json()
        self.assertEqual(self._names(body['shared_tag_speeches']), ['shared tagged (bob)'])
        self.assertEqual(body['shared_tag_speeches'][0]['trigger_tag_ids'], [self.tag.pk])

    def test_analyzer_page_config_has_the_same_list(self):
        page = self.client.get(reverse('log_analyzer'))
        from_page = json.loads(str(page.context['shared_tag_speeches_json']))
        self.assertEqual(self._names(from_page), ['shared tagged (bob)'])
