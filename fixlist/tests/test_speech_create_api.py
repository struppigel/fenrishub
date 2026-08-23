"""Tests for the analyzer's create-a-speech-from-marked-text endpoint."""
import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import Speech


class SpeechCreateApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.other_user = User.objects.create_user(username='bob', password='password123')
        self.client.login(username='alice', password='password123')
        self.url = reverse('speech_create_api')

    def _post(self, payload):
        return self.client.post(self.url, json.dumps(payload), content_type='application/json')

    def test_requires_login(self):
        self.client.logout()
        response = self._post({'name': 'greeting', 'content': 'hello'})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_rejects_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)

    def test_rejects_invalid_json(self):
        response = self.client.post(self.url, 'not json', content_type='application/json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json())

    def test_rejects_blank_name(self):
        response = self._post({'name': '   ', 'content': 'hello'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('name is required', response.json()['error'])
        self.assertFalse(Speech.objects.exists())

    def test_rejects_blank_content(self):
        response = self._post({'name': 'greeting', 'content': '   '})
        self.assertEqual(response.status_code, 400)
        self.assertIn('content is required', response.json()['error'])
        self.assertFalse(Speech.objects.exists())

    def test_rejects_overlong_name(self):
        response = self._post({'name': 'x' * 256, 'content': 'hello'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json())
        self.assertFalse(Speech.objects.exists())

    def test_rejects_overlong_category(self):
        response = self._post({'name': 'greeting', 'content': 'hello', 'category': 'c' * 256})
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.json())
        self.assertFalse(Speech.objects.exists())

    def test_rejects_non_string_name(self):
        response = self._post({'name': 42, 'content': 'hello'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('must be a string', response.json()['error'])

    def test_rejects_non_boolean_is_shared(self):
        response = self._post({'name': 'greeting', 'content': 'hello', 'is_shared': 'yes'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('must be a boolean', response.json()['error'])

    def test_rejects_duplicate_name_and_leaves_original_intact(self):
        Speech.objects.create(owner=self.user, name='greeting', content='original')

        response = self._post({'name': 'greeting', 'content': 'replacement'})

        self.assertEqual(response.status_code, 400)
        self.assertIn('already exists', response.json()['error'])
        self.assertEqual(Speech.objects.get(owner=self.user, name='greeting').content, 'original')

    def test_creates_speech_and_selects_it_for_the_analyzer(self):
        response = self._post({
            'name': 'greeting',
            'content': 'Hi {USERNAME}, welcome.',
            'category': 'intro',
            'is_shared': True,
        })

        self.assertEqual(response.status_code, 200)
        speech = Speech.objects.get(owner=self.user, name='greeting')
        self.assertEqual(speech.content, 'Hi {USERNAME}, welcome.')
        self.assertEqual(speech.category, 'intro')
        self.assertTrue(speech.is_shared)
        self.assertTrue(speech.analyzer_users.filter(pk=self.user.pk).exists())

    def test_response_matches_speeches_api_shape(self):
        response = self._post({'name': 'greeting', 'content': 'hello', 'category': 'intro'})

        speech = Speech.objects.get(owner=self.user, name='greeting')
        self.assertEqual(response.json(), {'speech': {
            'id': speech.id,
            'name': 'greeting',
            'category': 'intro',
            'content': 'hello',
        }})

    def test_category_defaults_to_generic(self):
        self._post({'name': 'greeting', 'content': 'hello'})

        speech = Speech.objects.get(owner=self.user, name='greeting')
        self.assertEqual(speech.category, Speech.DEFAULT_CATEGORY)

    def test_blank_category_falls_back_to_generic(self):
        self._post({'name': 'greeting', 'content': 'hello', 'category': '  '})

        speech = Speech.objects.get(owner=self.user, name='greeting')
        self.assertEqual(speech.category, Speech.DEFAULT_CATEGORY)

    def test_is_shared_defaults_to_false(self):
        self._post({'name': 'greeting', 'content': 'hello'})

        self.assertFalse(Speech.objects.get(owner=self.user, name='greeting').is_shared)

    def test_name_is_only_unique_per_owner(self):
        Speech.objects.create(owner=self.other_user, name='greeting', content='bob version')

        response = self._post({'name': 'greeting', 'content': 'alice version'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(Speech.objects.filter(name='greeting').count(), 2)

    def test_new_speech_appears_in_the_analyzer_speeches_api(self):
        self._post({'name': 'greeting', 'content': 'hello', 'category': 'intro'})

        response = self.client.get(reverse('speeches_api'))

        self.assertEqual(response.json()['speeches'], [{
            'id': Speech.objects.get(name='greeting').id,
            'name': 'greeting',
            'category': 'intro',
            'content': 'hello',
        }])
