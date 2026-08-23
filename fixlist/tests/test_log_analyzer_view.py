import re
from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone as tz

from ..views import log_analyzer_view
from .factories import make_superuser, make_uploaded_log
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


class LogAnalyzerViewTests(UploadedLogSharedSetupMixin, TestCase):

    def _render_with_user(self, user, **get_params):
        request = RequestFactory().get(reverse('log_analyzer'), get_params)
        request.user = user
        with patch('fixlist.views.analyzer.render', return_value=HttpResponse('ok')) as mock_render:
            response = log_analyzer_view(request)
        return response, mock_render.call_args.args[2]

    def test_passes_initial_upload_id_from_query(self):
        uploaded = make_uploaded_log(upload_id='silver-river', original_filename='single.txt')

        response, context = self._render_with_user(self.user, upload_id=uploaded.upload_id)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(context.get('initial_upload_id'), uploaded.upload_id)

    def test_passes_is_superuser_true_for_superuser(self):
        _, context = self._render_with_user(make_superuser())

        self.assertTrue(context.get('is_superuser'))

    def test_passes_is_superuser_false_for_regular_user(self):
        _, context = self._render_with_user(self.user)

        self.assertFalse(context.get('is_superuser'))

    def test_excludes_trashed_uploads(self):
        make_uploaded_log(upload_id='active-log', original_filename='active.txt')
        make_uploaded_log(upload_id='trashed-log', original_filename='trashed.txt', deleted_at=tz.now())
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('log_analyzer'))

        self.assertContains(response, 'active-log')
        self.assertNotContains(response, 'trashed-log')

    def test_renders_speech_capture_button_and_modal(self):
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('log_analyzer'))

        self.assertContains(response, 'id="addSpeechButton"')
        self.assertContains(response, 'id="speechCaptureModal"')
        self.assertContains(response, 'id="speechCaptureName"')
        self.assertContains(response, 'id="speechCaptureCategory"')
        self.assertContains(response, 'id="speechCaptureContent"')
        self.assertContains(response, 'id="speechCaptureShared"')
        self.assertContains(response, 'id="speechCapturePlaceholders"')

    def test_speech_capture_shares_by_default(self):
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('log_analyzer'))

        shared = re.search(r'<input[^>]*id="speechCaptureShared"[^>]*>', response.content.decode())
        self.assertIsNotNone(shared)
        self.assertIn('checked', shared.group(0))

    def test_speech_capture_button_starts_hidden_and_disabled(self):
        """It belongs to the response panel and needs marked text, neither of
        which is true on a freshly loaded page."""
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('log_analyzer'))

        button = re.search(r'<button[^>]*id="addSpeechButton"[^>]*>', response.content.decode())
        self.assertIsNotNone(button)
        self.assertIn('disabled', button.group(0))
        self.assertIn('hidden', button.group(0))

    def test_exposes_speech_create_url_to_the_frontend(self):
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('log_analyzer'))

        self.assertContains(response, f'speechCreateUrl: "{reverse("speech_create_api")}"')

    def test_loads_the_speech_capture_script(self):
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('log_analyzer'))

        self.assertContains(response, 'log_analyzer/speech_capture.js')
