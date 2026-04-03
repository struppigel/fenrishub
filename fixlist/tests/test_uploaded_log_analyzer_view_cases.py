from unittest.mock import patch

from django.contrib.auth.models import User
from django.http import HttpResponse
from django.test import RequestFactory
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone as tz

from ..models import UploadedLog
from ..views import log_analyzer_view
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


class UploadedLogAnalyzerViewTests(UploadedLogSharedSetupMixin, TestCase):

    def test_log_analyzer_view_passes_initial_upload_id_from_query(self):
        uploaded = UploadedLog.objects.create(
            upload_id='silver-river',
            reddit_username='reddit_name',
            original_filename='single.txt',
            content='payload',
        )
        request = RequestFactory().get(
            reverse('log_analyzer'),
            {'upload_id': uploaded.upload_id},
        )
        request.user = self.user

        with patch('fixlist.views.analyzer.render', return_value=HttpResponse('ok')) as mock_render:
            response = log_analyzer_view(request)

        rendered_context = mock_render.call_args.args[2]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(rendered_context.get('initial_upload_id'), uploaded.upload_id)

    def test_log_analyzer_view_passes_is_superuser_true_for_superuser(self):
        superuser = User.objects.create_superuser(
            username='admin', password='password123',
        )
        request = RequestFactory().get(reverse('log_analyzer'))
        request.user = superuser

        with patch('fixlist.views.analyzer.render', return_value=HttpResponse('ok')) as mock_render:
            log_analyzer_view(request)

        rendered_context = mock_render.call_args.args[2]
        self.assertTrue(rendered_context.get('is_superuser'))

    def test_log_analyzer_view_passes_is_superuser_false_for_regular_user(self):
        request = RequestFactory().get(reverse('log_analyzer'))
        request.user = self.user

        with patch('fixlist.views.analyzer.render', return_value=HttpResponse('ok')) as mock_render:
            log_analyzer_view(request)

        rendered_context = mock_render.call_args.args[2]
        self.assertFalse(rendered_context.get('is_superuser'))

    def test_log_analyzer_excludes_trashed_uploads(self):
        active = UploadedLog.objects.create(
            upload_id='active-log',
            reddit_username='reddit_name',
            original_filename='active.txt',
            content='payload',
        )
        trashed = UploadedLog.objects.create(
            upload_id='trashed-log',
            reddit_username='reddit_name',
            original_filename='trashed.txt',
            content='payload',
            deleted_at=tz.now(),
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('log_analyzer'))

        self.assertContains(response, 'active-log')
        self.assertNotContains(response, 'trashed-log')

