from django.test import TestCase
from django.urls import reverse

from ..models import UploadedLog
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


class UploadedLogDiffViewTests(UploadedLogSharedSetupMixin, TestCase):

    def test_diff_view_requires_login(self):
        response = self.client.get(reverse('diff_uploaded_logs', args=['a', 'b']))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_diff_view_returns_200_for_two_valid_uploads(self):
        log1 = UploadedLog.objects.create(
            upload_id='haze-north',
            reddit_username='reddit_name',
            original_filename='a.txt',
            content='line1\nline2\nline3',
        )
        log2 = UploadedLog.objects.create(
            upload_id='haze-south',
            reddit_username='reddit_name',
            original_filename='b.txt',
            content='line1\nchanged\nline3',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('diff_uploaded_logs', args=[log1.upload_id, log2.upload_id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, log1.upload_id)
        self.assertContains(response, log2.upload_id)

    def test_diff_view_marks_changed_and_equal_rows(self):
        log1 = UploadedLog.objects.create(
            upload_id='iron-peak',
            reddit_username='reddit_name',
            original_filename='a.txt',
            content='same\nold line\nsame',
        )
        log2 = UploadedLog.objects.create(
            upload_id='iron-vale',
            reddit_username='reddit_name',
            original_filename='b.txt',
            content='same\nnew line\nsame',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('diff_uploaded_logs', args=[log1.upload_id, log2.upload_id]))
        html = response.content.decode()

        self.assertIn('diff-row-equal', html)
        self.assertIn('diff-row-replace', html)
        self.assertEqual(response.context['equal_count'], 2)
        self.assertEqual(response.context['changed_count'], 1)

    def test_diff_view_identical_logs_show_zero_changed(self):
        log1 = UploadedLog.objects.create(
            upload_id='jade-ridge',
            reddit_username='reddit_name',
            original_filename='a.txt',
            content='identical\ncontent',
        )
        log2 = UploadedLog.objects.create(
            upload_id='jade-coast',
            reddit_username='reddit_name',
            original_filename='b.txt',
            content='identical\ncontent',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('diff_uploaded_logs', args=[log1.upload_id, log2.upload_id]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['changed_count'], 0)
        self.assertEqual(response.context['equal_count'], 2)

