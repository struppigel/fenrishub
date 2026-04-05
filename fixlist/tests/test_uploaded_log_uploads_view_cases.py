from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse
from unittest.mock import patch

from ..forms import UploadedLogForm
from ..models import UploadedLog
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


class UploadedLogUploadsViewTests(UploadedLogSharedSetupMixin, TestCase):

    def test_uploaded_log_form_uses_charset_normalizer_detection(self):
        class _DetectedText:
            def __str__(self):
                return 'Detected line\nSecond line'

        with patch('fixlist.forms.from_bytes') as mocked_from_bytes:
            mocked_from_bytes.return_value.best.return_value = _DetectedText()
            form = UploadedLogForm(
                data={'reddit_username': 'reddit_name'},
                files={'log_file': SimpleUploadedFile('sample.txt', b'\x81\x82\x83', content_type='text/plain')},
            )

            self.assertTrue(form.is_valid(), form.errors)
            self.assertEqual(form.cleaned_data['log_file'].decoded_content, 'Detected line\nSecond line')

    def test_uploaded_log_form_falls_back_when_detected_text_is_invalid(self):
        class _DetectedInvalidText:
            def __str__(self):
                return '\ufffd\ufffd\x00\ufffd\ufffd'

        # UTF-16-LE encoded text without BOM should be accepted via fallback
        # when detector output is invalid.
        payload = 'Addition line\nSecond line'.encode('utf-16-le')
        with patch('fixlist.forms.from_bytes') as mocked_from_bytes:
            mocked_from_bytes.return_value.best.return_value = _DetectedInvalidText()
            form = UploadedLogForm(
                data={'reddit_username': 'reddit_name'},
                files={'log_file': SimpleUploadedFile('Addition.txt', payload, content_type='text/plain')},
            )

            self.assertTrue(form.is_valid(), form.errors)
            self.assertEqual(form.cleaned_data['log_file'].decoded_content, 'Addition line\nSecond line')

    def test_uploaded_log_form_prefers_readable_candidate_over_mojibake_detector_output(self):
        source_text = 'Additional scan result of Farbar Recovery Scan Tool\nRan by nickl'
        detector_mojibake = source_text.encode('utf-8').decode('utf-16-le', errors='ignore')

        class _DetectedMojibakeText:
            def __str__(self):
                return detector_mojibake

        with patch('fixlist.forms.from_bytes') as mocked_from_bytes:
            mocked_from_bytes.return_value.best.return_value = _DetectedMojibakeText()
            form = UploadedLogForm(
                data={'reddit_username': 'reddit_name'},
                files={
                    'log_file': SimpleUploadedFile(
                        'Addition.txt',
                        source_text.encode('utf-8'),
                        content_type='text/plain',
                    )
                },
            )

            self.assertTrue(form.is_valid(), form.errors)
            self.assertEqual(form.cleaned_data['log_file'].decoded_content, source_text)

    def test_uploaded_log_form_ascii_with_form_feed_not_decoded_as_utf16le(self):
        source_text = 'Additional scan result of Farbar Recovery Scan Tool\n\x0cRan by nickl'
        payload = source_text.encode('utf-8')
        form = UploadedLogForm(
            data={'reddit_username': 'reddit_name'},
            files={
                'log_file': SimpleUploadedFile(
                    'Addition.txt', payload, content_type='text/plain',
                )
            },
        )

        self.assertTrue(form.is_valid(), form.errors)
        decoded = form.cleaned_data['log_file'].decoded_content
        self.assertIn('Farbar Recovery Scan Tool', decoded)
        self.assertNotIn('\x0c', decoded)

    def test_upload_log_view_logs_context_on_unhandled_exception(self):
        with (
            patch('fixlist.views.uploads.UploadedLog.objects.create', side_effect=RuntimeError('boom')),
            patch('fixlist.views.uploads.logger.exception') as mocked_logger,
        ):
            with self.assertRaises(RuntimeError):
                self.client.post(
                    reverse('upload_log'),
                    {
                        'reddit_username': 'reddit_name',
                        'log_file': SimpleUploadedFile('Addition.txt', b'line-a\nline-b', content_type='text/plain'),
                    },
                    REMOTE_ADDR='203.0.113.10',
                )

        self.assertTrue(mocked_logger.called)

    def test_upload_log_view_allows_anonymous_upload_and_returns_id(self):
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('sample.txt', b'line-a\nline-b', content_type='text/plain'),
            },
        )

        uploaded = UploadedLog.objects.get(reddit_username='reddit_name')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('upload_log'))
        self.assertEqual(uploaded.original_filename, 'sample.txt')

        first_get = self.client.get(reverse('upload_log'))
        self.assertEqual(first_get.status_code, 200)
        self.assertContains(first_get, uploaded.upload_id)
        self.assertContains(first_get, 'id="uploadedLogId"')

        second_get = self.client.get(reverse('upload_log'))
        self.assertEqual(second_get.status_code, 200)
        self.assertNotContains(second_get, 'id="uploadedLogId"')
        self.assertEqual(UploadedLog.objects.count(), 1)
        self.assertEqual(uploaded.total_line_count, 2)
        self.assertEqual(uploaded.count_unknown, 0)  # Unknown type logs are not analyzed

    def test_upload_with_u_slash_prefix_strips_prefix_and_succeeds(self):
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'u/reddit_name',
                'log_file': SimpleUploadedFile('a.txt', b'data', content_type='text/plain'),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(UploadedLog.objects.filter(reddit_username='reddit_name').exists())

    def test_upload_with_slash_u_slash_prefix_strips_prefix_and_succeeds(self):
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': '/u/reddit_name',
                'log_file': SimpleUploadedFile('a.txt', b'data', content_type='text/plain'),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(UploadedLog.objects.filter(reddit_username='reddit_name').exists())

    def test_upload_with_hyphenated_username_succeeds(self):
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'Dazzling-Substance57',
                'log_file': SimpleUploadedFile('a.txt', b'data', content_type='text/plain'),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(UploadedLog.objects.filter(reddit_username='Dazzling-Substance57').exists())

    def test_upload_to_helper_url_assigns_recipient_channel(self):
        response = self.client.post(
            reverse('upload_log_for_helper', args=['alice']),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('a.txt', b'data', content_type='text/plain'),
            },
        )

        self.assertEqual(response.status_code, 302)
        uploaded = UploadedLog.objects.get(reddit_username='reddit_name')
        self.assertEqual(uploaded.recipient_user, self.user)

    def test_upload_to_unknown_helper_url_falls_back_to_general_channel(self):
        response = self.client.post(
            reverse('upload_log_for_helper', args=['missing_helper']),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('a.txt', b'data', content_type='text/plain'),
            },
        )

        self.assertEqual(response.status_code, 302)
        uploaded = UploadedLog.objects.get(reddit_username='reddit_name')
        self.assertIsNone(uploaded.recipient_user)

    def test_upload_to_unknown_helper_url_shows_general_fallback_message(self):
        response = self.client.post(
            reverse('upload_log_for_helper', args=['missing_helper']),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('a.txt', b'data', content_type='text/plain'),
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Upload was saved to the general channel')

    def test_upload_with_special_chars_in_username_shows_form_error(self):
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'some user!',
                'log_file': SimpleUploadedFile('a.txt', b'data', content_type='text/plain'),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '3-20 letters, numbers, underscores, or hyphens')
        self.assertEqual(UploadedLog.objects.count(), 0)

    def test_upload_with_too_short_username_shows_form_error(self):
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'ab',
                'log_file': SimpleUploadedFile('a.txt', b'data', content_type='text/plain'),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '3-20 letters, numbers, underscores, or hyphens')
        self.assertEqual(UploadedLog.objects.count(), 0)

    def test_upload_log_view_rejects_unsupported_extension(self):
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('sample.csv', b'line-a', content_type='text/plain'),
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Only .txt or .log files are allowed.')
        self.assertEqual(UploadedLog.objects.count(), 0)

    def test_upload_log_view_allows_log_extension(self):
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('sample.log', b'line-a\nline-b', content_type='text/plain'),
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('upload_log'))
        uploaded = UploadedLog.objects.get(reddit_username='reddit_name')
        self.assertEqual(uploaded.original_filename, 'sample.log')

    def test_upload_log_view_allows_utf16le_without_bom(self):
        utf16le_content = 'Addition sample line\nNext line'.encode('utf-16-le')
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('Addition.txt', utf16le_content, content_type='text/plain'),
            },
        )

        self.assertEqual(response.status_code, 302)
        uploaded = UploadedLog.objects.get(reddit_username='reddit_name')
        self.assertNotIn('\x00', uploaded.content)

    def test_uploaded_log_form_rejects_pasted_invalid_control_characters(self):
        form = UploadedLogForm(
            data={
                'reddit_username': 'reddit_name',
                'log_text': 'line1\x01line2',
            }
        )

        self.assertFalse(form.is_valid())
        self.assertIn(
            'Pasted log contains invalid control characters. Please remove binary/non-text characters and try again.',
            form.errors.get('log_text', []),
        )

    @override_settings(ANON_UPLOAD_RATE_LIMIT_COUNT=1, ANON_UPLOAD_RATE_LIMIT_WINDOW_SECONDS=3600)

    @override_settings(ANON_UPLOAD_RATE_LIMIT_COUNT=1, ANON_UPLOAD_RATE_LIMIT_WINDOW_SECONDS=3600)
    def test_anonymous_upload_rate_limit_blocks_second_attempt(self):
        first = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('first.txt', b'line-a', content_type='text/plain'),
            },
            REMOTE_ADDR='203.0.113.10',
        )
        second = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('second.txt', b'line-b', content_type='text/plain'),
            },
            REMOTE_ADDR='203.0.113.10',
        )

        self.assertEqual(first.status_code, 302)
        self.assertEqual(second.status_code, 200)
        self.assertContains(second, 'Anonymous upload rate limit reached')
        self.assertEqual(UploadedLog.objects.count(), 1)

    @override_settings(ANON_UPLOAD_RATE_LIMIT_COUNT=1, ANON_UPLOAD_RATE_LIMIT_WINDOW_SECONDS=3600)

    @override_settings(ANON_UPLOAD_RATE_LIMIT_COUNT=1, ANON_UPLOAD_RATE_LIMIT_WINDOW_SECONDS=3600)
    def test_authenticated_upload_not_rate_limited(self):
        self.client.login(username='alice', password='password123')

        first = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('first.txt', b'line-a', content_type='text/plain'),
            },
            REMOTE_ADDR='203.0.113.10',
        )
        second = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('second.txt', b'line-b', content_type='text/plain'),
            },
            REMOTE_ADDR='203.0.113.10',
        )

        self.assertEqual(first.status_code, 302)
        self.assertEqual(second.status_code, 302)
        self.assertEqual(UploadedLog.objects.count(), 2)

    def test_upload_detail_shows_content_hash(self):
        uploaded = UploadedLog.objects.create(
            upload_id='hash-detail',
            reddit_username='test_user',
            original_filename='x.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[uploaded.upload_id]))

        self.assertContains(response, uploaded.content_hash)

    def test_upload_id_link_has_log_type_class(self):
        UploadedLog.objects.create(
            upload_id='bright-fox',
            reddit_username='test_user',
            original_filename='frst.txt',
            log_type='FRST',
            content='Scan result of Farbar Recovery Scan Tool\nline',
            recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertContains(response, 'log-type-frst')

    def test_upload_id_link_class_for_each_log_type(self):
        types_and_classes = [
            ('FRST', 'log-type-frst'),
            ('Addition', 'log-type-addition'),
            ('FRST&Addition', 'log-type-frstaddition'),
            ('Fixlog', 'log-type-fixlog'),
            ('Unknown', 'log-type-unknown'),
        ]
        self.client.login(username='alice', password='password123')
        for i, (log_type, expected_class) in enumerate(types_and_classes):
            with self.subTest(log_type=log_type):
                UploadedLog.objects.create(
                    upload_id=f'test-log-{i}',
                    reddit_username='test_user',
                    original_filename='log.txt',
                    log_type=log_type,
                    content='content',
                    recipient_user=self.user,
                )
                response = self.client.get(reverse('uploaded_logs'))
                self.assertContains(response, expected_class)

