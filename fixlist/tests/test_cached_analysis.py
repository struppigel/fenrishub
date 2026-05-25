import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import UploadedLog, UploadedLogAnalysis


FRST_LOG_CONTENT = 'Scan result of Farbar Recovery Scan Tool\nrandom-line\nanother-line'


class RecalculateAnalysisStatsCacheTests(TestCase):
    def test_creates_cache_row_for_analyzable_log(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content=FRST_LOG_CONTENT,
            log_type='FRST',
        )
        log.recalculate_analysis_stats()

        cached = UploadedLogAnalysis.objects.get(upload=log)
        self.assertEqual(cached.source_content_hash, log.content_hash)
        self.assertIn('lines', cached.payload)
        self.assertIn('summary', cached.payload)
        self.assertIn('warnings', cached.payload)
        self.assertGreater(len(cached.payload['lines']), 0)

    def test_overwrites_existing_cache_row(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content=FRST_LOG_CONTENT,
            log_type='FRST',
        )
        log.recalculate_analysis_stats()
        first_updated_at = UploadedLogAnalysis.objects.get(upload=log).updated_at

        log.recalculate_analysis_stats()
        cached = UploadedLogAnalysis.objects.get(upload=log)
        self.assertGreaterEqual(cached.updated_at, first_updated_at)
        self.assertEqual(UploadedLogAnalysis.objects.filter(upload=log).count(), 1)

    def test_skips_cache_for_non_analyzable_log(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='unknown.txt',
            content='not an FRST log',
            log_type='Unknown',
        )
        log.recalculate_analysis_stats()

        self.assertFalse(UploadedLogAnalysis.objects.filter(upload=log).exists())

    def test_removes_stale_cache_when_type_becomes_non_analyzable(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content=FRST_LOG_CONTENT,
            log_type='FRST',
        )
        log.recalculate_analysis_stats()
        self.assertTrue(UploadedLogAnalysis.objects.filter(upload=log).exists())

        log.log_type = 'Unknown'
        log.save(update_fields=['log_type'])
        log.recalculate_analysis_stats()

        self.assertFalse(UploadedLogAnalysis.objects.filter(upload=log).exists())

    def test_cascade_delete_with_uploaded_log(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content=FRST_LOG_CONTENT,
            log_type='FRST',
        )
        log.recalculate_analysis_stats()
        log_pk = log.pk

        log.delete()
        self.assertFalse(UploadedLogAnalysis.objects.filter(upload_id=log_pk).exists())


class UploadedLogCachedAnalysisApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='analyzer', password='pw')

    def _make_cached_log(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content=FRST_LOG_CONTENT,
            log_type='FRST',
        )
        log.recalculate_analysis_stats()
        return log

    def test_requires_login(self):
        log = self._make_cached_log()
        response = self.client.get(
            reverse('uploaded_log_cached_analysis_api', args=[log.upload_id]),
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_returns_payload_when_cache_exists(self):
        log = self._make_cached_log()
        self.client.login(username='analyzer', password='pw')

        response = self.client.get(
            reverse('uploaded_log_cached_analysis_api', args=[log.upload_id]),
        )
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(payload['has_cache'])
        self.assertEqual(payload['source_content_hash'], log.content_hash)
        self.assertIn('lines', payload['payload'])

    def test_reports_no_cache_when_row_missing(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='unknown.txt',
            content='just text',
        )
        self.client.login(username='analyzer', password='pw')

        response = self.client.get(
            reverse('uploaded_log_cached_analysis_api', args=[log.upload_id]),
        )
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertFalse(payload['has_cache'])
        self.assertIsNone(payload['payload'])

    def test_reports_no_cache_when_content_hash_drifted(self):
        log = self._make_cached_log()
        # Simulate content edit after the cache was written.
        log.content = log.content + '\nadded line after cache'
        log.save()  # triggers content_hash recompute via UploadedLog.save
        self.client.login(username='analyzer', password='pw')

        response = self.client.get(
            reverse('uploaded_log_cached_analysis_api', args=[log.upload_id]),
        )
        payload = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertFalse(payload['has_cache'])

    def test_returns_404_for_unknown_upload(self):
        self.client.login(username='analyzer', password='pw')
        response = self.client.get(
            reverse('uploaded_log_cached_analysis_api', args=['no-such-upload']),
        )
        self.assertEqual(response.status_code, 404)


class AnalyzeLogApiCacheWriteTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='analyzer', password='pw')

    def test_analyze_api_upserts_cache_for_known_upload(self):
        log = UploadedLog.objects.create(
            reddit_username='reddit_name',
            original_filename='frst.txt',
            content=FRST_LOG_CONTENT,
            log_type='FRST',
        )
        self.assertFalse(UploadedLogAnalysis.objects.filter(upload=log).exists())

        self.client.login(username='analyzer', password='pw')
        response = self.client.post(
            reverse('analyze_log_api'),
            data=json.dumps({'log': FRST_LOG_CONTENT, 'upload_id': log.upload_id}),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 200)
        cached = UploadedLogAnalysis.objects.get(upload=log)
        self.assertEqual(cached.source_content_hash, log.content_hash)
        self.assertIn('lines', cached.payload)
