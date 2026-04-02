from django.contrib.auth.models import User
from django.db import IntegrityError
from django.test import TestCase
from unittest.mock import patch

from ..analyzer import FRST_END_OF_ADDITION, FRST_END_OF_LOG
from ..models import Fixlist, UploadedLog, detect_log_type


class FixlistModelTests(TestCase):
    def test_share_token_generated_on_create(self):
        user = User.objects.create_user(username="alice", password="password123")

        fixlist = Fixlist.objects.create(
            owner=user,
            title="Initial",
            content="line1",
        )

        self.assertEqual(len(fixlist.share_token), 32)
        self.assertTrue(fixlist.share_token.isalnum())


class UploadedLogModelTests(TestCase):
    def test_upload_id_defaults_to_two_words(self):
        uploaded = UploadedLog.objects.create(
            reddit_username='test_user',
            original_filename='log.txt',
            content='line-1',
        )

        parts = uploaded.upload_id.split('-')
        self.assertEqual(len(parts), 2)
        self.assertTrue(all(parts))

    def test_upload_id_adds_suffix_on_collision(self):
        UploadedLog.objects.create(
            upload_id='amber-otter',
            reddit_username='first_user',
            original_filename='a.txt',
            content='aaa',
        )

        with patch('fixlist.models.generate_memorable_upload_id', return_value='amber-otter'):
            uploaded = UploadedLog.objects.create(
                reddit_username='second_user',
                original_filename='b.txt',
                content='bbb',
            )

        self.assertRegex(uploaded.upload_id, r'^amber-otter-[a-z0-9]{2}$')

    def test_save_retries_when_generated_upload_id_hits_unique_race(self):
        UploadedLog.objects.create(
            upload_id='amber-otter',
            reddit_username='first_user',
            original_filename='a.txt',
            content='aaa',
        )

        from django.db.models.base import Model
        original_model_save = Model.save

        def first_insert_collides_then_retry(self, *args, **kwargs):
            if self._state.adding and self.upload_id == 'amber-otter':
                raise IntegrityError('UNIQUE constraint failed: fixlist_uploadedlog.upload_id')
            return original_model_save(self, *args, **kwargs)

        with (
            patch.object(UploadedLog, '_generate_unique_upload_id', side_effect=['amber-otter', 'quiet-valley']),
            patch('django.db.models.base.Model.save', autospec=True, side_effect=first_insert_collides_then_retry),
        ):
            uploaded = UploadedLog.objects.create(
                reddit_username='second_user',
                original_filename='b.txt',
                content='bbb',
            )

        self.assertEqual(uploaded.upload_id, 'quiet-valley')

    def test_log_type_defaults_to_unknown(self):
        uploaded = UploadedLog.objects.create(
            upload_id='quiet-plain',
            reddit_username='test_user',
            original_filename='log.txt',
            content='some random content',
        )
        self.assertEqual(uploaded.log_type, 'Unknown')

    def test_recalculate_log_type_persists_detected_type(self):
        uploaded = UploadedLog.objects.create(
            upload_id='bright-hill',
            reddit_username='test_user',
            original_filename='frst.txt',
            content='Scan result of Farbar Recovery Scan Tool\nsome content',
        )
        uploaded.recalculate_log_type()
        uploaded.refresh_from_db()
        self.assertEqual(uploaded.log_type, 'FRST')

    def test_apply_analysis_summary_sets_all_stat_fields(self):
        uploaded = UploadedLog.objects.create(
            upload_id='mellow-valley',
            reddit_username='stats_user',
            original_filename='stats.txt',
            content='placeholder',
        )

        uploaded.apply_analysis_summary(
            {
                'total_lines': 6,
                'status_counts': {
                    'B': 1,
                    'P': 2,
                    'C': 0,
                    '!': 1,
                    'G': 0,
                    'S': 0,
                    'I': 1,
                    'J': 0,
                    '?': 1,
                },
            }
        )
        uploaded.save(update_fields=UploadedLog.analysis_stat_update_fields())
        uploaded.refresh_from_db()

        self.assertEqual(uploaded.total_line_count, 6)
        self.assertEqual(uploaded.count_malware, 1)
        self.assertEqual(uploaded.count_pup, 2)
        self.assertEqual(uploaded.count_clean, 0)
        self.assertEqual(uploaded.count_warning, 1)
        self.assertEqual(uploaded.count_grayware, 0)
        self.assertEqual(uploaded.count_security, 0)
        self.assertEqual(uploaded.count_info, 1)
        self.assertEqual(uploaded.count_junk, 0)
        self.assertEqual(uploaded.count_unknown, 1)


_FRST_CONTENT = 'Scan result of Farbar Recovery Scan Tool\ncontent'
_FRST_COMPLETE = (
    f'Scan result of Farbar Recovery Scan Tool\ncontent\n{FRST_END_OF_LOG}\n'
    f'Additional scan result of Farbar Recovery Scan Tool\ncontent\n{FRST_END_OF_ADDITION}'
)
_ADDITION_CONTENT = 'Additional scan result of Farbar Recovery Scan Tool\ncontent'


class ContentHashTests(TestCase):
    def test_content_hash_populated_on_create(self):
        uploaded = UploadedLog.objects.create(
            reddit_username='test_user',
            original_filename='log.txt',
            content='hello world',
        )
        self.assertTrue(uploaded.content_hash)
        self.assertEqual(len(uploaded.content_hash), 32)

    def test_content_hash_is_deterministic(self):
        a = UploadedLog.objects.create(
            upload_id='hash-a',
            reddit_username='test_user',
            original_filename='a.txt',
            content='same content',
        )
        b = UploadedLog.objects.create(
            upload_id='hash-b',
            reddit_username='test_user',
            original_filename='b.txt',
            content='same content',
        )
        self.assertEqual(a.content_hash, b.content_hash)

    def test_content_hash_differs_for_different_content(self):
        a = UploadedLog.objects.create(
            upload_id='diff-a',
            reddit_username='test_user',
            original_filename='a.txt',
            content='content A',
        )
        b = UploadedLog.objects.create(
            upload_id='diff-b',
            reddit_username='test_user',
            original_filename='b.txt',
            content='content B',
        )
        self.assertNotEqual(a.content_hash, b.content_hash)

    def test_content_hash_updates_on_content_change(self):
        uploaded = UploadedLog.objects.create(
            upload_id='hash-update',
            reddit_username='test_user',
            original_filename='log.txt',
            content='original',
        )
        original_hash = uploaded.content_hash
        uploaded.content = 'modified'
        uploaded.save()
        uploaded.refresh_from_db()
        self.assertNotEqual(uploaded.content_hash, original_hash)

    def test_compute_content_hash_matches_mmh3(self):
        import mmh3
        content = 'test string'
        expected = format(mmh3.hash128(content.encode('utf-8'), signed=False), '032x')
        self.assertEqual(UploadedLog.compute_content_hash(content), expected)


class IncompleteLogFlagTests(TestCase):
    def _make_log(self, log_type, content):
        return UploadedLog.objects.create(
            upload_id=f'test-{log_type.lower().replace("&", "")}',
            reddit_username='test_user',
            original_filename='log.txt',
            log_type=log_type,
            content=content,
        )

    def test_frst_without_end_markers_is_incomplete(self):
        log = self._make_log('FRST', _FRST_CONTENT)
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertTrue(log.is_incomplete)

    def test_frst_with_end_markers_is_not_incomplete(self):
        log = self._make_log('FRST', _FRST_COMPLETE)
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertFalse(log.is_incomplete)

    def test_unknown_type_is_never_incomplete(self):
        log = self._make_log('Unknown', _FRST_CONTENT)
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertFalse(log.is_incomplete)

    def test_addition_without_end_markers_is_incomplete(self):
        log = self._make_log('Addition', _ADDITION_CONTENT)
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertTrue(log.is_incomplete)

    def test_frst_with_only_frst_ending_is_not_incomplete(self):
        log = self._make_log('FRST', f'{_FRST_CONTENT}\n{FRST_END_OF_LOG}')
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertFalse(log.is_incomplete)

    def test_addition_with_only_addition_ending_is_not_incomplete(self):
        log = self._make_log('Addition', f'{_ADDITION_CONTENT}\n{FRST_END_OF_ADDITION}')
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertFalse(log.is_incomplete)

    def test_frst_and_addition_without_end_markers_is_incomplete(self):
        log = self._make_log('FRST&Addition', _FRST_CONTENT)
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertTrue(log.is_incomplete)

    def test_frst_and_addition_with_end_markers_is_not_incomplete(self):
        log = self._make_log('FRST&Addition', _FRST_COMPLETE)
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertFalse(log.is_incomplete)

    def test_frst_and_addition_with_only_one_ending_is_incomplete(self):
        content = (
            'Scan result of Farbar Recovery Scan Tool\nfrst content\n'
            'Additional scan result of Farbar Recovery Scan Tool\naddition content\n'
            f'{FRST_END_OF_LOG}'
        )
        log = self._make_log('FRST&Addition', content)
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertTrue(log.is_incomplete)

    def test_fixlog_type_is_never_incomplete(self):
        log = self._make_log('Fixlog', 'Fix result of Farbar Recovery Scan Tool\nsome fix')
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        self.assertFalse(log.is_incomplete)


class FixlogStatsTests(TestCase):
    def _make_fixlog(self, content):
        log = UploadedLog.objects.create(
            upload_id='test-fixlog-stats',
            reddit_username='test_user',
            original_filename='fixlog.txt',
            log_type='Fixlog',
            content=content,
        )
        log.recalculate_analysis_stats()
        log.refresh_from_db()
        return log

    def test_counts_all_status_messages(self):
        content = (
            'Fix result of Farbar Recovery Scan Tool\n'
            'HKLM\\Something => removed successfully\n'
            'HKLM\\Other => Error setting value.\n'
            '"HKU\\Run\\App" => not found\n'
            'D:\\Games\\Foo => moved successfully\n'
            'some line without arrow\n'
        )
        log = self._make_fixlog(content)
        self.assertEqual(log.fixlog_total, 4)
        self.assertEqual(log.fixlog_success, 2)
        self.assertEqual(log.fixlog_not_found, 1)
        self.assertEqual(log.fixlog_error, 1)

    def test_no_status_lines(self):
        log = self._make_fixlog('Fix result of Farbar Recovery Scan Tool\njust text\n')
        self.assertEqual(log.fixlog_total, 0)
        self.assertEqual(log.fixlog_success, 0)
        self.assertEqual(log.fixlog_not_found, 0)
        self.assertEqual(log.fixlog_error, 0)


class DetectLogTypeTests(TestCase):
    def test_frst(self):
        self.assertEqual(
            detect_log_type('Scan result of Farbar Recovery Scan Tool\nline2'),
            'FRST',
        )

    def test_addition(self):
        self.assertEqual(
            detect_log_type('Additional scan result of Farbar Recovery Scan Tool\nline2'),
            'Addition',
        )

    def test_fixlog(self):
        self.assertEqual(
            detect_log_type('Fix result of Farbar Recovery Scan Tool\nline2'),
            'Fixlog',
        )

    def test_frst_and_addition_when_both_present(self):
        content = (
            'Scan result of Farbar Recovery Scan Tool\nfrst content\n'
            'Additional scan result of Farbar Recovery Scan Tool\naddition content'
        )
        self.assertEqual(detect_log_type(content), 'FRST&Addition')

    def test_unknown(self):
        self.assertEqual(detect_log_type('some random log content'), 'Unknown')

    def test_empty(self):
        self.assertEqual(detect_log_type(''), 'Unknown')

    def test_addition_does_not_match_frst_marker(self):
        # "Additional scan result" must not trigger FRST detection
        content = 'Additional scan result of Farbar Recovery Scan Tool\nline2'
        self.assertEqual(detect_log_type(content), 'Addition')

    def test_leading_whitespace_ignored_for_fixlog(self):
        self.assertEqual(
            detect_log_type('\n\nFix result of Farbar Recovery Scan Tool\nline2'),
            'Fixlog',
        )
