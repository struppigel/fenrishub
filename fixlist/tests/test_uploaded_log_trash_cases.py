import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser, User
from django.core.cache import cache
from django.http import HttpResponse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase
from django.test import override_settings
from django.urls import reverse

from ..models import AccessLog, ClassificationRule, Fixlist, UploadedLog
from ..views import log_analyzer_view, shared_fixlist_view, view_fixlist


class TrashViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.client.login(username='alice', password='password123')

    def _make_log(self, upload_id, **kwargs):
        if 'recipient_user' not in kwargs:
            kwargs['recipient_user'] = self.user
        return UploadedLog.objects.create(
            upload_id=upload_id,
            reddit_username='test_user',
            original_filename='x.txt',
            content='payload',
            **kwargs,
        )

    # --- soft delete ---

    def test_delete_from_list_sets_deleted_at_not_hard_deletes(self):
        log = self._make_log('quiet-forest')

        self.client.post(reverse('uploaded_logs'), {'action': 'delete', 'upload_id': log.upload_id})

        log.refresh_from_db()
        self.assertIsNotNone(log.deleted_at)

    def test_delete_from_detail_sets_deleted_at(self):
        log = self._make_log('bright-river')

        self.client.post(
            reverse('view_uploaded_log', args=[log.upload_id]),
            {'action': 'delete'},
        )

        log.refresh_from_db()
        self.assertIsNotNone(log.deleted_at)

    def test_soft_deleted_log_excluded_from_uploads_list(self):
        active = self._make_log('active-log')
        self._make_log('trashed-log', deleted_at='2024-01-01T00:00:00+00:00')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertContains(response, 'active-log')
        self.assertNotContains(response, 'trashed-log')

    def test_soft_deleted_log_is_viewable_on_detail_view(self):
        from django.utils import timezone as tz
        log = self._make_log('gone-log', deleted_at=tz.now())

        response = self.client.get(reverse('view_uploaded_log', args=[log.upload_id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, log.upload_id)

    def test_soft_deleted_log_returns_404_on_content_api(self):
        from django.utils import timezone as tz
        log = self._make_log('gone-api', deleted_at=tz.now())

        response = self.client.get(
            reverse('uploaded_log_content_api', args=[log.upload_id])
        )

        self.assertEqual(response.status_code, 404)

    # --- trash list ---

    def test_trash_view_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse('uploads_trash'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_trash_view_shows_deleted_logs(self):
        from django.utils import timezone as tz
        self._make_log('active-log')
        self._make_log('trashed-log', deleted_at=tz.now())

        response = self.client.get(reverse('uploads_trash'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'trashed-log')
        self.assertNotContains(response, 'active-log')

    def test_trash_view_is_paginated(self):
        from django.utils import timezone as tz

        for index in range(9):
            self._make_log(
                f'trashed-page-{index}',
                deleted_at=tz.now() + timedelta(seconds=index),
            )

        first_page = self.client.get(reverse('uploads_trash'))
        second_page = self.client.get(reverse('uploads_trash'), {'page': '2'})

        self.assertEqual(first_page.status_code, 200)
        self.assertEqual(first_page.context['page_obj'].paginator.num_pages, 2)
        self.assertEqual(len(first_page.context['page_obj'].object_list), 8)
        self.assertContains(first_page, 'page 1 of 2')
        self.assertContains(first_page, '?page=2')

        self.assertEqual(second_page.status_code, 200)
        self.assertEqual(second_page.context['page_obj'].number, 2)
        self.assertEqual(len(second_page.context['page_obj'].object_list), 1)

    def test_uploads_list_shows_trash_count(self):
        from django.utils import timezone as tz
        self._make_log('active-log')
        self._make_log('trashed-one', deleted_at=tz.now())
        self._make_log('trashed-two', deleted_at=tz.now())

        response = self.client.get(reverse('uploaded_logs'))

        self.assertContains(response, 'trash (2)')

    def test_uploads_list_trash_count_includes_all_users(self):
        from django.utils import timezone as tz
        self._make_log('own-active')
        self._make_log('own-trashed', deleted_at=tz.now())
        self._make_log('other-trashed', deleted_at=tz.now(), recipient_user=User.objects.create_user(username='bob', password='password123'))

        default_response = self.client.get(reverse('uploaded_logs'))
        show_all_response = self.client.get(reverse('uploaded_logs'), {'show_all': '1'})

        self.assertContains(default_response, 'trash (2)')
        self.assertContains(show_all_response, 'trash (2)')

    def test_uploads_list_shows_no_count_when_trash_empty(self):
        self._make_log('active-log')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertNotContains(response, 'trash (')
        self.assertContains(response, '>trash<')

    # --- restore ---

    def test_restore_clears_deleted_at(self):
        from django.utils import timezone as tz
        log = self._make_log('restore-me', deleted_at=tz.now())

        self.client.post(reverse('uploads_trash'), {'action': 'restore', 'upload_id': log.upload_id})

        log.refresh_from_db()
        self.assertIsNone(log.deleted_at)

    def test_restore_log_appears_in_uploads_list(self):
        from django.utils import timezone as tz
        log = self._make_log('restore-me', deleted_at=tz.now())

        self.client.post(reverse('uploads_trash'), {'action': 'restore', 'upload_id': log.upload_id})

        response = self.client.get(reverse('uploaded_logs'))
        self.assertContains(response, 'restore-me')

    def test_restore_redirects_to_trash(self):
        from django.utils import timezone as tz
        log = self._make_log('restore-me', deleted_at=tz.now())

        response = self.client.post(
            reverse('uploads_trash'), {'action': 'restore', 'upload_id': log.upload_id}
        )

        self.assertRedirects(response, reverse('uploads_trash'))

    # --- permanent delete ---

    def test_permanent_delete_removes_record(self):
        from django.utils import timezone as tz
        log = self._make_log('bye-forever', deleted_at=tz.now())

        self.client.post(
            reverse('uploads_trash'), {'action': 'delete_permanent', 'upload_id': log.upload_id}
        )

        self.assertFalse(UploadedLog.objects.filter(upload_id='bye-forever').exists())

    def test_permanent_delete_only_works_on_trashed_logs(self):
        active = self._make_log('still-active')

        response = self.client.post(
            reverse('uploads_trash'), {'action': 'delete_permanent', 'upload_id': active.upload_id}
        )

        self.assertEqual(response.status_code, 404)
        self.assertTrue(UploadedLog.objects.filter(upload_id='still-active').exists())

    # --- empty trash ---

    def test_empty_trash_removes_all_trashed_logs(self):
        from django.utils import timezone as tz
        self._make_log('trashed-one', deleted_at=tz.now())
        self._make_log('trashed-two', deleted_at=tz.now())
        active = self._make_log('still-active')

        self.client.post(reverse('uploads_trash'), {'action': 'empty_trash'})

        self.assertFalse(UploadedLog.objects.filter(deleted_at__isnull=False).exists())
        self.assertTrue(UploadedLog.objects.filter(pk=active.pk).exists())

    def test_empty_trash_redirects_to_trash(self):
        response = self.client.post(reverse('uploads_trash'), {'action': 'empty_trash'})
        self.assertRedirects(response, reverse('uploads_trash'))

    # --- merge soft-delete ---

    def test_merge_soft_deletes_source_logs_with_trsh_suffix(self):
        first = self._make_log('amber-meadow')
        second = self._make_log('azure-harbor')

        self.client.post(
            reverse('uploaded_logs'),
            {'action': 'merge', 'selected_upload_ids': [first.upload_id, second.upload_id]},
        )

        first_trashed = UploadedLog.objects.get(upload_id='amber-meadow-trsh')
        second_trashed = UploadedLog.objects.get(upload_id='azure-harbor-trsh')
        self.assertIsNotNone(first_trashed.deleted_at)
        self.assertIsNotNone(second_trashed.deleted_at)

    def test_merge_source_logs_absent_from_uploads_list(self):
        first = self._make_log('amber-meadow')
        second = self._make_log('azure-harbor')

        self.client.post(
            reverse('uploaded_logs'),
            {'action': 'merge', 'selected_upload_ids': [first.upload_id, second.upload_id]},
        )

        response = self.client.get(reverse('uploaded_logs'))
        self.assertNotContains(response, 'amber-meadow-trsh')
        self.assertNotContains(response, 'azure-harbor-trsh')

    def test_merge_source_logs_appear_in_trash(self):
        first = self._make_log('amber-meadow')
        second = self._make_log('azure-harbor')

        self.client.post(
            reverse('uploaded_logs'),
            {'action': 'merge', 'selected_upload_ids': [first.upload_id, second.upload_id]},
        )

        response = self.client.get(reverse('uploads_trash'))
        self.assertContains(response, 'amber-meadow-trsh')
        self.assertContains(response, 'azure-harbor-trsh')

    def test_merge_appends_counter_when_trash_id_already_exists(self):
        """Regression: merging must not 500 when {id}-trsh already exists in trash."""
        from django.utils import timezone as tz
        # Pre-existing trashed record from a prior merge that retained 'amber-meadow'.
        self._make_log('amber-meadow-trsh', deleted_at=tz.now())

        first = self._make_log('amber-meadow')
        second = self._make_log('azure-harbor')

        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'merge', 'selected_upload_ids': [first.upload_id, second.upload_id]},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        # Pre-existing trash record is untouched.
        self.assertTrue(UploadedLog.objects.filter(upload_id='amber-meadow-trsh').exists())
        # New trash record gets a counter suffix to avoid colliding.
        self.assertTrue(UploadedLog.objects.filter(upload_id='amber-meadow-trsh-2').exists())
        self.assertTrue(UploadedLog.objects.filter(upload_id='azure-harbor-trsh').exists())
        # Merged log keeps the retained id and is active.
        self.assertTrue(
            UploadedLog.objects.filter(
                upload_id='amber-meadow', deleted_at__isnull=True
            ).exists()
        )

    # --- rescan excludes trashed logs ---

    def test_rescan_does_not_process_trashed_logs(self):
        from django.utils import timezone as tz
        active = UploadedLog.objects.create(
            upload_id='active-frst',
            reddit_username='test_user',
            original_filename='a.txt',
            log_type='FRST',
            content='Scan result of Farbar Recovery Scan Tool\nMAL-LINE',
        )
        trashed = UploadedLog.objects.create(
            upload_id='trashed-frst',
            reddit_username='test_user',
            original_filename='b.txt',
            log_type='FRST',
            content='Scan result of Farbar Recovery Scan Tool\nMAL-LINE',
            deleted_at=tz.now(),
        )
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text='MAL-LINE',
        )

        self.client.post(reverse('uploaded_logs'), {
            'action': 'rescan_selected',
            'selected_upload_ids': ['active-frst', 'trashed-frst'],
        })

        active.refresh_from_db()
        trashed.refresh_from_db()
        self.assertEqual(active.count_malware, 1)
        self.assertEqual(trashed.count_malware, 0)


class PurgeOldTrashTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.client.login(username='alice', password='password123')

    def _make_log(self, upload_id, **kwargs):
        return UploadedLog.objects.create(
            upload_id=upload_id,
            reddit_username='test_user',
            original_filename='x.txt',
            content='payload',
            **kwargs,
        )

    def _old_deleted_at(self):
        from django.utils import timezone as tz
        return tz.now() - timedelta(days=31)

    def _recent_deleted_at(self):
        from django.utils import timezone as tz
        return tz.now() - timedelta(days=1)

    def test_delete_from_list_purges_old_trash(self):
        old = self._make_log('old-trash', deleted_at=self._old_deleted_at())
        target = self._make_log('new-victim')

        self.client.post(reverse('uploaded_logs'), {'action': 'delete', 'upload_id': target.upload_id})

        self.assertFalse(UploadedLog.objects.filter(pk=old.pk).exists())

    def test_delete_from_list_keeps_recent_trash(self):
        recent = self._make_log('recent-trash', deleted_at=self._recent_deleted_at())
        target = self._make_log('new-victim')

        self.client.post(reverse('uploaded_logs'), {'action': 'delete', 'upload_id': target.upload_id})

        self.assertTrue(UploadedLog.objects.filter(pk=recent.pk).exists())

    def test_delete_from_detail_purges_old_trash(self):
        old = self._make_log('old-trash', deleted_at=self._old_deleted_at())
        target = self._make_log('new-victim')

        self.client.post(
            reverse('view_uploaded_log', args=[target.upload_id]),
            {'action': 'delete'},
        )

        self.assertFalse(UploadedLog.objects.filter(pk=old.pk).exists())

    def test_merge_purges_old_trash(self):
        old = self._make_log('old-trash', deleted_at=self._old_deleted_at())
        first = self._make_log('merge-a')
        second = self._make_log('merge-b')

        self.client.post(
            reverse('uploaded_logs'),
            {'action': 'merge', 'selected_upload_ids': [first.upload_id, second.upload_id]},
        )

        self.assertFalse(UploadedLog.objects.filter(pk=old.pk).exists())

    def test_purge_does_not_delete_active_logs(self):
        active = self._make_log('active-log')
        target = self._make_log('new-victim')
        # put something old in trash to trigger purge
        self._make_log('old-trash', deleted_at=self._old_deleted_at())

        self.client.post(reverse('uploaded_logs'), {'action': 'delete', 'upload_id': target.upload_id})

        self.assertTrue(UploadedLog.objects.filter(pk=active.pk).exists())

