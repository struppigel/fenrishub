import json
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


class FixlistCrudViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.client.login(username="alice", password="password123")

    def test_create_fixlist_creates_record_and_redirects(self):
        response = self.client.post(
            reverse("create_fixlist"),
            {
                "title": "Created Via Test",
                "content": "ioc-1\nioc-2",
                "internal_note": "internal context",
            },
        )

        created = Fixlist.objects.get(title="Created Via Test")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[created.pk]))
        self.assertEqual(created.owner, self.user)
        self.assertEqual(created.internal_note, "internal context")

    def test_create_fixlist_ignores_rule_persistence_payload(self):
        pending_changes = [
            {
                "id": "1",
                "line": "MALICIOUS-LINE",
                "original_status": "?",
                "new_status": ClassificationRule.STATUS_MALWARE,
                "order": 1,
            }
        ]

        response = self.client.post(
            reverse("create_fixlist"),
            {
                "title": "Fixlist Ignores Rule Persist Payload",
                "content": "line-a",
                "internal_note": "",
                "persist_rules": "1",
                "pending_rule_changes_json": json.dumps(pending_changes),
                "selected_rule_change_ids_json": json.dumps(["1"]),
            },
        )

        created = Fixlist.objects.get(title="Fixlist Ignores Rule Persist Payload")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[created.pk]))
        self.assertEqual(ClassificationRule.objects.count(), 0)

    def test_update_fixlist_changes_content(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            title="Before",
            content="old-content",
            internal_note="old-note",
        )

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {
                "action": "update",
                "title": "After",
                "content": "new-content",
                "internal_note": "new-note",
            },
        )

        fixlist.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("view_fixlist", args=[fixlist.pk]))
        self.assertEqual(fixlist.title, "After")
        self.assertEqual(fixlist.content, "new-content")
        self.assertEqual(fixlist.internal_note, "new-note")

    def test_delete_fixlist_removes_record(self):
        fixlist = Fixlist.objects.create(owner=self.user, title="Delete Me", content="x")

        response = self.client.post(
            reverse("view_fixlist", args=[fixlist.pk]),
            {"action": "delete"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("dashboard"))
        self.assertFalse(Fixlist.objects.filter(pk=fixlist.pk).exists())

    def test_view_fixlist_context_includes_guest_preview_url(self):
        fixlist = Fixlist.objects.create(
            owner=self.user,
            title="Previewable",
            content="payload",
        )
        request = RequestFactory().get(reverse("view_fixlist", args=[fixlist.pk]))
        request.user = self.user

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
            response = view_fixlist(request, pk=fixlist.pk)

        rendered_context = mock_render.call_args.args[2]
        share_url = rendered_context["share_url"]

        self.assertEqual(response.status_code, 200)
        self.assertIn(f"/share/{fixlist.share_token}/", share_url)
        self.assertEqual(
            rendered_context["guest_preview_url"],
            f"{share_url}?preview=guest",
        )


class SharingAndDownloadTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password123")
        self.factory = RequestFactory()
        self.fixlist = Fixlist.objects.create(
            owner=self.user,
            title="Shareable",
            content="ioc-a\nioc-b",
            internal_note="Internal only",
        )

    def test_shared_view_creates_access_log_for_anonymous_access(self):
        request = self.factory.get(reverse("shared_fixlist", args=[self.fixlist.share_token]))
        request.user = AnonymousUser()

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
            response = shared_fixlist_view(request, token=self.fixlist.share_token)

        rendered_context = mock_render.call_args.args[2]

        self.assertEqual(response.status_code, 200)
        self.assertEqual(rendered_context["fixlist"].pk, self.fixlist.pk)
        self.assertFalse(rendered_context["is_owner"])
        self.assertEqual(AccessLog.objects.filter(fixlist=self.fixlist).count(), 1)

    def test_download_increments_counter_and_returns_attachment(self):
        response = self.client.get(reverse("download_fixlist", args=[self.fixlist.share_token]))

        self.fixlist.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain")
        self.assertIn('attachment; filename="Fixlist.txt"', response["Content-Disposition"])
        self.assertEqual(response.content.decode("utf-8"), self.fixlist.content)
        self.assertEqual(self.fixlist.download_count, 1)
        self.assertEqual(AccessLog.objects.filter(fixlist=self.fixlist).count(), 1)

    def test_copy_api_returns_content_and_logs_access(self):
        response = self.client.post(reverse("copy_api", args=[self.fixlist.share_token]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"content": self.fixlist.content})
        self.assertEqual(AccessLog.objects.filter(fixlist=self.fixlist).count(), 1)

    def test_shared_view_marks_owner_in_context_when_logged_in(self):
        request = self.factory.get(reverse("shared_fixlist", args=[self.fixlist.share_token]))
        request.user = self.user

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
            response = shared_fixlist_view(request, token=self.fixlist.share_token)

        rendered_context = mock_render.call_args.args[2]

        self.assertEqual(response.status_code, 200)
        self.assertTrue(rendered_context["is_owner"])
        self.assertFalse(rendered_context["preview_as_guest"])

    def test_shared_view_owner_guest_preview_sets_non_owner_context(self):
        request = self.factory.get(
            reverse("shared_fixlist", args=[self.fixlist.share_token]),
            {"preview": "guest"},
        )
        request.user = self.user

        with patch("fixlist.views.render", return_value=HttpResponse("ok")) as mock_render:
            response = shared_fixlist_view(request, token=self.fixlist.share_token)

        rendered_context = mock_render.call_args.args[2]

        self.assertEqual(response.status_code, 200)
        self.assertTrue(rendered_context["preview_as_guest"])
        self.assertFalse(rendered_context["is_owner"])


class UploadedLogViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        cache.clear()

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

    def test_upload_log_view_rejects_non_txt_extension(self):
        response = self.client.post(
            reverse('upload_log'),
            {
                'reddit_username': 'reddit_name',
                'log_file': SimpleUploadedFile('sample.log', b'line-a', content_type='text/plain'),
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Only .txt files are allowed.')
        self.assertEqual(UploadedLog.objects.count(), 0)

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

    def test_uploaded_logs_page_requires_login(self):
        response = self.client.get(reverse('uploaded_logs'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_authenticated_user_can_view_upload_by_id(self):
        uploaded = UploadedLog.objects.create(
            upload_id='bright-river',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[uploaded.upload_id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'payload')

    def test_authenticated_user_can_delete_upload(self):
        uploaded = UploadedLog.objects.create(
            upload_id='quiet-forest',
            reddit_username='reddit_name',
            original_filename='x.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'delete', 'upload_id': uploaded.upload_id},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('uploaded_logs'))
        uploaded.refresh_from_db()
        self.assertIsNotNone(uploaded.deleted_at)

    def test_merge_selected_uploads_creates_new_record(self):
        first = UploadedLog.objects.create(
            upload_id='amber-meadow',
            reddit_username='reddit_name',
            original_filename='first.txt',
            content='aaa',
        )
        second = UploadedLog.objects.create(
            upload_id='azure-harbor',
            reddit_username='reddit_name',
            original_filename='second.txt',
            content='bbb',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {
                'action': 'merge',
                'selected_upload_ids': [first.upload_id, second.upload_id],
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(UploadedLog.objects.filter(deleted_at__isnull=True).count(), 1)
        merged = UploadedLog.objects.filter(deleted_at__isnull=True).first()
        self.assertIsNotNone(merged)
        self.assertEqual(merged.content, 'aaa\nbbb')
        self.assertEqual(merged.total_line_count, 2)
        self.assertEqual(merged.count_unknown, 0)  # Unknown type logs are not analyzed

    def test_merge_retains_first_upload_id_and_deletes_originals(self):
        first = UploadedLog.objects.create(
            upload_id='amber-meadow',
            reddit_username='reddit_name',
            original_filename='first.txt',
            content='aaa',
        )
        second = UploadedLog.objects.create(
            upload_id='azure-harbor',
            reddit_username='reddit_name',
            original_filename='second.txt',
            content='bbb',
        )
        self.client.login(username='alice', password='password123')

        self.client.post(
            reverse('uploaded_logs'),
            {
                'action': 'merge',
                'selected_upload_ids': [first.upload_id, second.upload_id],
            },
        )

        self.assertFalse(UploadedLog.objects.filter(upload_id='azure-harbor').exists())
        self.assertTrue(UploadedLog.objects.filter(upload_id='azure-harbor-trsh').exists())
        merged = UploadedLog.objects.get(upload_id='amber-meadow')
        self.assertEqual(merged.content, 'aaa\nbbb')

    def test_merge_requires_at_least_two_uploads(self):
        only = UploadedLog.objects.create(
            upload_id='mellow-garden',
            reddit_username='reddit_name',
            original_filename='single.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {
                'action': 'merge',
                'selected_upload_ids': [only.upload_id],
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('uploaded_logs'))
        self.assertEqual(UploadedLog.objects.count(), 1)

    def test_bulk_rescan_recalculates_stats_for_all_uploads(self):
        first = UploadedLog.objects.create(
            upload_id='silent-river',
            reddit_username='reddit_name',
            original_filename='first.txt',
            log_type='FRST',
            content='Scan result of Farbar Recovery Scan Tool\nMAL-LINE\nOTHER-LINE',
        )
        second = UploadedLog.objects.create(
            upload_id='rapid-harbor',
            reddit_username='reddit_name',
            original_filename='second.txt',
            log_type='FRST',
            content='Scan result of Farbar Recovery Scan Tool\nMAL-LINE',
        )
        ClassificationRule.objects.create(
            owner=self.user,
            status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_EXACT,
            source_text='MAL-LINE',
        )

        self.client.login(username='alice', password='password123')
        response = self.client.post(
            reverse('uploaded_logs'),
            {'action': 'rescan_stats_all'},
        )

        first.refresh_from_db()
        second.refresh_from_db()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('uploaded_logs'))
        self.assertEqual(first.total_line_count, 2)
        self.assertEqual(first.count_malware, 1)
        self.assertEqual(first.count_unknown, 1)
        self.assertEqual(second.total_line_count, 1)
        self.assertEqual(second.count_malware, 1)
        self.assertEqual(second.count_unknown, 0)

    def test_username_filter_shows_only_matching_uploads(self):
        UploadedLog.objects.create(
            upload_id='amber-wolf',
            reddit_username='alice_user',
            original_filename='a.txt',
            content='aaa',
        )
        UploadedLog.objects.create(
            upload_id='azure-bear',
            reddit_username='bob_user',
            original_filename='b.txt',
            content='bbb',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'), {'u': 'alice_user'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'amber-wolf')
        self.assertNotContains(response, 'azure-bear')

    def test_username_filter_empty_shows_all_uploads(self):
        UploadedLog.objects.create(
            upload_id='amber-wolf',
            reddit_username='alice_user',
            original_filename='a.txt',
            content='aaa',
        )
        UploadedLog.objects.create(
            upload_id='azure-bear',
            reddit_username='bob_user',
            original_filename='b.txt',
            content='bbb',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'amber-wolf')
        self.assertContains(response, 'azure-bear')

    def test_all_usernames_passed_to_context(self):
        UploadedLog.objects.create(
            upload_id='amber-wolf',
            reddit_username='alice_user',
            original_filename='a.txt',
            content='aaa',
        )
        UploadedLog.objects.create(
            upload_id='azure-bear',
            reddit_username='bob_user',
            original_filename='b.txt',
            content='bbb',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertIn('alice_user', list(response.context['all_usernames']))
        self.assertIn('bob_user', list(response.context['all_usernames']))

    def test_upload_id_link_has_log_type_class(self):
        UploadedLog.objects.create(
            upload_id='bright-fox',
            reddit_username='test_user',
            original_filename='frst.txt',
            log_type='FRST',
            content='Scan result of Farbar Recovery Scan Tool\nline',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertContains(response, 'log-type-frst')

    def test_upload_id_link_class_for_each_log_type(self):
        types_and_classes = [
            ('FRST', 'log-type-frst'),
            ('Addition', 'log-type-addition'),
            ('FRST&Addition', 'log-type-frstaddition'),
            ('Fixlist', 'log-type-fixlist'),
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
                )
                response = self.client.get(reverse('uploaded_logs'))
                self.assertContains(response, expected_class)

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

        with patch('fixlist.views.render', return_value=HttpResponse('ok')) as mock_render:
            response = log_analyzer_view(request)

        rendered_context = mock_render.call_args.args[2]
        self.assertEqual(response.status_code, 200)
        self.assertEqual(rendered_context.get('initial_upload_id'), uploaded.upload_id)


class TrashViewTests(TestCase):
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

    def test_soft_deleted_log_returns_404_on_detail_view(self):
        from django.utils import timezone as tz
        log = self._make_log('gone-log', deleted_at=tz.now())

        response = self.client.get(reverse('view_uploaded_log', args=[log.upload_id]))

        self.assertEqual(response.status_code, 404)

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

    def test_uploads_list_shows_trash_count(self):
        from django.utils import timezone as tz
        self._make_log('active-log')
        self._make_log('trashed-one', deleted_at=tz.now())
        self._make_log('trashed-two', deleted_at=tz.now())

        response = self.client.get(reverse('uploaded_logs'))

        self.assertContains(response, 'trash (2)')

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

        self.client.post(reverse('uploaded_logs'), {'action': 'rescan_stats_all'})

        active.refresh_from_db()
        trashed.refresh_from_db()
        self.assertEqual(active.count_malware, 1)
        self.assertEqual(trashed.count_malware, 0)

