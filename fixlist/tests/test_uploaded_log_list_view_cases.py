from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule, UploadedLog
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


class UploadedLogListViewTests(UploadedLogSharedSetupMixin, TestCase):

    def test_uploaded_logs_page_requires_login(self):
        response = self.client.get(reverse('uploaded_logs'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_uploaded_logs_list_shows_assign_only_for_unassigned_in_show_all_mode(self):
        UploadedLog.objects.create(
            upload_id='assign-visible-general',
            reddit_username='general_user',
            original_filename='g.txt',
            content='payload',
            recipient_user=None,
        )
        UploadedLog.objects.create(
            upload_id='assign-hidden-owned',
            reddit_username='alice_user',
            original_filename='a.txt',
            content='payload',
            recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'), {'show_all': '1'})

        self.assertContains(response, '>assign</button>', count=1)

    def test_uploaded_logs_list_shows_own_channel_only_by_default(self):
        UploadedLog.objects.create(
            upload_id='general-log',
            reddit_username='general_user',
            original_filename='g.txt',
            content='payload',
            recipient_user=None,
        )
        UploadedLog.objects.create(
            upload_id='alice-log',
            reddit_username='alice_user',
            original_filename='a.txt',
            content='payload',
            recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='bob-log',
            reddit_username='bob_user',
            original_filename='b.txt',
            content='payload',
            recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertContains(response, 'alice-log')
        self.assertNotContains(response, 'general-log')
        self.assertNotContains(response, 'bob-log')

    def test_uploaded_logs_list_show_all_includes_other_helpers_uploads(self):
        UploadedLog.objects.create(
            upload_id='general-log-all',
            reddit_username='general_user',
            original_filename='g.txt',
            content='payload',
            recipient_user=None,
        )
        UploadedLog.objects.create(
            upload_id='alice-log-all',
            reddit_username='alice_user',
            original_filename='a.txt',
            content='payload',
            recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='bob-log-all',
            reddit_username='bob_user',
            original_filename='b.txt',
            content='payload',
            recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'), {'show_all': '1'})

        self.assertContains(response, 'general-log-all')
        self.assertContains(response, 'alice-log-all')
        self.assertContains(response, 'bob-log-all')
        self.assertTrue(response.context.get('show_all'))

    def test_uploaded_logs_list_is_paginated(self):
        for index in range(9):
            UploadedLog.objects.create(
                upload_id=f'page-log-{index}',
                reddit_username='paged_user',
                original_filename='x.txt',
                content='payload',
                recipient_user=self.user,
            )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['page_obj'].paginator.num_pages, 2)
        self.assertEqual(len(response.context['page_obj'].object_list), 8)
        self.assertContains(response, 'page 1 of 2')
        self.assertContains(response, 'page-log-8')
        self.assertNotContains(response, 'page-log-0')

        second_page = self.client.get(reverse('uploaded_logs'), {'page': '2'})

        self.assertEqual(second_page.status_code, 200)
        self.assertEqual(second_page.context['page_obj'].number, 2)
        self.assertContains(second_page, 'page-log-0')
        self.assertNotContains(second_page, 'page-log-8')

    def test_uploaded_logs_pagination_preserves_filter_and_channel_state(self):
        for index in range(9):
            UploadedLog.objects.create(
                upload_id=f'alice-page-log-{index}',
                reddit_username='alice_user',
                original_filename='x.txt',
                content='payload',
                recipient_user=self.user,
            )
        UploadedLog.objects.create(
            upload_id='bob-page-log',
            reddit_username='bob_user',
            original_filename='x.txt',
            content='payload',
            recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'), {'page': '2', 'u': 'alice_user', 'show_all': '1'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['page_obj'].number, 2)
        self.assertEqual(response.context['pagination_query'], 'u=alice_user&show_all=1')
        self.assertContains(response, '?page=1&amp;u=alice_user&amp;show_all=1')
        self.assertContains(response, 'alice-page-log-0')
        self.assertNotContains(response, 'bob-page-log')

    def test_uploads_list_shows_content_hash(self):
        uploaded = UploadedLog.objects.create(
            upload_id='hash-list',
            reddit_username='test_user',
            original_filename='x.txt',
            content='payload',
            recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertContains(response, uploaded.content_hash[:8])

    def test_uploads_list_highlights_duplicate_hashes(self):
        UploadedLog.objects.create(
            upload_id='dup-one',
            reddit_username='test_user',
            original_filename='a.txt',
            content='duplicate content',
            recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='dup-two',
            reddit_username='test_user',
            original_filename='b.txt',
            content='duplicate content',
            recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))
        html = response.content.decode()

        self.assertIn('content-hash duplicate-hash', html)

    def test_uploads_list_no_duplicate_class_for_unique_hashes(self):
        UploadedLog.objects.create(
            upload_id='unique-one',
            reddit_username='test_user',
            original_filename='a.txt',
            content='completely unique content alpha',
        )
        UploadedLog.objects.create(
            upload_id='unique-two',
            reddit_username='test_user',
            original_filename='b.txt',
            content='completely unique content beta',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))
        html = response.content.decode()

        self.assertNotIn('content-hash duplicate-hash', html)

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

    def test_delete_selected_uploads_moves_selected_to_trash(self):
        first = UploadedLog.objects.create(
            upload_id='drift-spark',
            reddit_username='reddit_name',
            original_filename='first.txt',
            content='aaa',
        )
        second = UploadedLog.objects.create(
            upload_id='echo-meadow',
            reddit_username='reddit_name',
            original_filename='second.txt',
            content='bbb',
        )
        keep = UploadedLog.objects.create(
            upload_id='frost-cove',
            reddit_username='reddit_name',
            original_filename='keep.txt',
            content='ccc',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {
                'action': 'delete_selected',
                'selected_upload_ids': [first.upload_id, second.upload_id],
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('uploaded_logs'))
        first.refresh_from_db()
        second.refresh_from_db()
        keep.refresh_from_db()
        self.assertIsNotNone(first.deleted_at)
        self.assertIsNotNone(second.deleted_at)
        self.assertIsNone(keep.deleted_at)

    def test_delete_selected_uploads_requires_selection(self):
        existing = UploadedLog.objects.create(
            upload_id='glint-grove',
            reddit_username='reddit_name',
            original_filename='only.txt',
            content='payload',
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {
                'action': 'delete_selected',
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('uploaded_logs'))
        existing.refresh_from_db()
        self.assertIsNone(existing.deleted_at)

    def test_delete_selected_uploads_rejects_other_helpers_assigned_uploads(self):
        own = UploadedLog.objects.create(
            upload_id='delete-selected-own',
            reddit_username='reddit_name',
            original_filename='own.txt',
            content='aaa',
            recipient_user=self.user,
        )
        other = UploadedLog.objects.create(
            upload_id='delete-selected-foreign',
            reddit_username='reddit_name',
            original_filename='foreign.txt',
            content='bbb',
            recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.post(
            reverse('uploaded_logs'),
            {
                'action': 'delete_selected',
                'selected_upload_ids': [own.upload_id, other.upload_id],
                'show_all': '1',
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Only the assigned helper can delete: delete-selected-foreign.')
        own.refresh_from_db()
        other.refresh_from_db()
        self.assertIsNone(own.deleted_at)
        self.assertIsNone(other.deleted_at)

    def test_bulk_rescan_recalculates_stats_for_selected_uploads(self):
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
            {
                'action': 'rescan_selected',
                'selected_upload_ids': ['silent-river', 'rapid-harbor'],
            },
        )

        first.refresh_from_db()
        second.refresh_from_db()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('uploaded_logs'))
        self.assertEqual(first.total_line_count, 3)
        self.assertEqual(first.count_malware, 1)
        self.assertEqual(first.count_unknown, 2)
        self.assertEqual(second.total_line_count, 2)
        self.assertEqual(second.count_malware, 1)
        self.assertEqual(second.count_unknown, 1)

    def test_bulk_rescan_only_rescans_selected_uploads(self):
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
        self.client.post(
            reverse('uploaded_logs'),
            {
                'action': 'rescan_selected',
                'selected_upload_ids': ['silent-river'],
            },
        )

        first.refresh_from_db()
        second.refresh_from_db()

        self.assertEqual(first.count_malware, 1)
        self.assertEqual(second.count_malware, 0)

    def test_username_filter_shows_only_matching_uploads(self):
        UploadedLog.objects.create(
            upload_id='amber-wolf',
            reddit_username='alice_user',
            original_filename='a.txt',
            content='aaa',
            recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='azure-bear',
            reddit_username='bob_user',
            original_filename='b.txt',
            content='bbb',
            recipient_user=self.user,
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
            recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='azure-bear',
            reddit_username='bob_user',
            original_filename='b.txt',
            content='bbb',
            recipient_user=self.user,
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
            recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='azure-bear',
            reddit_username='bob_user',
            original_filename='b.txt',
            content='bbb',
            recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'))

        self.assertIn('alice_user', list(response.context['all_usernames']))
        self.assertIn('bob_user', list(response.context['all_usernames']))

    def test_search_filters_by_upload_id(self):
        UploadedLog.objects.create(
            upload_id='amber-wolf', reddit_username='user1',
            original_filename='a.txt', content='aaa', recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='azure-bear', reddit_username='user2',
            original_filename='b.txt', content='bbb', recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'), {'q': 'amber'})

        self.assertContains(response, 'amber-wolf')
        self.assertNotContains(response, 'azure-bear')

    def test_search_filters_by_reddit_username(self):
        UploadedLog.objects.create(
            upload_id='amber-wolf', reddit_username='alice_user',
            original_filename='a.txt', content='aaa', recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='azure-bear', reddit_username='bob_user',
            original_filename='b.txt', content='bbb', recipient_user=self.user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'), {'q': 'bob_user'})

        self.assertContains(response, 'azure-bear')
        self.assertNotContains(response, 'amber-wolf')

    def test_search_filters_by_assignee_username(self):
        UploadedLog.objects.create(
            upload_id='amber-wolf', reddit_username='user1',
            original_filename='a.txt', content='aaa', recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='azure-bear', reddit_username='user2',
            original_filename='b.txt', content='bbb', recipient_user=self.other_user,
        )
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('uploaded_logs'), {'q': 'bob', 'show_all': '1'})

        self.assertContains(response, 'azure-bear')
        self.assertNotContains(response, 'amber-wolf')

