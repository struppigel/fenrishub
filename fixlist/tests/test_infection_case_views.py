from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import Fixlist, InfectionCase, InfectionCaseFixlist, InfectionCaseLog, UploadedLog


class InfectionCaseViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.other_user = User.objects.create_user(username='bob', password='password123')
        self.client.login(username='alice', password='password123')

    def test_create_infection_case_creates_record_and_redirects(self):
        response = self.client.post(
            reverse('create_infection_case'),
            {
                'username': 'target_user',
                'symptom_description': 'Symptoms here',
                'reference_url': 'https://example.com/case-notes',
                'auto_assign_new_items': '1',
            },
        )

        self.assertEqual(response.status_code, 302)
        created = InfectionCase.objects.get(owner=self.user)
        self.assertEqual(created.username, 'target_user')
        self.assertTrue(created.auto_assign_new_items)
        self.assertTrue(response.url.endswith(reverse('view_infection_case', args=[created.case_id])))

    def test_create_case_view_auto_assign_checkbox_is_checked_by_default(self):
        response = self.client.get(reverse('create_infection_case'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="auto_assign_new_items"')
        self.assertContains(response, 'checked')

    def test_auto_assign_links_new_logs_and_fixlists_for_matching_username(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=True)

        created_log = UploadedLog.objects.create(
            upload_id='auto-link-log',
            reddit_username='target_user',
            original_filename='auto.txt',
            content='content',
            recipient_user=self.user,
        )
        created_fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='x')

        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=created_log).exists())
        self.assertTrue(InfectionCaseFixlist.objects.filter(case=case, fixlist=created_fixlist).exists())

    def test_auto_assign_unassigned_log_to_matching_case_owner(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=True)

        created_log = UploadedLog.objects.create(
            upload_id='auto-link-unassigned-log',
            reddit_username='target_user',
            original_filename='auto-unassigned.txt',
            content='content',
            recipient_user=None,
        )

        created_log.refresh_from_db()
        self.assertEqual(created_log.recipient_user, self.user)
        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=created_log).exists())

    def test_auto_assign_unassigned_log_skips_when_multiple_case_owners_match(self):
        case_one = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=True)
        case_two = InfectionCase.objects.create(owner=self.other_user, username='target_user', auto_assign_new_items=True)

        created_log = UploadedLog.objects.create(
            upload_id='auto-link-unassigned-ambiguous-log',
            reddit_username='target_user',
            original_filename='auto-unassigned-ambiguous.txt',
            content='content',
            recipient_user=None,
        )

        created_log.refresh_from_db()
        self.assertIsNone(created_log.recipient_user)
        self.assertFalse(InfectionCaseLog.objects.filter(case=case_one, uploaded_log=created_log).exists())
        self.assertFalse(InfectionCaseLog.objects.filter(case=case_two, uploaded_log=created_log).exists())

    def test_auto_assign_disabled_does_not_link_new_items(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)

        created_log = UploadedLog.objects.create(
            upload_id='auto-link-off-log',
            reddit_username='target_user',
            original_filename='auto-off.txt',
            content='content',
            recipient_user=self.user,
        )
        created_fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='x')

        self.assertFalse(InfectionCaseLog.objects.filter(case=case, uploaded_log=created_log).exists())
        self.assertFalse(InfectionCaseFixlist.objects.filter(case=case, fixlist=created_fixlist).exists())

    def test_auto_assign_does_not_link_new_items_for_closed_case(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            auto_assign_new_items=True,
            status=InfectionCase.STATUS_CLOSED,
        )

        created_log = UploadedLog.objects.create(
            upload_id='auto-link-closed-log',
            reddit_username='target_user',
            original_filename='auto-closed.txt',
            content='content',
            recipient_user=self.user,
        )
        created_fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='x')

        self.assertFalse(InfectionCaseLog.objects.filter(case=case, uploaded_log=created_log).exists())
        self.assertFalse(InfectionCaseFixlist.objects.filter(case=case, fixlist=created_fixlist).exists())

    def test_create_case_view_lists_usernames_from_scoped_uploaded_logs(self):
        UploadedLog.objects.create(
            upload_id='username-choice-own',
            reddit_username='own_user',
            original_filename='own.txt',
            content='content',
            recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='username-choice-general',
            reddit_username='general_user',
            original_filename='general.txt',
            content='content',
            recipient_user=None,
        )
        UploadedLog.objects.create(
            upload_id='username-choice-other-helper',
            reddit_username='other_helper_user',
            original_filename='other.txt',
            content='content',
            recipient_user=self.other_user,
        )

        response = self.client.get(reverse('create_infection_case'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="uploadedLogUsernames"')
        self.assertContains(response, 'value="own_user"')
        self.assertContains(response, 'value="general_user"')
        self.assertNotContains(response, 'value="other_helper_user"')

    def test_seed_case_adds_all_scoped_items_for_case_username(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        in_scope_log = UploadedLog.objects.create(
            upload_id='seed-log-owned',
            reddit_username='target_user',
            original_filename='owned.txt',
            content='content',
            recipient_user=self.user,
        )
        general_log = UploadedLog.objects.create(
            upload_id='seed-log-general',
            reddit_username='target_user',
            original_filename='general.txt',
            content='content',
            recipient_user=None,
        )
        UploadedLog.objects.create(
            upload_id='seed-log-other-helper',
            reddit_username='target_user',
            original_filename='other.txt',
            content='content',
            recipient_user=self.other_user,
        )
        owned_fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='x')
        Fixlist.objects.create(owner=self.other_user, username='target_user', content='x')

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'seed_username_items'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=in_scope_log).exists())
        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=general_log).exists())
        self.assertTrue(InfectionCaseFixlist.objects.filter(case=case, fixlist=owned_fixlist).exists())
        self.assertEqual(InfectionCaseLog.objects.filter(case=case).count(), 2)
        self.assertEqual(InfectionCaseFixlist.objects.filter(case=case).count(), 1)

    def test_add_items_requires_confirmation_for_mismatched_username(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        mismatched_log = UploadedLog.objects.create(
            upload_id='confirm-log',
            reddit_username='other_name',
            original_filename='x.txt',
            content='content',
            recipient_user=self.user,
        )

        response = self.client.post(
            reverse('infection_case_add_items', args=[case.case_id]),
            {'selected_upload_ids': [mismatched_log.upload_id]},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'confirm username change')
        self.assertFalse(InfectionCaseLog.objects.filter(case=case, uploaded_log=mismatched_log).exists())

        confirm_response = self.client.post(
            reverse('infection_case_confirm_username_change', args=[case.case_id]),
            {'selected_upload_ids': [mismatched_log.upload_id]},
        )

        self.assertEqual(confirm_response.status_code, 302)
        mismatched_log.refresh_from_db()
        self.assertEqual(mismatched_log.reddit_username, 'target_user')
        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=mismatched_log).exists())

    def test_case_timeline_is_sorted_by_item_creation_time(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        uploaded_log = UploadedLog.objects.create(
            upload_id='timeline-log',
            reddit_username='target_user',
            original_filename='log.txt',
            content='content',
            recipient_user=self.user,
        )
        fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='fix')

        old_time = timezone.now() - timedelta(days=2)
        new_time = timezone.now() - timedelta(days=1)
        UploadedLog.objects.filter(pk=uploaded_log.pk).update(created_at=old_time)
        Fixlist.objects.filter(pk=fixlist.pk).update(created_at=new_time)

        InfectionCaseLog.objects.create(case=case, uploaded_log=uploaded_log, added_by=self.user)
        InfectionCaseFixlist.objects.create(case=case, fixlist=fixlist, added_by=self.user)

        response = self.client.get(reverse('view_infection_case', args=[case.case_id]))

        self.assertEqual(response.status_code, 200)
        html = response.content.decode('utf-8')
        self.assertLess(html.find('timeline-log'), html.find(f'#{fixlist.pk}'))

    def test_unlink_log_removes_only_case_link(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        uploaded_log = UploadedLog.objects.create(
            upload_id='unlink-log',
            reddit_username='target_user',
            original_filename='unlink.txt',
            content='content',
            recipient_user=self.user,
        )
        InfectionCaseLog.objects.create(case=case, uploaded_log=uploaded_log, added_by=self.user)

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {
                'action': 'unlink_log',
                'upload_id': uploaded_log.upload_id,
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(InfectionCaseLog.objects.filter(case=case, uploaded_log=uploaded_log).exists())
        self.assertTrue(UploadedLog.objects.filter(pk=uploaded_log.pk).exists())

    def test_unlink_fixlist_removes_only_case_link(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='fix')
        InfectionCaseFixlist.objects.create(case=case, fixlist=fixlist, added_by=self.user)

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {
                'action': 'unlink_fixlist',
                'fixlist_id': str(fixlist.pk),
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(InfectionCaseFixlist.objects.filter(case=case, fixlist=fixlist).exists())
        self.assertTrue(Fixlist.objects.filter(pk=fixlist.pk).exists())
