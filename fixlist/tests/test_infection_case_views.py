from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import Fixlist, InfectionCase, InfectionCaseFixlist, InfectionCaseLog, InfectionCaseNote, UploadedLog
from ..views.infection_cases import _build_case_timeline


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

    def test_seed_case_assigns_unassigned_logs_to_case_owner(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        general_log = UploadedLog.objects.create(
            upload_id='seed-general-assign',
            reddit_username='target_user',
            original_filename='general.txt',
            content='content',
            recipient_user=None,
        )

        self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'seed_username_items'},
        )

        general_log.refresh_from_db()
        self.assertEqual(general_log.recipient_user, self.user)

    def test_linking_unassigned_log_to_case_assigns_to_case_owner(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        unassigned_log = UploadedLog.objects.create(
            upload_id='unassigned-log',
            reddit_username='target_user',
            original_filename='log.txt',
            content='content',
            recipient_user=None,
        )
        assigned_log = UploadedLog.objects.create(
            upload_id='assigned-log',
            reddit_username='target_user',
            original_filename='log2.txt',
            content='content',
            recipient_user=self.user,
        )

        self.client.post(
            reverse('infection_case_add_items', args=[case.case_id]),
            {'selected_upload_ids': [unassigned_log.upload_id, assigned_log.upload_id]},
        )

        unassigned_log.refresh_from_db()
        assigned_log.refresh_from_db()
        self.assertEqual(unassigned_log.recipient_user, self.user)
        self.assertEqual(assigned_log.recipient_user, self.user)

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
        fixlist.refresh_from_db()
        self.assertLess(html.find('timeline-log'), html.find(fixlist.share_token))

    def test_add_note_creates_right_side_timeline_item(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'add_note', 'note_content': 'User observed recurring browser popups.'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(InfectionCaseNote.objects.filter(case=case).count(), 1)
        page = self.client.get(reverse('view_infection_case', args=[case.case_id]))
        self.assertContains(page, 'NOTE')
        self.assertContains(page, 'User observed recurring browser popups.')

    def test_add_note_rejects_empty_content(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'add_note', 'note_content': '   '},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(InfectionCaseNote.objects.filter(case=case).count(), 0)

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

    def test_delete_case_keeps_linked_items_when_trash_option_not_selected(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        uploaded_log = UploadedLog.objects.create(
            upload_id='delete-case-log',
            reddit_username='target_user',
            original_filename='delete-log.txt',
            content='content',
            recipient_user=self.user,
        )
        fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='fix')
        InfectionCaseLog.objects.create(case=case, uploaded_log=uploaded_log, added_by=self.user)
        InfectionCaseFixlist.objects.create(case=case, fixlist=fixlist, added_by=self.user)

        response = self.client.post(reverse('infection_case_delete', args=[case.case_id]))

        self.assertEqual(response.status_code, 302)
        case.refresh_from_db()
        uploaded_log.refresh_from_db()
        fixlist.refresh_from_db()
        self.assertIsNotNone(case.deleted_at)
        self.assertIsNone(uploaded_log.deleted_at)
        self.assertIsNone(fixlist.deleted_at)

    def test_delete_case_can_move_linked_items_to_trash(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        uploaded_log = UploadedLog.objects.create(
            upload_id='delete-case-trash-log',
            reddit_username='target_user',
            original_filename='delete-trash-log.txt',
            content='content',
            recipient_user=self.user,
        )
        fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='fix')
        InfectionCaseLog.objects.create(case=case, uploaded_log=uploaded_log, added_by=self.user)
        InfectionCaseFixlist.objects.create(case=case, fixlist=fixlist, added_by=self.user)

        response = self.client.post(
            reverse('infection_case_delete', args=[case.case_id]),
            {'move_linked_to_trash': '1'},
        )

        self.assertEqual(response.status_code, 302)
        case.refresh_from_db()
        uploaded_log.refresh_from_db()
        fixlist.refresh_from_db()
        self.assertIsNotNone(case.deleted_at)
        self.assertIsNotNone(uploaded_log.deleted_at)
        self.assertIsNotNone(fixlist.deleted_at)

    def test_anchored_note_appears_directly_after_anchor_log(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        log_early = UploadedLog.objects.create(
            upload_id='anchor-early',
            reddit_username='target_user',
            original_filename='early.txt',
            content='content',
            recipient_user=self.user,
        )
        log_late = UploadedLog.objects.create(
            upload_id='anchor-late',
            reddit_username='target_user',
            original_filename='late.txt',
            content='content',
            recipient_user=self.user,
        )
        t1 = timezone.now() - timedelta(days=3)
        t2 = timezone.now() - timedelta(days=1)
        UploadedLog.objects.filter(pk=log_early.pk).update(created_at=t1)
        UploadedLog.objects.filter(pk=log_late.pk).update(created_at=t2)

        link_early = InfectionCaseLog.objects.create(case=case, uploaded_log=log_early, added_by=self.user)
        InfectionCaseLog.objects.create(case=case, uploaded_log=log_late, added_by=self.user)

        # Note is created AFTER log_late but anchored to log_early — it must appear after log_early.
        note = InfectionCaseNote.objects.create(
            case=case, content='anchored to early log', created_by=self.user, anchor_log=link_early
        )
        InfectionCaseNote.objects.filter(pk=note.pk).update(created_at=timezone.now())

        timeline = _build_case_timeline(case)

        self.assertEqual(len(timeline), 3)
        self.assertEqual(timeline[0]['item_type'], 'log')
        self.assertEqual(timeline[0]['uploaded_log'].upload_id, 'anchor-early')
        self.assertEqual(timeline[1]['item_type'], 'note')
        self.assertEqual(timeline[1]['note'].content, 'anchored to early log')
        self.assertEqual(timeline[2]['item_type'], 'log')
        self.assertEqual(timeline[2]['uploaded_log'].upload_id, 'anchor-late')

    def test_add_note_with_invalid_anchor_becomes_unanchored(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'add_note', 'note_content': 'fallback note', 'anchor_log_upload_id': 'no-such-log'},
        )

        self.assertEqual(response.status_code, 302)
        note = InfectionCaseNote.objects.get(case=case)
        self.assertIsNone(note.anchor_log)
        self.assertEqual(note.content, 'fallback note')

    def test_anchored_note_created_via_post_action(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        uploaded_log = UploadedLog.objects.create(
            upload_id='post-anchor-log',
            reddit_username='target_user',
            original_filename='pa.txt',
            content='content',
            recipient_user=self.user,
        )
        link = InfectionCaseLog.objects.create(case=case, uploaded_log=uploaded_log, added_by=self.user)

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'add_note', 'note_content': 'note via anchor', 'anchor_log_upload_id': 'post-anchor-log'},
        )

        self.assertEqual(response.status_code, 302)
        note = InfectionCaseNote.objects.get(case=case)
        self.assertEqual(note.anchor_log_id, link.pk)
        self.assertEqual(note.content, 'note via anchor')

    def test_infection_cases_view_only_lists_owned_active_cases_with_visible_item_counts(self):
        visible_case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        deleted_case = InfectionCase.objects.create(
            owner=self.user,
            username='deleted_user',
            auto_assign_new_items=False,
            deleted_at=timezone.now(),
        )
        InfectionCase.objects.create(owner=self.other_user, username='other_user', auto_assign_new_items=False)

        visible_log = UploadedLog.objects.create(
            upload_id='case-list-visible-log',
            reddit_username='target_user',
            original_filename='visible-log.txt',
            content='content',
            recipient_user=self.user,
        )
        hidden_log = UploadedLog.objects.create(
            upload_id='case-list-hidden-log',
            reddit_username='target_user',
            original_filename='hidden-log.txt',
            content='content',
            recipient_user=self.user,
            deleted_at=timezone.now(),
        )
        visible_fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='fix')
        hidden_fixlist = Fixlist.objects.create(
            owner=self.user,
            username='target_user',
            content='fix',
            deleted_at=timezone.now(),
        )
        visible_note = InfectionCaseNote.objects.create(case=visible_case, content='visible note', created_by=self.user)
        InfectionCaseNote.objects.create(
            case=visible_case,
            content='hidden note',
            created_by=self.user,
            deleted_at=timezone.now(),
        )

        InfectionCaseLog.objects.create(case=visible_case, uploaded_log=visible_log, added_by=self.user)
        InfectionCaseLog.objects.create(case=visible_case, uploaded_log=hidden_log, added_by=self.user)
        InfectionCaseFixlist.objects.create(case=visible_case, fixlist=visible_fixlist, added_by=self.user)
        InfectionCaseFixlist.objects.create(case=visible_case, fixlist=hidden_fixlist, added_by=self.user)

        response = self.client.get(reverse('infection_cases'))

        self.assertEqual(response.status_code, 200)
        cases = response.context['cases']
        self.assertEqual([case.case_id for case in cases], [visible_case.case_id])
        self.assertEqual(cases[0].item_count, 3)
        self.assertEqual(cases[0].last_activity, visible_note.created_at)
        self.assertNotIn(deleted_case.case_id, response.content.decode('utf-8'))

    def test_view_infection_case_timeline_excludes_soft_deleted_items(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        visible_log = UploadedLog.objects.create(
            upload_id='timeline-visible-log',
            reddit_username='target_user',
            original_filename='visible-log.txt',
            content='content',
            recipient_user=self.user,
        )
        hidden_log = UploadedLog.objects.create(
            upload_id='timeline-hidden-log',
            reddit_username='target_user',
            original_filename='hidden-log.txt',
            content='content',
            recipient_user=self.user,
            deleted_at=timezone.now(),
        )
        visible_fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='fix')
        hidden_fixlist = Fixlist.objects.create(
            owner=self.user,
            username='target_user',
            content='fix',
            deleted_at=timezone.now(),
        )
        visible_note = InfectionCaseNote.objects.create(case=case, content='visible note', created_by=self.user)
        InfectionCaseNote.objects.create(
            case=case,
            content='hidden note',
            created_by=self.user,
            deleted_at=timezone.now(),
        )

        InfectionCaseLog.objects.create(case=case, uploaded_log=visible_log, added_by=self.user)
        InfectionCaseLog.objects.create(case=case, uploaded_log=hidden_log, added_by=self.user)
        InfectionCaseFixlist.objects.create(case=case, fixlist=visible_fixlist, added_by=self.user)
        InfectionCaseFixlist.objects.create(case=case, fixlist=hidden_fixlist, added_by=self.user)

        response = self.client.get(reverse('view_infection_case', args=[case.case_id]))

        self.assertEqual(response.status_code, 200)
        timeline_items = response.context['timeline_items']
        self.assertEqual(len(timeline_items), 3)
        self.assertEqual({item['item_type'] for item in timeline_items}, {'log', 'fixlist', 'note'})
        self.assertContains(response, 'timeline-visible-log')
        self.assertContains(response, 'visible note')
        self.assertNotContains(response, 'timeline-hidden-log')
        self.assertNotContains(response, 'hidden note')

    def test_update_case_changes_metadata_status_and_auto_assign(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            symptom_description='old description',
            reference_url='https://example.com/old',
            auto_assign_new_items=True,
        )

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {
                'action': 'update_case',
                'symptom_description': 'new description',
                'reference_url': 'https://example.com/new',
                'status': InfectionCase.STATUS_CLOSED,
            },
        )

        self.assertEqual(response.status_code, 302)
        case.refresh_from_db()
        self.assertEqual(case.symptom_description, 'new description')
        self.assertEqual(case.reference_url, 'https://example.com/new')
        self.assertEqual(case.status, InfectionCase.STATUS_CLOSED)
        self.assertFalse(case.auto_assign_new_items)

    def test_confirm_username_change_updates_mismatched_fixlist_and_links_it(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        mismatched_fixlist = Fixlist.objects.create(owner=self.user, username='other_user', content='fix')

        response = self.client.post(
            reverse('infection_case_add_items', args=[case.case_id]),
            {'selected_fixlist_ids': [str(mismatched_fixlist.pk)]},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'confirm username change')
        self.assertFalse(InfectionCaseFixlist.objects.filter(case=case, fixlist=mismatched_fixlist).exists())

        confirm_response = self.client.post(
            reverse('infection_case_confirm_username_change', args=[case.case_id]),
            {'selected_fixlist_ids': [str(mismatched_fixlist.pk)]},
        )

        self.assertEqual(confirm_response.status_code, 302)
        mismatched_fixlist.refresh_from_db()
        self.assertEqual(mismatched_fixlist.username, 'target_user')
        self.assertTrue(InfectionCaseFixlist.objects.filter(case=case, fixlist=mismatched_fixlist).exists())

    def test_edit_note_updates_content(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        note = InfectionCaseNote.objects.create(case=case, content='original text', created_by=self.user)

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'edit_note', 'note_id': str(note.pk), 'note_content': 'updated text'},
        )

        self.assertEqual(response.status_code, 302)
        note.refresh_from_db()
        self.assertEqual(note.content, 'updated text')

    def test_edit_note_rejects_empty_content(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        note = InfectionCaseNote.objects.create(case=case, content='original text', created_by=self.user)

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'edit_note', 'note_id': str(note.pk), 'note_content': '   '},
        )

        self.assertEqual(response.status_code, 302)
        note.refresh_from_db()
        self.assertEqual(note.content, 'original text')

    def test_delete_note_soft_deletes(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        note = InfectionCaseNote.objects.create(case=case, content='to be deleted', created_by=self.user)

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'delete_note', 'note_id': str(note.pk)},
        )

        self.assertEqual(response.status_code, 302)
        note.refresh_from_db()
        self.assertIsNotNone(note.deleted_at)

    def test_other_user_cannot_view_or_delete_case_they_do_not_own(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self.client.logout()
        self.client.login(username='bob', password='password123')

        view_response = self.client.get(reverse('view_infection_case', args=[case.case_id]))
        delete_response = self.client.post(reverse('infection_case_delete', args=[case.case_id]))

        self.assertEqual(view_response.status_code, 404)
        self.assertEqual(delete_response.status_code, 404)
