from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import Fixlist, InfectionCase, InfectionCaseFixlist, InfectionCaseLog, InfectionCaseNote, UploadedLog
from ..views.infection_cases import _build_case_timeline
from ..views.utils import _autoclose_stale_cases


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
            forum_username='target_user',
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
            forum_username='target_user',
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
            forum_username='target_user',
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
            forum_username='target_user',
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
            forum_username='target_user',
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
            forum_username='own_user',
            original_filename='own.txt',
            content='content',
            recipient_user=self.user,
        )
        UploadedLog.objects.create(
            upload_id='username-choice-general',
            forum_username='general_user',
            original_filename='general.txt',
            content='content',
            recipient_user=None,
        )
        UploadedLog.objects.create(
            upload_id='username-choice-other-helper',
            forum_username='other_helper_user',
            original_filename='other.txt',
            content='content',
            recipient_user=self.other_user,
        )

        response = self.client.get(reverse('create_infection_case'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="uploadedLogUsernames"')
        self.assertContains(response, 'value="own_user"')
        self.assertContains(response, 'value="general_user"')
        # other_helper_user excluded from scoped datalist but included in all-usernames datalist
        scoped_choices = response.context['username_choices']
        all_choices = response.context['all_username_choices']
        self.assertNotIn('other_helper_user', scoped_choices)
        self.assertIn('other_helper_user', all_choices)

    def test_seed_case_adds_all_scoped_items_for_case_username(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        in_scope_log = UploadedLog.objects.create(
            upload_id='seed-log-owned',
            forum_username='target_user',
            original_filename='owned.txt',
            content='content',
            recipient_user=self.user,
        )
        general_log = UploadedLog.objects.create(
            upload_id='seed-log-general',
            forum_username='target_user',
            original_filename='general.txt',
            content='content',
            recipient_user=None,
        )
        UploadedLog.objects.create(
            upload_id='seed-log-other-helper',
            forum_username='target_user',
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
            forum_username='target_user',
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
            forum_username='target_user',
            original_filename='log.txt',
            content='content',
            recipient_user=None,
        )
        assigned_log = UploadedLog.objects.create(
            upload_id='assigned-log',
            forum_username='target_user',
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
            forum_username='other_name',
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
        self.assertEqual(mismatched_log.forum_username, 'target_user')
        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=mismatched_log).exists())

    def test_case_timeline_is_sorted_by_item_creation_time(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        uploaded_log = UploadedLog.objects.create(
            upload_id='timeline-log',
            forum_username='target_user',
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
            forum_username='target_user',
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
            forum_username='target_user',
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
            forum_username='target_user',
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
            forum_username='target_user',
            original_filename='early.txt',
            content='content',
            recipient_user=self.user,
        )
        log_late = UploadedLog.objects.create(
            upload_id='anchor-late',
            forum_username='target_user',
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
            forum_username='target_user',
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
            forum_username='target_user',
            original_filename='visible-log.txt',
            content='content',
            recipient_user=self.user,
        )
        hidden_log = UploadedLog.objects.create(
            upload_id='case-list-hidden-log',
            forum_username='target_user',
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
            forum_username='target_user',
            original_filename='visible-log.txt',
            content='content',
            recipient_user=self.user,
        )
        hidden_log = UploadedLog.objects.create(
            upload_id='timeline-hidden-log',
            forum_username='target_user',
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

    def test_other_helper_can_view_case_read_only(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self.client.logout()
        self.client.login(username='bob', password='password123')

        response = self.client.get(reverse('view_infection_case', args=[case.case_id]))

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.context['can_edit'])
        self.assertContains(response, 'view-only')
        self.assertContains(response, self.user.username)

    def test_other_helper_cannot_post_mutations_to_shared_case(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self.client.logout()
        self.client.login(username='bob', password='password123')

        response = self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'add_note', 'note_content': 'sneaky'},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(InfectionCaseNote.objects.filter(case=case).count(), 0)

    def test_other_helper_cannot_delete_case_they_do_not_own(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self.client.logout()
        self.client.login(username='bob', password='password123')

        delete_response = self.client.post(reverse('infection_case_delete', args=[case.case_id]))

        self.assertEqual(delete_response.status_code, 404)
        case.refresh_from_db()
        self.assertIsNone(case.deleted_at)

    def test_soft_deleted_case_is_404_for_non_owner(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            auto_assign_new_items=False,
            deleted_at=timezone.now(),
        )
        self.client.logout()
        self.client.login(username='bob', password='password123')

        response = self.client.get(reverse('view_infection_case', args=[case.case_id]))

        self.assertEqual(response.status_code, 404)


class InfectionCaseMergeLogsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.other_user = User.objects.create_user(username='bob', password='password123')
        self.client.login(username='alice', password='password123')
        self.case = InfectionCase.objects.create(
            owner=self.user, username='target_user', auto_assign_new_items=False,
        )

    def _link_log(self, *, upload_id, forum_username='target_user', content='content', filename=None):
        log = UploadedLog.objects.create(
            upload_id=upload_id,
            forum_username=forum_username,
            original_filename=filename or f'{upload_id}.txt',
            content=content,
            recipient_user=self.user,
        )
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=log, added_by=self.user)
        return log

    def test_merge_logs_in_case_combines_and_links_merged_log(self):
        log_a = self._link_log(upload_id='merge-case-a', content='AAA\n')
        log_b = self._link_log(upload_id='merge-case-b', content='BBB\n')

        response = self.client.post(
            reverse('view_infection_case', args=[self.case.case_id]),
            {'action': 'merge_logs', 'selected_upload_ids': [log_a.upload_id, log_b.upload_id]},
        )

        self.assertEqual(response.status_code, 302)
        merged = UploadedLog.objects.get(upload_id='merge-case-a', deleted_at__isnull=True)
        self.assertIn('AAA', merged.content)
        self.assertIn('BBB', merged.content)
        # Sources were renamed and soft-deleted.
        self.assertFalse(UploadedLog.objects.filter(upload_id='merge-case-b', deleted_at__isnull=True).exists())
        self.assertTrue(UploadedLog.objects.filter(upload_id='merge-case-b-trsh', deleted_at__isnull=False).exists())
        # Merged log is on the case timeline.
        self.assertTrue(InfectionCaseLog.objects.filter(case=self.case, uploaded_log=merged).exists())

    def test_merge_logs_requires_two_selected(self):
        log_a = self._link_log(upload_id='merge-too-few-a')

        response = self.client.post(
            reverse('view_infection_case', args=[self.case.case_id]),
            {'action': 'merge_logs', 'selected_upload_ids': [log_a.upload_id]},
        )

        self.assertEqual(response.status_code, 302)
        log_a.refresh_from_db()
        self.assertIsNone(log_a.deleted_at)

    def test_merge_logs_with_different_usernames_renders_confirmation(self):
        log_a = self._link_log(upload_id='merge-multi-a', forum_username='alpha', content='AAA\n')
        log_b = self._link_log(upload_id='merge-multi-b', forum_username='beta', content='BBB\n')

        response = self.client.post(
            reverse('view_infection_case', args=[self.case.case_id]),
            {'action': 'merge_logs', 'selected_upload_ids': [log_a.upload_id, log_b.upload_id]},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'choose a username')
        self.assertContains(response, 'value="alpha"')
        self.assertContains(response, 'value="beta"')
        # No merge yet — both sources still active.
        self.assertIsNone(UploadedLog.objects.get(pk=log_a.pk).deleted_at)
        self.assertIsNone(UploadedLog.objects.get(pk=log_b.pk).deleted_at)

        confirm_response = self.client.post(
            reverse('view_infection_case', args=[self.case.case_id]),
            {
                'action': 'confirm_merge_logs',
                'selected_upload_ids': [log_a.upload_id, log_b.upload_id],
                'selected_username': 'beta',
            },
        )

        self.assertEqual(confirm_response.status_code, 302)
        merged = UploadedLog.objects.get(upload_id='merge-multi-a', deleted_at__isnull=True)
        self.assertEqual(merged.forum_username, 'beta')
        self.assertTrue(InfectionCaseLog.objects.filter(case=self.case, uploaded_log=merged).exists())

    def test_merge_logs_rejects_logs_not_in_case(self):
        in_case = self._link_log(upload_id='merge-scoped-in')
        outside = UploadedLog.objects.create(
            upload_id='merge-scoped-outside',
            forum_username='target_user',
            original_filename='outside.txt',
            content='ZZZ\n',
            recipient_user=self.user,
        )

        response = self.client.post(
            reverse('view_infection_case', args=[self.case.case_id]),
            {'action': 'merge_logs', 'selected_upload_ids': [in_case.upload_id, outside.upload_id]},
        )

        self.assertEqual(response.status_code, 302)
        in_case.refresh_from_db()
        outside.refresh_from_db()
        self.assertIsNone(in_case.deleted_at)
        self.assertIsNone(outside.deleted_at)


class InfectionCaseTrainingModeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.other_user = User.objects.create_user(username='bob', password='password123')
        self.client.login(username='alice', password='password123')

    def test_create_training_case_sets_is_training_flag(self):
        response = self.client.post(
            reverse('create_infection_case'),
            {
                'username': 'target_user',
                'is_training': '1',
            },
        )

        self.assertEqual(response.status_code, 302)
        created = InfectionCase.objects.get(owner=self.user)
        self.assertTrue(created.is_training)

    def test_training_case_forces_auto_assign_off(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            auto_assign_new_items=True,
            is_training=True,
        )

        case.refresh_from_db()
        self.assertFalse(case.auto_assign_new_items)

    def test_auto_assign_signal_skips_training_cases_for_logs(self):
        InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            is_training=True,
        )

        created_log = UploadedLog.objects.create(
            upload_id='training-signal-log',
            forum_username='target_user',
            original_filename='signal.txt',
            content='content',
            recipient_user=None,
        )

        created_log.refresh_from_db()
        self.assertIsNone(created_log.recipient_user)
        self.assertFalse(InfectionCaseLog.objects.filter(uploaded_log=created_log).exists())

    def test_auto_assign_signal_skips_training_cases_for_fixlists(self):
        InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            is_training=True,
        )

        created_fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='x')

        self.assertFalse(InfectionCaseFixlist.objects.filter(fixlist=created_fixlist).exists())

    def test_link_case_items_does_not_reassign_recipient_for_training_case(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            is_training=True,
        )
        unassigned_log = UploadedLog.objects.create(
            upload_id='training-unassigned',
            forum_username='target_user',
            original_filename='log.txt',
            content='content',
            recipient_user=None,
        )

        self.client.post(
            reverse('infection_case_add_items', args=[case.case_id]),
            {'selected_upload_ids': [unassigned_log.upload_id]},
        )

        unassigned_log.refresh_from_db()
        self.assertIsNone(unassigned_log.recipient_user)
        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=unassigned_log).exists())

    def test_add_items_skips_username_mismatch_confirmation_for_training_case(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            is_training=True,
        )
        mismatched_log = UploadedLog.objects.create(
            upload_id='training-mismatch',
            forum_username='other_name',
            original_filename='x.txt',
            content='content',
            recipient_user=self.user,
        )

        response = self.client.post(
            reverse('infection_case_add_items', args=[case.case_id]),
            {'selected_upload_ids': [mismatched_log.upload_id]},
        )

        self.assertEqual(response.status_code, 302)
        mismatched_log.refresh_from_db()
        self.assertEqual(mismatched_log.forum_username, 'other_name')
        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=mismatched_log).exists())

    def test_training_case_seed_includes_other_helper_logs(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            is_training=True,
        )
        other_helper_log = UploadedLog.objects.create(
            upload_id='training-other-helper',
            forum_username='target_user',
            original_filename='other.txt',
            content='content',
            recipient_user=self.other_user,
        )

        self.client.post(
            reverse('view_infection_case', args=[case.case_id]),
            {'action': 'seed_username_items'},
        )

        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=other_helper_log).exists())
        other_helper_log.refresh_from_db()
        self.assertEqual(other_helper_log.recipient_user, self.other_user)

    def test_training_case_selectable_uploads_includes_other_helper_logs(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            is_training=True,
        )
        other_helper_log = UploadedLog.objects.create(
            upload_id='training-selectable-other',
            forum_username='target_user',
            original_filename='other.txt',
            content='content',
            recipient_user=self.other_user,
        )

        response = self.client.get(reverse('view_infection_case', args=[case.case_id]))

        selectable_ids = set(response.context['selectable_uploads'].values_list('upload_id', flat=True))
        self.assertIn('training-selectable-other', selectable_ids)

    def test_non_training_case_selectable_uploads_excludes_other_helper_logs(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            auto_assign_new_items=False,
        )
        UploadedLog.objects.create(
            upload_id='normal-other-helper',
            forum_username='target_user',
            original_filename='other.txt',
            content='content',
            recipient_user=self.other_user,
        )

        response = self.client.get(reverse('view_infection_case', args=[case.case_id]))

        selectable_ids = set(response.context['selectable_uploads'].values_list('upload_id', flat=True))
        self.assertNotIn('normal-other-helper', selectable_ids)

    def test_training_shown_in_case_list(self):
        InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            is_training=True,
        )

        response = self.client.get(reverse('infection_cases'))

        self.assertContains(response, 'observe')

    def test_training_shown_in_case_detail(self):
        case = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            is_training=True,
        )

        response = self.client.get(reverse('view_infection_case', args=[case.case_id]))

        self.assertContains(response, 'observe')


class AutoCloseStaleCasesTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.client.login(username='alice', password='password123')
        self.stale_time = timezone.now() - timedelta(days=31)
        self.recent_time = timezone.now() - timedelta(days=29)

    def _backdate_case(self, case, when):
        InfectionCase.objects.filter(pk=case.pk).update(created_at=when)

    def _make_log(self, upload_id, when):
        log = UploadedLog.objects.create(
            upload_id=upload_id,
            forum_username='target_user',
            original_filename=f'{upload_id}.txt',
            content='content',
            recipient_user=self.user,
        )
        UploadedLog.objects.filter(pk=log.pk).update(created_at=when)
        return log

    def test_case_with_old_log_is_closed(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self._backdate_case(case, self.stale_time)
        log = self._make_log('autoclose-old-log', self.stale_time)
        InfectionCaseLog.objects.create(case=case, uploaded_log=log, added_by=self.user)

        _autoclose_stale_cases()

        case.refresh_from_db()
        self.assertEqual(case.status, InfectionCase.STATUS_CLOSED)

    def test_case_with_recent_log_stays_open(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self._backdate_case(case, self.stale_time)
        log = self._make_log('autoclose-recent-log', self.recent_time)
        InfectionCaseLog.objects.create(case=case, uploaded_log=log, added_by=self.user)

        _autoclose_stale_cases()

        case.refresh_from_db()
        self.assertEqual(case.status, InfectionCase.STATUS_OPEN)

    def test_case_with_recent_note_stays_open(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self._backdate_case(case, self.stale_time)
        note = InfectionCaseNote.objects.create(case=case, content='still working', created_by=self.user)
        InfectionCaseNote.objects.filter(pk=note.pk).update(created_at=self.recent_time)

        _autoclose_stale_cases()

        case.refresh_from_db()
        self.assertEqual(case.status, InfectionCase.STATUS_OPEN)

    def test_empty_case_closed_when_created_long_ago(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self._backdate_case(case, self.stale_time)

        _autoclose_stale_cases()

        case.refresh_from_db()
        self.assertEqual(case.status, InfectionCase.STATUS_CLOSED)

    def test_empty_recent_case_stays_open(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self._backdate_case(case, self.recent_time)

        _autoclose_stale_cases()

        case.refresh_from_db()
        self.assertEqual(case.status, InfectionCase.STATUS_OPEN)

    def test_stale_training_case_is_not_closed(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', is_training=True)
        self._backdate_case(case, self.stale_time)

        _autoclose_stale_cases()

        case.refresh_from_db()
        self.assertEqual(case.status, InfectionCase.STATUS_OPEN)

    def test_already_closed_and_soft_deleted_cases_are_untouched(self):
        soft_deleted = InfectionCase.objects.create(
            owner=self.user,
            username='target_user',
            auto_assign_new_items=False,
            deleted_at=timezone.now(),
        )
        self._backdate_case(soft_deleted, self.stale_time)

        closed = _autoclose_stale_cases()

        self.assertEqual(closed, 0)

    def test_old_log_with_recent_fixlist_stays_open(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self._backdate_case(case, self.stale_time)
        old_log = self._make_log('mixed-old-log', self.stale_time)
        InfectionCaseLog.objects.create(case=case, uploaded_log=old_log, added_by=self.user)
        fixlist = Fixlist.objects.create(owner=self.user, username='target_user', content='fix')
        Fixlist.objects.filter(pk=fixlist.pk).update(created_at=self.recent_time)
        InfectionCaseFixlist.objects.create(case=case, fixlist=fixlist, added_by=self.user)

        _autoclose_stale_cases()

        case.refresh_from_db()
        self.assertEqual(case.status, InfectionCase.STATUS_OPEN)

    def test_returns_count_of_closed_cases(self):
        first = InfectionCase.objects.create(owner=self.user, username='u1', auto_assign_new_items=False)
        second = InfectionCase.objects.create(owner=self.user, username='u2', auto_assign_new_items=False)
        self._backdate_case(first, self.stale_time)
        self._backdate_case(second, self.stale_time)

        self.assertEqual(_autoclose_stale_cases(), 2)

    def test_loading_cases_list_triggers_autoclose(self):
        case = InfectionCase.objects.create(owner=self.user, username='target_user', auto_assign_new_items=False)
        self._backdate_case(case, self.stale_time)

        response = self.client.get(reverse('infection_cases'))

        self.assertEqual(response.status_code, 200)
        case.refresh_from_db()
        self.assertEqual(case.status, InfectionCase.STATUS_CLOSED)
