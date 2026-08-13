"""Deletion protection for uploaded logs and fixlists.

Protected records must survive every delete path: manual trash/permanent delete
(single and bulk), empty trash, merges, case cascades, and the automatic purge.
"""
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import Fixlist, UploadedLog
from ..views.utils import _purge_old_trash


def _make_user(username, password='password123'):
    return User.objects.create_user(username=username, password=password)


class UploadedLogProtectionTests(TestCase):
    def setUp(self):
        self.user = _make_user('alice')
        self.client.login(username='alice', password='password123')

    def _make_log(self, upload_id, **kwargs):
        kwargs.setdefault('recipient_user', self.user)
        return UploadedLog.objects.create(
            upload_id=upload_id,
            forum_username='test_user',
            original_filename='x.txt',
            content='payload',
            **kwargs,
        )

    # --- toggling ---

    def test_protect_action_sets_flag(self):
        log = self._make_log('quiet-forest')

        self.client.post(reverse('view_uploaded_log', args=[log.upload_id]), {'action': 'protect'})

        log.refresh_from_db()
        self.assertTrue(log.is_protected)

    def test_unprotect_action_clears_flag(self):
        log = self._make_log('bright-river', is_protected=True)

        self.client.post(reverse('view_uploaded_log', args=[log.upload_id]), {'action': 'unprotect'})

        log.refresh_from_db()
        self.assertFalse(log.is_protected)

    def test_other_helpers_channel_cannot_toggle_protection(self):
        bob = _make_user('bob')
        log = self._make_log('bobs-log', recipient_user=bob)

        self.client.post(reverse('view_uploaded_log', args=[log.upload_id]), {'action': 'protect'})

        log.refresh_from_db()
        self.assertFalse(log.is_protected)

    def test_detail_view_shows_protected_state(self):
        log = self._make_log('shown-log', is_protected=True)

        response = self.client.get(reverse('view_uploaded_log', args=[log.upload_id]))

        self.assertContains(response, 'deletion-protected')
        self.assertContains(response, 'value="unprotect"')

    # --- delete paths ---

    def test_detail_delete_blocked(self):
        log = self._make_log('safe-detail', is_protected=True)

        self.client.post(reverse('view_uploaded_log', args=[log.upload_id]), {'action': 'delete'})

        log.refresh_from_db()
        self.assertIsNone(log.deleted_at)

    def test_list_delete_blocked(self):
        log = self._make_log('safe-list', is_protected=True)

        self.client.post(reverse('uploaded_logs'), {'action': 'delete', 'upload_id': log.upload_id})

        log.refresh_from_db()
        self.assertIsNone(log.deleted_at)

    def test_bulk_delete_blocked_and_leaves_selection_untouched(self):
        protected = self._make_log('safe-bulk', is_protected=True)
        other = self._make_log('plain-bulk')

        self.client.post(reverse('uploaded_logs'), {
            'action': 'delete_selected',
            'selected_upload_ids': [protected.upload_id, other.upload_id],
        })

        protected.refresh_from_db()
        other.refresh_from_db()
        self.assertIsNone(protected.deleted_at)
        self.assertIsNone(other.deleted_at)

    def test_permanent_delete_blocked(self):
        log = self._make_log('safe-perm', is_protected=True, deleted_at=timezone.now())

        self.client.post(reverse('uploads_trash'), {
            'action': 'delete_permanent',
            'upload_id': log.upload_id,
        })

        self.assertTrue(UploadedLog.objects.filter(pk=log.pk).exists())

    def test_bulk_permanent_delete_blocked(self):
        protected = self._make_log('safe-perm-bulk', is_protected=True, deleted_at=timezone.now())
        other = self._make_log('plain-perm-bulk', deleted_at=timezone.now())

        self.client.post(reverse('uploads_trash'), {
            'action': 'delete_permanent_selected',
            'selected_upload_ids': [protected.upload_id, other.upload_id],
        })

        self.assertTrue(UploadedLog.objects.filter(pk=protected.pk).exists())
        self.assertTrue(UploadedLog.objects.filter(pk=other.pk).exists())

    def test_empty_trash_keeps_protected_and_deletes_the_rest(self):
        protected = self._make_log('safe-empty', is_protected=True, deleted_at=timezone.now())
        other = self._make_log('plain-empty', deleted_at=timezone.now())

        self.client.post(reverse('uploads_trash'), {'action': 'empty_trash'})

        self.assertTrue(UploadedLog.objects.filter(pk=protected.pk).exists())
        self.assertFalse(UploadedLog.objects.filter(pk=other.pk).exists())

    def test_merge_blocked_when_a_source_is_protected(self):
        protected = self._make_log('safe-merge', is_protected=True)
        other = self._make_log('plain-merge')

        self.client.post(reverse('uploaded_logs'), {
            'action': 'merge',
            'selected_upload_ids': [protected.upload_id, other.upload_id],
        })

        protected.refresh_from_db()
        other.refresh_from_db()
        self.assertIsNone(protected.deleted_at)
        self.assertIsNone(other.deleted_at)

    # --- automatic purge ---

    def test_purge_keeps_protected_log_in_trash(self):
        protected = self._make_log('safe-purge', is_protected=True)
        other = self._make_log('plain-purge')
        old_trash = timezone.now() - timedelta(days=8)
        UploadedLog.objects.filter(pk__in=[protected.pk, other.pk]).update(deleted_at=old_trash)

        _purge_old_trash()

        self.assertTrue(UploadedLog.objects.filter(pk=protected.pk).exists())
        self.assertFalse(UploadedLog.objects.filter(pk=other.pk).exists())

    def test_purge_keeps_protected_log_past_hard_cutoff(self):
        protected = self._make_log('safe-old', is_protected=True)
        other = self._make_log('plain-old')
        long_ago = timezone.now() - timedelta(days=40)
        UploadedLog.objects.filter(pk__in=[protected.pk, other.pk]).update(created_at=long_ago)

        _purge_old_trash()

        self.assertTrue(UploadedLog.objects.filter(pk=protected.pk).exists())
        self.assertFalse(UploadedLog.objects.filter(pk=other.pk).exists())


class FixlistProtectionTests(TestCase):
    def setUp(self):
        self.user = _make_user('alice')
        self.client.login(username='alice', password='password123')

    def _make_fixlist(self, username='My Fixlist', **kwargs):
        return Fixlist.objects.create(
            owner=self.user, username=username, content='line-1', **kwargs
        )

    # --- toggling ---

    def test_protect_action_sets_flag(self):
        fixlist = self._make_fixlist()

        self.client.post(reverse('view_fixlist', args=[fixlist.pk]), {'action': 'protect'})

        fixlist.refresh_from_db()
        self.assertTrue(fixlist.is_protected)

    def test_unprotect_action_clears_flag(self):
        fixlist = self._make_fixlist(is_protected=True)

        self.client.post(reverse('view_fixlist', args=[fixlist.pk]), {'action': 'unprotect'})

        fixlist.refresh_from_db()
        self.assertFalse(fixlist.is_protected)

    def test_detail_view_shows_protected_state(self):
        fixlist = self._make_fixlist(is_protected=True)

        response = self.client.get(reverse('view_fixlist', args=[fixlist.pk]))

        self.assertContains(response, 'deletion-protected')
        self.assertContains(response, 'value="unprotect"')

    # --- delete paths ---

    def test_detail_delete_blocked(self):
        fixlist = self._make_fixlist(is_protected=True)

        self.client.post(reverse('view_fixlist', args=[fixlist.pk]), {'action': 'delete'})

        fixlist.refresh_from_db()
        self.assertIsNone(fixlist.deleted_at)

    def test_bulk_delete_blocked_and_leaves_selection_untouched(self):
        protected = self._make_fixlist(username='Protected', is_protected=True)
        other = self._make_fixlist(username='Plain')

        self.client.post(reverse('dashboard'), {
            'action': 'delete_selected',
            'selected_pks': [protected.pk, other.pk],
        })

        protected.refresh_from_db()
        other.refresh_from_db()
        self.assertIsNone(protected.deleted_at)
        self.assertIsNone(other.deleted_at)

    def test_permanent_delete_blocked(self):
        fixlist = self._make_fixlist(is_protected=True, deleted_at=timezone.now())

        self.client.post(reverse('fixlists_trash'), {
            'action': 'delete_permanent',
            'pk': fixlist.pk,
        })

        self.assertTrue(Fixlist.objects.filter(pk=fixlist.pk).exists())

    def test_bulk_permanent_delete_blocked(self):
        protected = self._make_fixlist(username='Protected', is_protected=True, deleted_at=timezone.now())
        other = self._make_fixlist(username='Plain', deleted_at=timezone.now())

        self.client.post(reverse('fixlists_trash'), {
            'action': 'delete_permanent_selected',
            'selected_pks': [protected.pk, other.pk],
        })

        self.assertTrue(Fixlist.objects.filter(pk=protected.pk).exists())
        self.assertTrue(Fixlist.objects.filter(pk=other.pk).exists())

    def test_empty_trash_keeps_protected_and_deletes_the_rest(self):
        protected = self._make_fixlist(username='Protected', is_protected=True, deleted_at=timezone.now())
        other = self._make_fixlist(username='Plain', deleted_at=timezone.now())

        self.client.post(reverse('fixlists_trash'), {'action': 'empty_trash'})

        self.assertTrue(Fixlist.objects.filter(pk=protected.pk).exists())
        self.assertFalse(Fixlist.objects.filter(pk=other.pk).exists())

    # --- automatic purge ---

    def test_purge_keeps_protected_fixlist_in_trash(self):
        protected = self._make_fixlist(username='Protected', is_protected=True)
        other = self._make_fixlist(username='Plain')
        old_trash = timezone.now() - timedelta(days=8)
        Fixlist.objects.filter(pk__in=[protected.pk, other.pk]).update(deleted_at=old_trash)

        _purge_old_trash()

        self.assertTrue(Fixlist.objects.filter(pk=protected.pk).exists())
        self.assertFalse(Fixlist.objects.filter(pk=other.pk).exists())

    def test_purge_keeps_protected_fixlist_past_hard_cutoff(self):
        protected = self._make_fixlist(username='Protected', is_protected=True)
        other = self._make_fixlist(username='Plain')
        long_ago = timezone.now() - timedelta(days=40)
        Fixlist.objects.filter(pk__in=[protected.pk, other.pk]).update(created_at=long_ago)

        _purge_old_trash()

        self.assertTrue(Fixlist.objects.filter(pk=protected.pk).exists())
        self.assertFalse(Fixlist.objects.filter(pk=other.pk).exists())


class InfectionCaseCascadeProtectionTests(TestCase):
    def test_case_delete_cascade_skips_protected_items(self):
        from ..models import InfectionCase, InfectionCaseFixlist, InfectionCaseLog

        user = _make_user('alice')
        self.client.login(username='alice', password='password123')
        case = InfectionCase.objects.create(owner=user, username='victim')
        log = UploadedLog.objects.create(
            upload_id='cased-log',
            forum_username='victim',
            original_filename='x.txt',
            content='payload',
            recipient_user=user,
            is_protected=True,
        )
        fixlist = Fixlist.objects.create(
            owner=user, username='victim', content='line-1', is_protected=True
        )
        # Cases with auto-assign already link new items, so only fill in gaps.
        InfectionCaseLog.objects.get_or_create(case=case, uploaded_log=log)
        InfectionCaseFixlist.objects.get_or_create(case=case, fixlist=fixlist)

        self.client.post(
            reverse('infection_case_delete', args=[case.case_id]),
            {'move_linked_to_trash': '1'},
        )

        log.refresh_from_db()
        fixlist.refresh_from_db()
        case.refresh_from_db()
        self.assertIsNone(log.deleted_at)
        self.assertIsNone(fixlist.deleted_at)
        self.assertIsNotNone(case.deleted_at)
