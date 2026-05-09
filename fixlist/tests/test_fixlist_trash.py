from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser, User
from django.contrib.messages import get_messages
from django.core.management import call_command
from django.http import Http404, HttpResponse
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import AccessLog, Fixlist, UploadedLog
from ..views import shared_fixlist_view


def _make_user(username, password="password123"):
    return User.objects.create_user(username=username, password=password)


def _make_fixlist(owner, username="My Fixlist", content="line-1", **kwargs):
    return Fixlist.objects.create(owner=owner, username=username, content=content, **kwargs)


class FixlistSoftDeleteTests(TestCase):
    def setUp(self):
        self.user = _make_user("alice")
        self.client.login(username="alice", password="password123")
        self.fixlist = _make_fixlist(self.user)

    def _delete(self):
        return self.client.post(
            reverse("view_fixlist", args=[self.fixlist.pk]),
            {"action": "delete"},
        )

    def test_delete_sets_deleted_at(self):
        self._delete()
        self.fixlist.refresh_from_db()
        self.assertIsNotNone(self.fixlist.deleted_at)

    def test_delete_record_still_exists(self):
        self._delete()
        self.assertTrue(Fixlist.objects.filter(pk=self.fixlist.pk).exists())

    def test_delete_redirects_to_dashboard(self):
        response = self._delete()
        self.assertRedirects(response, reverse("dashboard"))

    def test_trashed_fixlist_excluded_from_dashboard(self):
        active = _make_fixlist(self.user, username="Active")
        _make_fixlist(self.user, username="Trashed", deleted_at=timezone.now())

        response = self.client.get(reverse("dashboard"))

        self.assertContains(response, "Active")
        self.assertNotContains(response, "Trashed")

    def test_dashboard_shows_trash_count(self):
        _make_fixlist(self.user, deleted_at=timezone.now())
        _make_fixlist(self.user, deleted_at=timezone.now())

        response = self.client.get(reverse("dashboard"))

        self.assertContains(response, "trash (2)")

    def test_dashboard_shows_no_count_when_trash_empty(self):
        _make_fixlist(self.user)

        response = self.client.get(reverse("dashboard"))

        self.assertNotContains(response, "trash (")
        self.assertContains(response, ">trash<")

    def test_delete_purges_old_fixlist_trash(self):
        old = _make_fixlist(
            self.user,
            username="Old Trash",
            deleted_at=timezone.now() - timedelta(days=8),
        )

        self._delete()

        self.assertFalse(Fixlist.objects.filter(pk=old.pk).exists())

    def test_delete_keeps_recent_fixlist_trash(self):
        recent = _make_fixlist(
            self.user,
            username="Recent Trash",
            deleted_at=timezone.now() - timedelta(days=1),
        )

        self._delete()

        self.assertTrue(Fixlist.objects.filter(pk=recent.pk).exists())


class DashboardSearchAndFilterTests(TestCase):
    def setUp(self):
        self.user = _make_user("alice")
        self.client.login(username="alice", password="password123")

    def test_dashboard_search_filters_by_username(self):
        _make_fixlist(self.user, username="amber_meadow")
        _make_fixlist(self.user, username="quiet_forest")

        response = self.client.get(reverse("dashboard"), {"q": "amber"})
        listed = {f.username for f in response.context["fixlists"]}

        self.assertEqual(listed, {"amber_meadow"})

    def test_dashboard_search_filters_by_share_token(self):
        first = _make_fixlist(self.user, username="hits")
        _make_fixlist(self.user, username="misses")
        token_fragment = first.share_token[:8]

        response = self.client.get(reverse("dashboard"), {"q": token_fragment})
        listed = {f.username for f in response.context["fixlists"]}

        self.assertEqual(listed, {"hits"})

    def test_dashboard_user_dropdown_filters_by_username(self):
        _make_fixlist(self.user, username="alpha_user")
        _make_fixlist(self.user, username="beta_user")

        response = self.client.get(reverse("dashboard"), {"u": "alpha_user"})
        listed = {f.username for f in response.context["fixlists"]}

        self.assertEqual(listed, {"alpha_user"})

    def test_dashboard_user_dropdown_lists_all_active_usernames(self):
        _make_fixlist(self.user, username="alpha_user")
        _make_fixlist(self.user, username="beta_user")
        _make_fixlist(self.user, username="trashed_user", deleted_at=timezone.now())

        response = self.client.get(reverse("dashboard"))
        usernames = list(response.context["all_usernames"])

        self.assertIn("alpha_user", usernames)
        self.assertIn("beta_user", usernames)
        self.assertNotIn("trashed_user", usernames)

    def test_dashboard_pagination_preserves_filters(self):
        for index in range(11):
            _make_fixlist(self.user, username=f"paged_{index}")

        response = self.client.get(reverse("dashboard"), {"q": "paged"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "page=2")
        self.assertContains(response, "q=paged")

    def test_dashboard_bulk_delete_moves_fixlists_to_trash(self):
        first = _make_fixlist(self.user, username="bulk_del_1")
        second = _make_fixlist(self.user, username="bulk_del_2")

        self.client.post(
            reverse("dashboard"),
            {"action": "delete_selected", "selected_pks": [first.pk, second.pk]},
        )

        first.refresh_from_db()
        second.refresh_from_db()
        self.assertIsNotNone(first.deleted_at)
        self.assertIsNotNone(second.deleted_at)

    def test_dashboard_bulk_delete_cannot_affect_other_users(self):
        bob = _make_user("bob")
        bobs = _make_fixlist(bob, username="bobs_active")

        self.client.post(
            reverse("dashboard"),
            {"action": "delete_selected", "selected_pks": [bobs.pk]},
        )

        bobs.refresh_from_db()
        self.assertIsNone(bobs.deleted_at)


class FixlistsTrashViewTests(TestCase):
    def setUp(self):
        self.user = _make_user("alice")
        self.client.login(username="alice", password="password123")

    def _trashed(self, username="Trashed", **kwargs):
        return _make_fixlist(self.user, username=username, deleted_at=timezone.now(), **kwargs)

    def test_trash_view_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("fixlists_trash"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

    def test_trash_view_shows_trashed_fixlists(self):
        self._trashed(username="In Trash")

        response = self.client.get(reverse("fixlists_trash"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "In Trash")

    def test_trash_view_excludes_active_fixlists(self):
        _make_fixlist(self.user, username="Active")
        self._trashed(username="Trashed")

        response = self.client.get(reverse("fixlists_trash"))

        self.assertNotContains(response, "Active")
        self.assertContains(response, "Trashed")

    def test_trash_view_scoped_to_owner(self):
        other = _make_user("bob")
        _make_fixlist(other, username="Bob Trash", deleted_at=timezone.now())

        response = self.client.get(reverse("fixlists_trash"))

        self.assertNotContains(response, "Bob Trash")

    # --- restore ---

    def test_restore_clears_deleted_at(self):
        fixlist = self._trashed()

        self.client.post(reverse("fixlists_trash"), {"action": "restore", "pk": fixlist.pk})

        fixlist.refresh_from_db()
        self.assertIsNone(fixlist.deleted_at)

    def test_restore_fixlist_appears_in_dashboard(self):
        fixlist = self._trashed(username="Restore Me")

        self.client.post(reverse("fixlists_trash"), {"action": "restore", "pk": fixlist.pk})

        response = self.client.get(reverse("dashboard"))
        self.assertContains(response, "Restore Me")

    def test_restore_redirects_to_trash(self):
        fixlist = self._trashed()

        response = self.client.post(
            reverse("fixlists_trash"), {"action": "restore", "pk": fixlist.pk}
        )

        self.assertRedirects(response, reverse("fixlists_trash"))

    def test_restore_cannot_affect_other_users_fixlist(self):
        other = _make_user("bob")
        fixlist = _make_fixlist(other, username="Bob Trash", deleted_at=timezone.now())

        response = self.client.post(
            reverse("fixlists_trash"), {"action": "restore", "pk": fixlist.pk}
        )

        self.assertEqual(response.status_code, 404)
        fixlist.refresh_from_db()
        self.assertIsNotNone(fixlist.deleted_at)

    # --- permanent delete ---

    def test_permanent_delete_removes_record(self):
        fixlist = self._trashed()

        self.client.post(
            reverse("fixlists_trash"), {"action": "delete_permanent", "pk": fixlist.pk}
        )

        self.assertFalse(Fixlist.objects.filter(pk=fixlist.pk).exists())

    def test_permanent_delete_redirects_to_trash(self):
        fixlist = self._trashed()

        response = self.client.post(
            reverse("fixlists_trash"), {"action": "delete_permanent", "pk": fixlist.pk}
        )

        self.assertRedirects(response, reverse("fixlists_trash"))

    def test_permanent_delete_only_works_on_trashed(self):
        fixlist = _make_fixlist(self.user, username="Active")

        response = self.client.post(
            reverse("fixlists_trash"), {"action": "delete_permanent", "pk": fixlist.pk}
        )

        self.assertEqual(response.status_code, 404)
        self.assertTrue(Fixlist.objects.filter(pk=fixlist.pk).exists())

    def test_permanent_delete_cannot_affect_other_users_fixlist(self):
        other = _make_user("bob")
        fixlist = _make_fixlist(other, deleted_at=timezone.now())

        response = self.client.post(
            reverse("fixlists_trash"), {"action": "delete_permanent", "pk": fixlist.pk}
        )

        self.assertEqual(response.status_code, 404)
        self.assertTrue(Fixlist.objects.filter(pk=fixlist.pk).exists())

    # --- empty trash ---

    def test_empty_trash_removes_all_user_trashed_fixlists(self):
        self._trashed(username="One")
        self._trashed(username="Two")

        self.client.post(reverse("fixlists_trash"), {"action": "empty_trash"})

        self.assertFalse(
            Fixlist.objects.filter(owner=self.user, deleted_at__isnull=False).exists()
        )

    def test_empty_trash_does_not_affect_active_fixlists(self):
        active = _make_fixlist(self.user, username="Active")
        self._trashed(username="Gone")

        self.client.post(reverse("fixlists_trash"), {"action": "empty_trash"})

        self.assertTrue(Fixlist.objects.filter(pk=active.pk).exists())

    def test_empty_trash_does_not_affect_other_users_fixlists(self):
        other = _make_user("bob")
        bob_trashed = _make_fixlist(other, deleted_at=timezone.now())

        self.client.post(reverse("fixlists_trash"), {"action": "empty_trash"})

        self.assertTrue(Fixlist.objects.filter(pk=bob_trashed.pk).exists())

    def test_empty_trash_redirects_to_trash(self):
        response = self.client.post(reverse("fixlists_trash"), {"action": "empty_trash"})
        self.assertRedirects(response, reverse("fixlists_trash"))

    def test_empty_trash_count_excludes_cascaded_rows(self):
        first = self._trashed(username="One")
        second = self._trashed(username="Two")
        for _ in range(3):
            AccessLog.objects.create(fixlist=first)
        for _ in range(5):
            AccessLog.objects.create(fixlist=second)

        response = self.client.post(reverse("fixlists_trash"), {"action": "empty_trash"})

        messages_list = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages_list), 1)
        self.assertEqual(
            str(messages_list[0]),
            "Trash emptied (2 fixlist(s) permanently deleted).",
        )

    # --- search and filter ---

    def test_trash_search_filters_by_username(self):
        self._trashed(username="amber_meadow")
        self._trashed(username="quiet_forest")

        response = self.client.get(reverse("fixlists_trash"), {"q": "amber"})
        listed = {f.username for f in response.context["fixlists"]}

        self.assertEqual(listed, {"amber_meadow"})

    def test_trash_user_dropdown_filters_by_username(self):
        self._trashed(username="zed")
        self._trashed(username="yan")

        response = self.client.get(reverse("fixlists_trash"), {"u": "zed"})
        listed = {f.username for f in response.context["fixlists"]}

        self.assertEqual(listed, {"zed"})

    def test_trash_pagination_preserves_filters(self):
        for index in range(11):
            self._trashed(username=f"paged_{index}")

        response = self.client.get(reverse("fixlists_trash"), {"q": "paged"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "page=2")
        self.assertContains(response, "q=paged")

    # --- bulk actions ---

    def test_trash_bulk_restore_clears_deleted_at(self):
        first = self._trashed(username="bulk_restore_1")
        second = self._trashed(username="bulk_restore_2")

        self.client.post(
            reverse("fixlists_trash"),
            {"action": "restore_selected", "selected_pks": [first.pk, second.pk]},
        )

        first.refresh_from_db()
        second.refresh_from_db()
        self.assertIsNone(first.deleted_at)
        self.assertIsNone(second.deleted_at)

    def test_trash_bulk_delete_permanent_removes_records(self):
        first = self._trashed(username="bulk_perm_1")
        second = self._trashed(username="bulk_perm_2")

        self.client.post(
            reverse("fixlists_trash"),
            {"action": "delete_permanent_selected", "selected_pks": [first.pk, second.pk]},
        )

        self.assertFalse(Fixlist.objects.filter(pk__in=[first.pk, second.pk]).exists())

    def test_trash_bulk_actions_cannot_affect_other_users(self):
        bob = _make_user("bob")
        bobs_trash = _make_fixlist(bob, username="bobs_trash", deleted_at=timezone.now())

        self.client.post(
            reverse("fixlists_trash"),
            {"action": "delete_permanent_selected", "selected_pks": [bobs_trash.pk]},
        )

        self.assertTrue(Fixlist.objects.filter(pk=bobs_trash.pk).exists())

    def test_trash_bulk_restore_rejects_active_fixlist(self):
        active = _make_fixlist(self.user, username="active")

        self.client.post(
            reverse("fixlists_trash"),
            {"action": "restore_selected", "selected_pks": [active.pk]},
        )

        active.refresh_from_db()
        self.assertIsNone(active.deleted_at)


class TrashedFixlistGuestAccessTests(TestCase):
    def setUp(self):
        self.user = _make_user("alice")
        self.factory = RequestFactory()
        self.fixlist = _make_fixlist(self.user, deleted_at=timezone.now())

    # --- shared view ---

    def test_shared_view_returns_404_for_anonymous_on_trashed_fixlist(self):
        request = self.factory.get(
            reverse("shared_fixlist", args=[self.fixlist.share_token])
        )
        request.user = AnonymousUser()

        with self.assertRaises(Http404):
            shared_fixlist_view(request, token=self.fixlist.share_token)

    def test_shared_view_returns_404_for_other_logged_in_user_on_trashed_fixlist(self):
        other = _make_user("bob")
        request = self.factory.get(
            reverse("shared_fixlist", args=[self.fixlist.share_token])
        )
        request.user = other

        with self.assertRaises(Http404):
            shared_fixlist_view(request, token=self.fixlist.share_token)

    def test_shared_view_allows_owner_access_to_trashed_fixlist(self):
        self.client.login(username="alice", password="password123")

        response = self.client.get(
            reverse("shared_fixlist", args=[self.fixlist.share_token])
        )

        self.assertEqual(response.status_code, 200)

    # --- download ---

    def test_download_returns_404_for_anonymous_on_trashed_fixlist(self):
        response = self.client.get(
            reverse("download_fixlist", args=[self.fixlist.share_token])
        )
        self.assertEqual(response.status_code, 404)

    def test_download_returns_404_for_other_logged_in_user_on_trashed_fixlist(self):
        _make_user("bob")
        self.client.login(username="bob", password="password123")

        response = self.client.get(
            reverse("download_fixlist", args=[self.fixlist.share_token])
        )

        self.assertEqual(response.status_code, 404)

    def test_download_allows_owner_access_to_trashed_fixlist(self):
        self.client.login(username="alice", password="password123")

        response = self.client.get(
            reverse("download_fixlist", args=[self.fixlist.share_token])
        )

        self.assertEqual(response.status_code, 200)

    # --- copy API ---

    def test_copy_api_returns_404_for_anonymous_on_trashed_fixlist(self):
        response = self.client.post(
            reverse("copy_api", args=[self.fixlist.share_token])
        )
        self.assertEqual(response.status_code, 404)

    def test_copy_api_returns_404_for_other_logged_in_user_on_trashed_fixlist(self):
        _make_user("bob")
        self.client.login(username="bob", password="password123")

        response = self.client.post(
            reverse("copy_api", args=[self.fixlist.share_token])
        )

        self.assertEqual(response.status_code, 404)

    def test_copy_api_allows_owner_access_to_trashed_fixlist(self):
        self.client.login(username="alice", password="password123")

        response = self.client.post(
            reverse("copy_api", args=[self.fixlist.share_token])
        )

        self.assertEqual(response.status_code, 200)

    # --- active fixlists unaffected ---

    def test_shared_view_accessible_for_anonymous_when_not_trashed(self):
        active = _make_fixlist(self.user, username="Public")
        request = self.factory.get(reverse("shared_fixlist", args=[active.share_token]))
        request.user = AnonymousUser()

        with patch("fixlist.views.fixlists.render", return_value=HttpResponse("ok")) as mock_render:
            response = shared_fixlist_view(request, token=active.share_token)

        self.assertEqual(response.status_code, 200)


class FixlistPurgeOldTrashTests(TestCase):
    def setUp(self):
        self.user = _make_user("alice")
        self.client.login(username="alice", password="password123")
        self.active = _make_fixlist(self.user, username="Active")

    def _old_deleted_at(self):
        return timezone.now() - timedelta(days=8)

    def _recent_deleted_at(self):
        return timezone.now() - timedelta(days=1)

    def _trash_active(self):
        """Trigger a trash action (which calls _purge_old_trash)."""
        self.client.post(
            reverse("view_fixlist", args=[self.active.pk]),
            {"action": "delete"},
        )

    def test_trashing_fixlist_purges_old_fixlist_trash(self):
        old = _make_fixlist(self.user, username="Old", deleted_at=self._old_deleted_at())

        self._trash_active()

        self.assertFalse(Fixlist.objects.filter(pk=old.pk).exists())

    def test_trashing_fixlist_keeps_recent_fixlist_trash(self):
        recent = _make_fixlist(
            self.user, username="Recent", deleted_at=self._recent_deleted_at()
        )

        self._trash_active()

        self.assertTrue(Fixlist.objects.filter(pk=recent.pk).exists())

    def test_trashing_fixlist_does_not_delete_active_fixlists(self):
        other_active = _make_fixlist(self.user, username="Other Active")

        self._trash_active()

        self.assertTrue(Fixlist.objects.filter(pk=other_active.pk).exists())

    def test_trashing_fixlist_also_purges_old_upload_trash(self):
        old_upload = UploadedLog.objects.create(
            upload_id="old-trash",
            reddit_username="test_user",
            original_filename="x.txt",
            content="payload",
            deleted_at=self._old_deleted_at(),
        )

        self._trash_active()

        self.assertFalse(UploadedLog.objects.filter(pk=old_upload.pk).exists())

    def test_purge_command_deletes_old_fixlists(self):
        old = _make_fixlist(self.user, username="Old", deleted_at=self._old_deleted_at())

        call_command("purge_old_trash", verbosity=0)

        self.assertFalse(Fixlist.objects.filter(pk=old.pk).exists())

    def test_purge_command_keeps_recent_fixlists(self):
        recent = _make_fixlist(
            self.user, username="Recent", deleted_at=self._recent_deleted_at()
        )

        call_command("purge_old_trash", verbosity=0)

        self.assertTrue(Fixlist.objects.filter(pk=recent.pk).exists())

    def test_purge_command_keeps_active_fixlists(self):
        call_command("purge_old_trash", verbosity=0)

        self.assertTrue(Fixlist.objects.filter(pk=self.active.pk).exists())

    def test_purge_command_hard_deletes_fixlists_older_than_30_days(self):
        old = _make_fixlist(self.user, username="Ancient")
        Fixlist.objects.filter(pk=old.pk).update(
            created_at=timezone.now() - timedelta(days=31),
        )

        call_command("purge_old_trash", verbosity=0)

        self.assertFalse(Fixlist.objects.filter(pk=old.pk).exists())

    def test_purge_command_keeps_fixlists_under_30_days(self):
        recent = _make_fixlist(self.user, username="Recent")
        Fixlist.objects.filter(pk=recent.pk).update(
            created_at=timezone.now() - timedelta(days=15),
        )

        call_command("purge_old_trash", verbosity=0)

        self.assertTrue(Fixlist.objects.filter(pk=recent.pk).exists())

    def test_purge_command_hard_deletes_uploads_older_than_30_days(self):
        old_upload = UploadedLog.objects.create(
            upload_id="ancient-upload",
            reddit_username="test_user",
            original_filename="x.txt",
            content="payload",
        )
        UploadedLog.objects.filter(pk=old_upload.pk).update(
            created_at=timezone.now() - timedelta(days=31),
        )

        call_command("purge_old_trash", verbosity=0)

        self.assertFalse(UploadedLog.objects.filter(pk=old_upload.pk).exists())
