"""One forum user under several forum names (fixlist/username_merge.py): the
admin's "same users" page, renaming whole names, and the related-logs tab's
button renaming same-machine logs to the log's forum name."""

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..models import (
    Fixlist, FixlistStat, InfectionCase, UploadedLog, UploadedLogMachineSignal, UploadedLogStat,
)
from ..username_merge import rename_forum_usernames, same_user_groups
from .factories import make_superuser, make_uploaded_log, make_user
from .test_machine_signals import ADDITION, FRST


def add_log(upload_id, content, forum_username, **extra):
    upload = make_uploaded_log(upload_id, log_type='Addition', content=content, forum_username=forum_username, **extra)
    UploadedLogMachineSignal.rebuild_for(upload)
    return upload


def group_names(groups):
    return [sorted(row['name'] for row in group['names']) for group in groups]


class SameUserGroupsTests(TestCase):
    def test_names_sharing_the_machine_sid_and_disks_are_grouped(self):
        add_log('bob-log', ADDITION, 'bob')
        add_log('robert-log', ADDITION.replace('Bob', 'Robert'), 'robert')
        add_log('bob-log-2', ADDITION, 'bob')
        groups = same_user_groups()
        self.assertEqual(group_names(groups), [['bob', 'robert']])
        group = groups[0]
        self.assertEqual(group['evidence'], ['machine SID', 'disk ID'])
        self.assertEqual([row['name'] for row in group['names']], ['bob', 'robert'])  # most logs first
        self.assertEqual(group['names'][0]['logs'], 2)
        self.assertEqual(group['names'][0]['samples'], ['bob-log-2', 'bob-log'])

    def test_another_windows_install_is_not_grouped(self):
        add_log('bob-log', ADDITION, 'bob')
        # The same disks, but another machine SID: the full comparison says different.
        add_log('x-log', ADDITION.replace('497541903', '111111111'), 'x')
        self.assertEqual(same_user_groups(), [])

    def test_a_signal_shared_by_many_names_is_ignored(self):
        for i in range(6):
            add_log(f'disk-log-{i}', 'Disk: 1 (Size: 1 GB) (Disk ID: AAAA1111)\n', f'user{i}')
        self.assertEqual(same_user_groups(), [])
        self.assertEqual(len(same_user_groups(max_names_per_key=6)), 1)

    def test_trashed_logs_are_ignored(self):
        add_log('bob-log', ADDITION, 'bob')
        add_log('trashed-log', ADDITION, 'trashy', deleted_at=timezone.now())
        self.assertEqual(same_user_groups(), [])

    def test_computer_name_counts_only_with_the_same_hardware(self):
        add_log('frst-log', FRST, 'bob')
        add_log('hw-log', FRST.replace('82K2', '99ZZ'), 'eve')
        self.assertEqual(same_user_groups(), [])
        add_log('pc-log', FRST.replace('Bob', 'Eve'), 'evelyn')
        groups = same_user_groups()
        self.assertEqual(group_names(groups), [['bob', 'evelyn']])
        self.assertEqual(groups[0]['evidence'], ['computer name and hardware'])

    def test_counts_fixlists_and_cases(self):
        owner = make_user()
        add_log('bob-log', ADDITION, 'bob')
        add_log('robert-log', ADDITION.replace('Bob', 'Robert'), 'robert')
        Fixlist.objects.create(owner=owner, username='robert', content='x')
        case = InfectionCase.objects.create(owner=owner, username='carol', auto_assign_new_items=False)
        case.set_extra_usernames(['robert'])
        rows = {row['name']: row for row in same_user_groups()[0]['names']}
        self.assertEqual((rows['robert']['fixlists'], rows['robert']['cases']), (1, 1))
        self.assertEqual((rows['bob']['fixlists'], rows['bob']['cases']), (0, 0))


class RenameForumUsernamesTests(TestCase):
    def setUp(self):
        self.owner = make_user()

    def test_renames_logs_stats_fixlists_and_cases(self):
        live = make_uploaded_log('live-log', forum_username='Robert')
        trashed = make_uploaded_log('trashed-log', forum_username='Robert', deleted_at=timezone.now())
        other = make_uploaded_log('other-log', forum_username='someone')
        orphan = UploadedLogStat.objects.create(source_id=99999, created_at=timezone.now(), forum_username='robert')
        fixlist = Fixlist.objects.create(owner=self.owner, username='Robert', content='x')
        main_case = InfectionCase.objects.create(owner=self.owner, username='Robert', auto_assign_new_items=False)
        main_case.set_extra_usernames(['bob', 'rob'])
        extra_case = InfectionCase.objects.create(owner=self.owner, username='carol', auto_assign_new_items=False)
        extra_case.set_extra_usernames(['Robert', 'bob', 'rob'])

        counts = rename_forum_usernames(['Robert', 'rob'], ' bob ')

        self.assertEqual(counts, {'logs': 2, 'fixlists': 1, 'cases': 2})
        for upload in (live, trashed):
            upload.refresh_from_db()
            self.assertEqual(upload.forum_username, 'bob')
            self.assertEqual(UploadedLogStat.objects.get(source_id=upload.pk).forum_username, 'bob')
        other.refresh_from_db()
        self.assertEqual(other.forum_username, 'someone')
        orphan.refresh_from_db()
        self.assertEqual(orphan.forum_username, 'bob')
        fixlist.refresh_from_db()
        self.assertEqual(fixlist.username, 'bob')
        self.assertEqual(FixlistStat.objects.get(source_id=fixlist.pk).username, 'bob')
        main_case.refresh_from_db()
        self.assertEqual(main_case.all_usernames(), ['bob'])
        extra_case.refresh_from_db()
        self.assertEqual(extra_case.all_usernames(), ['carol', 'bob'])

    def test_invalid_new_name(self):
        with self.assertRaises(ValueError):
            rename_forum_usernames(['a'], '   ')
        with self.assertRaises(ValueError):
            rename_forum_usernames(['a'], 'x' * 101)


class SameUsersAdminTests(TestCase):
    def setUp(self):
        add_log('bob-log', ADDITION, 'bob')
        add_log('robert-log', ADDITION.replace('Bob', 'Robert'), 'robert')
        self.url = reverse('admin:fixlist_uploadedlog_same_users')

    def test_staff_only(self):
        self.client.force_login(make_user())
        self.assertEqual(self.client.get(self.url).status_code, 302)
        self.client.post(self.url, {'names': ['robert'], 'target': 'bob'})
        self.assertEqual(UploadedLog.objects.get(upload_id='robert-log').forum_username, 'robert')

    def test_lists_the_groups(self):
        self.client.force_login(make_superuser())
        html = self.client.get(self.url).content.decode()
        self.assertIn('same machine SID, disk ID', html)
        self.assertIn('robert-log', html)
        self.assertIn(reverse('admin:fixlist_uploadedlog_same_users'),
                      self.client.get(reverse('admin:fixlist_uploadedlog_changelist')).content.decode())

    def test_renames_to_a_listed_or_another_name(self):
        self.client.force_login(make_superuser())
        response = self.client.post(self.url, {'names': ['bob', 'robert'], 'target': 'bob'})
        self.assertRedirects(response, self.url, fetch_redirect_response=False)
        self.assertEqual(set(UploadedLog.objects.values_list('forum_username', flat=True)), {'bob'})
        self.client.post(self.url, {'names': ['bob'], 'target': '__custom__', 'custom_target': 'Bobby'})
        self.assertEqual(set(UploadedLog.objects.values_list('forum_username', flat=True)), {'Bobby'})

    def test_rejects_invalid_input(self):
        self.client.force_login(make_superuser())
        for data in (
            {'names': ['robert'], 'target': '__custom__', 'custom_target': ' '},
            {'names': ['robert'], 'target': '__custom__', 'custom_target': 'x' * 101},
            {'names': ['bob'], 'target': 'bob'},
            {'names': ['nobody'], 'target': 'bob'},
        ):
            self.client.post(self.url, data)
        self.assertEqual(UploadedLog.objects.get(upload_id='robert-log').forum_username, 'robert')
        self.assertEqual(UploadedLog.objects.get(upload_id='bob-log').forum_username, 'bob')


class RenameMachineLogsButtonTests(TestCase):
    def setUp(self):
        self.helper = make_user('helper')
        self.other_helper = make_user('other')
        self.bob = add_log('bob-log', ADDITION, 'bob')
        self.unassigned = add_log('robert-log', ADDITION.replace('Bob', 'Robert'), 'robert')
        self.mine = add_log('mine-log', ADDITION.replace('Bob', 'Rob'), 'rob', recipient_user=self.helper)
        self.theirs = add_log('theirs-log', ADDITION.replace('Bob', 'Rob'), 'rob', recipient_user=self.other_helper)
        self.unrelated = add_log('unrelated-log', 'just text', 'someone')
        self.fixlist = Fixlist.objects.create(owner=self.helper, username='robert', content='x')

    def fragment(self):
        return self.client.get(reverse('uploaded_log_related', args=['bob-log'])).content.decode()

    def rename(self, upload_ids):
        return self.client.post(
            reverse('view_uploaded_log', args=['bob-log']), {'action': 'rename_machine_logs', 'upload_ids': upload_ids},
        )

    def names(self):
        return dict(UploadedLog.objects.values_list('upload_id', 'forum_username'))

    def test_helper_sees_the_logs_they_may_rename(self):
        self.client.force_login(self.helper)
        html = self.fragment()
        self.assertIn('rename 2 logs to u/bob', html)
        self.assertIn('value="robert-log"', html)
        self.assertIn('value="mine-log"', html)
        self.assertNotIn('value="theirs-log"', html)
        self.assertIn('1 of these logs is assigned to other helpers', html)

    def test_helper_renames_unassigned_and_own_logs_only(self):
        self.client.force_login(self.helper)
        self.rename(['robert-log', 'mine-log', 'theirs-log', 'unrelated-log'])
        names = self.names()
        self.assertEqual(names['robert-log'], 'bob')
        self.assertEqual(names['mine-log'], 'bob')
        self.assertEqual(names['theirs-log'], 'rob')
        self.assertEqual(names['unrelated-log'], 'someone')
        self.assertEqual(UploadedLogStat.objects.get(source_id=self.unassigned.pk).forum_username, 'bob')
        self.fixlist.refresh_from_db()
        self.assertEqual(self.fixlist.username, 'robert')  # only the logs

    def test_staff_renames_logs_of_other_helpers(self):
        self.client.force_login(make_superuser())
        self.assertIn('rename 3 logs to u/bob', self.fragment())
        self.rename(['theirs-log'])
        self.assertEqual(self.names()['theirs-log'], 'bob')
        self.assertEqual(self.names()['robert-log'], 'robert')

    def test_no_button_without_other_names(self):
        UploadedLog.objects.exclude(upload_id='unrelated-log').update(forum_username='bob')
        self.client.force_login(self.helper)
        self.assertNotIn('rename_machine_logs', self.fragment())


class UploadsListUsernameLinkTests(TestCase):
    def test_a_forum_name_links_to_the_list_filtered_by_it(self):
        user = make_user()
        make_uploaded_log('bob-log', forum_username='bob & co')
        self.client.force_login(user)
        html = self.client.get(reverse('uploaded_logs'), {'channel': 'all'}).content.decode()
        self.assertIn('href="?u=bob%20%26%20co&amp;channel=all" class="username-filter-link"', html)
        filtered = self.client.get(reverse('uploaded_logs'), {'u': 'bob & co', 'channel': 'all'})
        self.assertContains(filtered, 'bob-log')
