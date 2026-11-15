"""Several forum usernames per infection case, adding the user's existing
items right after a case is created, and the "open" button for reference
URLs in the cases list."""

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from ..models import Fixlist, InfectionCase, InfectionCaseFixlist, InfectionCaseLog, UploadedLog


def make_log(upload_id, username, **extra):
    return UploadedLog.objects.create(
        upload_id=upload_id, forum_username=username, original_filename='log.txt', content='x', **extra,
    )


class CaseUsernamesTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.client.login(username='alice', password='password123')

    def create(self, **fields):
        data = {'username': 'main_name', 'auto_assign_new_items': '1', **fields}
        self.client.post(reverse('create_infection_case'), data)
        return InfectionCase.objects.get(owner=self.user)

    def test_other_usernames_are_saved_cleaned(self):
        case = self.create(other_usernames=' second , main_name, second,third ,, ')
        self.assertEqual(case.extra_username_list(), ['second', 'third'])
        self.assertEqual(case.all_usernames(), ['main_name', 'second', 'third'])

    def test_case_page_edits_the_other_usernames(self):
        case = self.create(other_usernames='second')
        self.client.post(reverse('view_infection_case', args=[case.case_id]), {
            'action': 'update_case', 'status': 'open', 'auto_assign_new_items': '1',
            'other_usernames': 'third, fourth',
        })
        self.assertEqual(case.extra_username_list(), ['third', 'fourth'])
        page = self.client.get(reverse('view_infection_case', args=[case.case_id])).content.decode()
        self.assertIn('main_name, third, fourth', page)

    def test_new_log_of_another_username_joins_the_case(self):
        case = self.create(other_usernames='second')
        log = make_log('new-second', 'second')
        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=log).exists())
        other = make_log('new-stranger', 'stranger')
        self.assertFalse(InfectionCaseLog.objects.filter(case=case, uploaded_log=other).exists())
        # Exact match, like the main username.
        upper = make_log('new-upper', 'SECOND')
        self.assertFalse(InfectionCaseLog.objects.filter(case=case, uploaded_log=upper).exists())

    def test_new_fixlist_of_another_username_joins_the_case(self):
        case = self.create(other_usernames='second')
        fixlist = Fixlist.objects.create(owner=self.user, username='second', content='x')
        self.assertTrue(InfectionCaseFixlist.objects.filter(case=case, fixlist=fixlist).exists())

    def test_seed_covers_all_usernames(self):
        case = self.create(other_usernames='second')
        InfectionCaseLog.objects.filter(case=case).delete()
        a = make_log('seed-main', 'main_name', recipient_user=self.user)
        b = make_log('seed-second', 'second', recipient_user=self.user)
        InfectionCaseLog.objects.filter(case=case).delete()
        self.client.post(reverse('view_infection_case', args=[case.case_id]), {'action': 'seed_username_items'})
        linked = set(InfectionCaseLog.objects.filter(case=case).values_list('uploaded_log_id', flat=True))
        self.assertEqual(linked, {a.pk, b.pk})

    def test_no_username_confirmation_for_another_username(self):
        case = self.create(other_usernames='second')
        log = make_log('manual-second', 'second', recipient_user=self.user)
        InfectionCaseLog.objects.filter(case=case).delete()
        response = self.client.post(reverse('infection_case_add_items', args=[case.case_id]),
                                    {'selected_upload_ids': ['manual-second']})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(InfectionCaseLog.objects.filter(case=case, uploaded_log=log).exists())
        log.refresh_from_db()
        self.assertEqual(log.forum_username, 'second')


class AddExistingItemsOnCreateTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.other = User.objects.create_user(username='bob', password='password123')
        self.client.login(username='alice', password='password123')

    def test_existing_logs_and_fixlists_join_a_new_case(self):
        mine = make_log('old-mine', 'victim', recipient_user=self.user)
        unassigned = make_log('old-free', 'victim')
        second = make_log('old-second', 'victim2')
        foreign = make_log('old-foreign', 'victim', recipient_user=self.other)
        fixlist = Fixlist.objects.create(owner=self.user, username='victim', content='x')
        response = self.client.post(reverse('create_infection_case'), {
            'username': 'victim', 'other_usernames': 'victim2', 'auto_assign_new_items': '1',
        })
        case = InfectionCase.objects.get(owner=self.user)
        linked = set(InfectionCaseLog.objects.filter(case=case).values_list('uploaded_log_id', flat=True))
        self.assertEqual(linked, {mine.pk, unassigned.pk, second.pk})
        self.assertNotIn(foreign.pk, linked)
        self.assertTrue(InfectionCaseFixlist.objects.filter(case=case, fixlist=fixlist).exists())
        messages = [str(m) for m in response.wsgi_request._messages]
        self.assertTrue(any('Added 3 log(s) and 1 fixlist(s)' in m for m in messages))

    def test_training_cases_start_empty(self):
        make_log('old-train', 'victim', recipient_user=self.user)
        self.client.post(reverse('create_infection_case'), {'username': 'victim', 'is_training': '1'})
        case = InfectionCase.objects.get(owner=self.user)
        self.assertFalse(InfectionCaseLog.objects.filter(case=case).exists())


class CasesListOpenButtonTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='password123')
        self.client.login(username='alice', password='password123')

    def test_open_button_only_for_web_links(self):
        InfectionCase.objects.create(owner=self.user, username='web', reference_url='https://forum.example/t/1')
        InfectionCase.objects.create(owner=self.user, username='ftp', reference_url='ftp://files.example/x')
        InfectionCase.objects.create(owner=self.user, username='none')
        page = self.client.get(reverse('infection_cases')).content.decode()
        self.assertIn('href="https://forum.example/t/1" target="_blank" rel="noopener noreferrer"', page)
        self.assertNotIn('href="ftp://files.example/x"', page)
        self.assertEqual(page.count('>open</button>'), 1)

    def test_extra_usernames_show_as_a_count(self):
        case = InfectionCase.objects.create(owner=self.user, username='main')
        case.set_extra_usernames(['b', 'c'])
        page = self.client.get(reverse('infection_cases')).content.decode()
        self.assertIn('title="b, c">(+2)</span>', page)
