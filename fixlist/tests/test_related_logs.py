"""The "related logs" tab of a log page: the page only counts them, the list
loads from views/uploads.py related_logs_fragment when the tab is opened."""

from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ..case_correlations import correlations_for_upload
from ..models import (
    CorrelationCache, HashVerdict, InfectionCase, InfectionCaseLog, UploadedLog, UploadedLogFileHash,
)
from .factories import make_uploaded_log, make_user
from .test_case_correlations import EVIL_SHA, FRST, MB_EVIL, MB_SAME, RUN_LINE, OTHER_LINE, cache_analysis

ESET_ON_PC = 'ESET Online Scanner\nComputer name: DESKTOP-BOB\n'
FRST_ON_PC = 'Ran by Bob (administrator) on DESKTOP-BOB (Dell) (01-11-2026 10:00:00)\n' + FRST


class RelatedLogsTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.case = InfectionCase.objects.create(owner=self.user, username='bob', auto_assign_new_items=False)
        self.frst = self.add('frst-log', 'FRST', FRST_ON_PC, minutes_ago=30)
        cache_analysis(self.frst, [RUN_LINE, OTHER_LINE])

    def add(self, upload_id, log_type, content, minutes_ago=0, link=True, **extra):
        upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username='nobody', **extra)
        UploadedLog.objects.filter(pk=upload.pk).update(created_at=timezone.now() - timedelta(minutes=minutes_ago))
        UploadedLogFileHash.rebuild_for(upload)
        if link:
            InfectionCaseLog.objects.create(case=self.case, uploaded_log=upload)
        return upload

    def page(self, upload_id='frst-log'):
        return self.client.get(reverse('view_uploaded_log', args=[upload_id]))

    def fragment(self, upload_id='frst-log'):
        return self.client.get(reverse('uploaded_log_related', args=[upload_id]))

    # --- the page ---

    def test_page_counts_the_related_logs_without_computing_correlations(self):
        self.add('mb-log', 'Malwarebytes', MB_SAME, minutes_ago=20)
        self.add('fix-log', 'Fixlog', 'Fix result of Farbar Recovery Scan Tool', minutes_ago=10)
        with mock.patch('fixlist.correlations.forward._compute', side_effect=AssertionError('computed during render')):
            html = self.page().content.decode()
        self.assertIn('related logs (2)', html)
        self.assertIn(reverse('uploaded_log_related', args=['frst-log']), html)

    def test_tab_is_offered_without_related_logs(self):
        # Its same-machine search covers the logs of other forum users.
        html = self.page().content.decode()
        self.assertIn('data-info-tab="related"', html)
        self.assertIn('>related logs</button>', html)
        self.assertIn(reverse('uploaded_log_related', args=['frst-log']), html)

    def test_a_log_without_summary_gets_tabs_for_its_related_logs(self):
        self.add('plain-log', 'Unknown', 'just some text')
        html = self.page('plain-log').content.decode()
        self.assertIn('data-info-tab="related"', html)
        self.assertIn('data-info-tab="metadata"', html)
        self.assertNotIn('data-info-tab="summary"', html)

    # --- the fragment ---

    def test_needs_a_login(self):
        self.client.logout()
        self.assertEqual(self.fragment().status_code, 302)

    def test_lists_newest_first_with_chips_tags_and_system(self):
        self.add('mb-log', 'Malwarebytes', MB_SAME, minutes_ago=20)
        self.add('eset-log', 'ESET', ESET_ON_PC, minutes_ago=5)
        self.add('fix-log', 'Fixlog', 'Fix result of Farbar Recovery Scan Tool', minutes_ago=10,
                 fixlog_total=3, fixlog_success=2)
        self.add('trashed-log', 'Fixlog', 'x', deleted_at=timezone.now())
        html = self.fragment().content.decode()
        self.assertIn('logs of your cases with this log', html)
        order = [html.index(f'>{upload_id}</a>') for upload_id in ('eset-log', 'fix-log', 'mb-log')]
        self.assertEqual(order, sorted(order))
        self.assertNotIn('trashed-log', html)
        self.assertIn('ok 2', html)                     # Fixlog chips
        self.assertIn('same system', html)              # DESKTOP-BOB in both
        self.assertIn(f'href="{reverse("view_uploaded_log", args=["mb-log"])}"', html)

    def test_other_system_badge(self):
        self.add('eset-other', 'ESET', 'ESET Online Scanner\nComputer name: OTHER-PC\n')
        self.assertIn('other system?', self.fragment().content.decode())

    def test_forum_user_scope_header(self):
        InfectionCaseLog.objects.all().delete()
        self.add('mb-user', 'Malwarebytes', MB_SAME, link=False)
        html = self.fragment().content.decode()
        self.assertIn('other logs of forum user nobody (no case of yours)', html)
        self.assertIn('mb-user', html)

    def test_correlated_lines_from_an_frst_page(self):
        now = timezone.now()
        HashVerdict.objects.create(sha256=EVIL_SHA, state='known', verdict='malicious', family='asyncrat',
                                   checked_at=now, next_check_at=now + timedelta(days=7))
        self.add('mb-log', 'Malwarebytes', MB_EVIL)
        self.assertIn('1 correlated line<', self.fragment().content.decode())

    def test_correlated_lines_from_another_log_page_use_stored_correlations_only(self):
        self.add('mb-log', 'Malwarebytes', MB_EVIL)
        # Nothing stored for the FRST log yet: no count, and nothing is computed.
        with mock.patch('fixlist.correlations.forward._compute', side_effect=AssertionError('computed')):
            self.assertNotIn('correlated line', self.fragment('mb-log').content.decode())
        correlations_for_upload(self.frst, self.user)
        self.assertTrue(CorrelationCache.objects.filter(upload=self.frst).exists())
        self.assertIn('1 correlated line<', self.fragment('mb-log').content.decode())

    def test_long_lists_are_capped(self):
        from ..views import uploads

        for index in range(4):
            self.add(f'extra-{index}', 'Fixlog', 'x', minutes_ago=index)
        with mock.patch.object(uploads, 'RELATED_LOGS_LIMIT', 3):
            html = self.fragment().content.decode()
        self.assertIn('and 1 more', html)
