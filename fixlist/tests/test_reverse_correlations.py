"""The other way round (case_correlations.reverse_correlations): the lines of
related FRST / Addition logs that point at a line of any other log, on that
log's page and through the endpoint (the analyzer). Nothing here may call
centralbox."""

from unittest import mock

from django.test import TestCase
from django.urls import reverse

from .. import centralbox
from ..case_correlations import correlations_for_upload, reverse_correlations, reverse_status
from ..models import InfectionCase, InfectionCaseLog, UploadedLog, UploadedLogFileHash
from .factories import make_uploaded_log, make_user
from .test_installed_app_correlations import (
    FIXLOG_APPS, FRST, FRST_LINES, HELPER_RUN, INSTALLED, MAU, SERVICE, cache_analysis,
)


def line_no(content, prefix):
    return next(no for no, text in enumerate(content.split('\n'), start=1) if text.strip().startswith(prefix))


class ReverseCorrelationTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.case = InfectionCase.objects.create(owner=self.user, username='bob', auto_assign_new_items=False)
        self.frst = make_uploaded_log('frst-log', log_type='FRST&Addition', content=FRST, forum_username='nobody')
        cache_analysis(self.frst, FRST_LINES, statuses={SERVICE: 'B', INSTALLED: 'C'})
        self.link(self.frst)
        self.fix = self.add_log('fix-apps', 'Fixlog', FIXLOG_APPS)
        self.mau = self.add_log('mau-log', 'MAU', MAU)

    def link(self, upload):
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=upload, added_by=self.user)

    def add_log(self, upload_id, log_type, content):
        upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(upload)
        self.link(upload)
        return upload

    def frst_no(self, text):
        return FRST.split('\n').index(text) + 1

    def test_lines_of_the_other_log_get_the_frst_lines_pointing_at_them(self):
        result = reverse_correlations(self.fix, self.user, compute=True)
        self.assertEqual(result['scope'], 'case')
        header = str(line_no(FIXLOG_APPS, '<=== Tool Kit'))
        self.assertEqual(result['texts'][header], '<=== Tool Kit [2.4] (Acme Inc.) ===>')
        entries = result['lines'][header]
        # The Installed Programs line (by name) before the files inside the folder.
        first = entries[0]
        self.assertEqual((first['kind'], first['upload_id'], first['line_no'], first['text'], first['match'],
                          first['what'], first['line_status']),
                         ('reverse', 'frst-log', self.frst_no(INSTALLED), INSTALLED, 'app', 'installed app', 'C'))
        folder = next(entry for entry in entries if entry.get('in_folder'))
        self.assertEqual((folder['text'], folder['line_status']), (SERVICE, 'B'))
        # The hash row of the file in the listing is pointed at by the service line.
        svc_row = str(line_no(FIXLOG_APPS, f'[{"A1" * 32}]'))
        self.assertEqual([(entry['text'], entry['what']) for entry in result['lines'][svc_row]],
                         [(SERVICE, 'file hash')])
        self.assertEqual(reverse_status(result['lines'][svc_row]), 'B')

    def test_mau_lines(self):
        result = reverse_correlations(self.mau, self.user, compute=True)
        run_value = str(line_no(MAU, '[RegValue] HKU'))
        self.assertEqual([(entry['text'], entry['match']) for entry in result['lines'][run_value]],
                         [(HELPER_RUN, 'registry')])

    def test_page_shows_stored_answers_only(self):
        # Nothing stored yet: the page asks for current ones afterwards.
        response = self.client.get(reverse('view_uploaded_log', args=['fix-apps']))
        data = response.context['correlations']
        self.assertEqual((data['fresh'], data['reverse'], data['lines']), (False, True, {}))
        self.assertIn('id="correlationData"', response.content.decode())
        correlations_for_upload(self.frst, self.user)
        response = self.client.get(reverse('view_uploaded_log', args=['fix-apps']))
        data = response.context['correlations']
        self.assertTrue(data['fresh'])
        header = str(line_no(FIXLOG_APPS, '<=== Tool Kit'))
        self.assertEqual(data['lines'][header]['entries'][0]['text'], INSTALLED)
        svc_row = str(line_no(FIXLOG_APPS, f'[{"A1" * 32}]'))
        self.assertEqual(data['lines'][svc_row]['status'], 'B')
        # Nothing is added to the summary box.
        self.assertFalse([item for item in response.context['highlight'].summary
                          if getattr(item, 'correlation', '')])

    def test_endpoint_keys_by_line_text(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'mau-log'}).json()
        http.assert_not_called()
        request.assert_not_called()
        self.assertTrue(body['reverse'])
        line = [text for text in MAU.split('\n') if text.strip().startswith('[RegKey] HKLM\\SYSTEM')][0].strip()
        self.assertEqual([entry['text'] for entry in body['correlations'][line]], [SERVICE])
        self.assertEqual(body['statuses'][line], 'B')
        self.assertIn(f'L{self.frst_no(SERVICE)}', body['notes'][line])

    def test_logs_outside_the_viewers_cases_give_nothing(self):
        other = make_user(username='other-helper')
        UploadedLog.objects.update(forum_username='')
        self.assertEqual(reverse_correlations(self.fix, other, compute=True)['lines'], {})

    def test_frst_logs_themselves_have_no_reverse_view(self):
        self.assertEqual(reverse_correlations(self.frst, self.user, compute=True)['lines'], {})
