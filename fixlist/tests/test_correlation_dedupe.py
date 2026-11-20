"""Each line of a related log once per FRST line (correlations/collector.py,
sources.merge_same_line), and what a related Spor log's own links add to an
FRST / FRST&Addition line (spor_source.SporFacts, forward._add_spor_links).
Nothing here may call centralbox."""

from collections import Counter
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from .. import centralbox
from ..case_correlations import reverse_correlations
from ..correlations.collector import LineEntries
from ..correlations.sources import merge_same_line
from ..models import InfectionCase, InfectionCaseLog, UploadedLogFileHash
from . import spor_sample as s
from .factories import make_uploaded_log, make_user
from .test_case_correlations import cache_analysis


def entry(line_no, kind='mention', upload_id='spor', **extra):
    return {'kind': kind, 'upload_id': upload_id, 'log_type': 'Spor', 'line_no': line_no, **extra}


class CollectorTests(SimpleTestCase):
    def test_a_source_line_is_kept_once_under_its_strongest_match(self):
        collector = LineEntries()
        self.assertTrue(collector.add(entry(5), 'name', other_path='c:\\x\\a.exe'))
        self.assertFalse(collector.add(entry(5), 'same_hash', other_path='c:\\y\\a.exe'))
        self.assertFalse(collector.add(entry(5), 'timing'))
        (kept,) = collector.entries
        self.assertEqual((kept['match'], kept['other_path']), ('same_hash', 'c:\\y\\a.exe'))
        # The same file beats everything; nothing is left of the weaker route.
        collector.add(entry(5), 'path')
        (kept,) = collector.entries
        self.assertNotIn('match', kept)
        self.assertNotIn('other_path', kept)

    def test_a_folder_is_weaker_than_the_file_and_kinds_break_ties(self):
        collector = LineEntries()
        collector.add(entry(7), 'path', in_folder=True)
        collector.add(entry(7, kind='evidence'), 'argument')
        (kept,) = collector.entries
        self.assertEqual((kept['kind'], kept['match']), ('evidence', 'argument'))
        collector.add(entry(8, kind='mention'), 'path')
        collector.add(entry(8, kind='detection'), 'path')
        self.assertEqual(collector.entries[1]['kind'], 'detection')

    def test_a_hash_row_counts_as_the_line_of_its_file(self):
        collector = LineEntries()
        collector.add(entry(4, kind='hash', anchor_line_no=3), 'path')
        collector.add(entry(3, kind='file_info'), 'path')
        self.assertEqual(len(collector), 1)

    def test_the_line_itself_and_entries_of_no_line_are_skipped(self):
        collector = LineEntries(own=('spor', 9))
        self.assertFalse(collector.add(entry(9)))
        self.assertFalse(collector.add(entry(0)))
        self.assertEqual(collector.entries, [])

    def test_entries_are_copies_with_the_system_of_their_log(self):
        shared = entry(2)
        collector = LineEntries(verdicts={'spor': 'same'})
        collector.add(shared, 'path')
        self.assertEqual(collector.entries[0]['system'], 'same')
        self.assertNotIn('system', shared)


class MergeSameLineTests(SimpleTestCase):
    def test_a_hash_row_and_the_facts_of_its_line_are_one_entry(self):
        info = entry(12, kind='file_info', signature='unsigned', severity='')
        row = entry(12, kind='hash', sha256='ab' * 32, md5='', detection='Trojan:Win32/X', severity='b',
                    centralbox={'verdict': 'malicious', 'report_url': 'https://centralbox.dev/analysis/x'})
        other = entry(13, kind='evidence')
        index = {'c:\\x\\a.exe': [row, other, info], 'name:a.exe': [info]}
        merge_same_line(index)
        merged, rest = index['c:\\x\\a.exe']
        self.assertIs(rest, other)
        self.assertEqual((merged['kind'], merged['sha256'], merged['detection'], merged['severity'],
                          merged['signature'], merged['centralbox']['verdict']),
                         ('file_info', 'ab' * 32, 'Trojan:Win32/X', 'b', 'unsigned', 'malicious'))
        # Under every key the same merged entry.
        self.assertIs(index['name:a.exe'][0], merged)

    def test_rows_of_other_lines_stay(self):
        info = entry(12, kind='file_info')
        row = entry(20, kind='hash', sha256='cd' * 32)
        index = {'k': [row, info]}
        merge_same_line(index)
        self.assertEqual(index['k'], [row, info])


QWX_LINE = (f'HKU\\S-1-5-21-1-2-3-1001\\...\\Run: [Host] => {s.SIDE_HOST} [12345 2026-11-20] (Some Developer) '
            '[File not signed]')
CREATED_LINE = f'2026-11-20 04:33 - 2026-11-20 04:33 - 000012345 _____ (Some Developer) {s.SIDE_HOST}'


class SporLinksViaFrstTests(TestCase):
    """An FRST&Addition line of qwXyZaB.exe in a case with a Spor 0.3.0 log."""

    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        case = InfectionCase.objects.create(owner=self.user, username='bob', auto_assign_new_items=False)
        content = '\n'.join(['Scan result of Farbar Recovery Scan Tool (FRST)', QWX_LINE, CREATED_LINE,
                             'Additional scan result of Farbar Recovery Scan Tool'])
        self.frst = make_uploaded_log('frst-qwx', log_type='FRST&Addition', content=content, forum_username='nobody')
        cache_analysis(self.frst, [QWX_LINE, CREATED_LINE])
        self.spor = make_uploaded_log('spor-qwx', log_type='Spor', content=s.SPOR_V4, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.spor)
        for upload in (self.frst, self.spor):
            InfectionCaseLog.objects.create(case=case, uploaded_log=upload)

    def get(self):
        with mock.patch.object(centralbox, '_http_get') as http, mock.patch.object(centralbox, '_request') as request:
            body = self.client.get(reverse('case_correlations_api'), {'upload_id': 'frst-qwx'}).json()
        http.assert_not_called()
        request.assert_not_called()
        return body

    def spor_lines(self, body, text):
        return {entry['line_no']: entry for entry in body['correlations'][text] if entry['upload_id'] == 'spor-qwx'}

    def test_every_spor_line_of_the_file_reaches_the_frst_line(self):
        found = self.spor_lines(self.get(), QWX_LINE)
        no = lambda prefix: s.LINES_V4.index(next(t for t in s.LINES_V4 if t.strip().startswith(prefix))) + 1
        # The first TIMELINE line, the later 4688 start, the SUMMARY line, the
        # FILES line (with its hash), the Run key and the running process.
        for prefix in ('2026-11-20 03:33:50 [NEW] ' + s.SIDE_HOST, '2026-11-20 03:33:53 [4688]',
                       '2026-11-20 03:33:50 [timeline NEW] ' + s.SIDE_HOST, s.SIDE_HOST + ' => ',
                       '2026-11-20 03:35:00 [run]', '2026-11-20 03:33:53 [4321]'):
            self.assertIn(no(prefix), found, prefix)
            self.assertNotIn(found[no(prefix)].get('match'), ('detail', 'named_by'), prefix)
        files = found[no(s.SIDE_HOST + ' => ')]
        self.assertEqual((files['kind'], files['sha256']), ('file_info', s.SIDE_HOST_SHA))
        # The cmd.exe line that started it (named_by) and providers.dll, which it side-loads (detail).
        self.assertEqual(found[no('2026-11-20 03:33:52 [SYSMON]')]['match'], 'named_by')
        self.assertEqual(found[no(s.SIDE_DLL + ' => ')]['match'], 'detail')

    def test_no_line_twice_and_details_never_rate(self):
        body = self.get()
        for text, entries in body['correlations'].items():
            counts = Counter((entry['upload_id'], entry.get('anchor_line_no') or entry['line_no']) for entry in entries)
            self.assertEqual([slot for slot, n in counts.items() if n > 1], [], text)
        # qwXyZaB.exe's own lines carry strong flags (!motw-removed, !proxy-exec): '!'.
        self.assertEqual(body['statuses'][QWX_LINE], '!')

    def test_a_plain_frst_log_gets_them_too(self):
        self.frst.log_type = 'FRST'
        self.frst.save(update_fields=['log_type'])
        found = self.spor_lines(self.get(), QWX_LINE)
        self.assertIn('named_by', {entry.get('match') for entry in found.values()})

    def test_the_spor_summary_line_lists_the_frst_line(self):
        self.get()
        result = reverse_correlations(self.spor, self.user)
        summary = str(s.LINES_V4.index(next(t for t in s.LINES_V4 if t.startswith('2026-11-20 03:33:50 [timeline NEW] '
                                                                                  + s.SIDE_HOST))) + 1)
        self.assertIn(QWX_LINE, [entry['text'] for entry in result['lines'][summary]])
