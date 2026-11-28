"""The log page marks a Spor line linked to its own file's FILES hash even when
nothing about it is notable (spor_self.SelfLinks.hash_lines, views/centralbox.py
add_self_link_context `self_hash_lines`): a "loaded:" script with a hash shows
its icon without hovering. The codes (and so the API) stay as they were."""

from django.test import SimpleTestCase, TestCase

from ..correlations.spor_self import compute
from ..log_types import LOG_TYPE_SPOR
from ..views.centralbox import add_self_link_context
from .factories import make_uploaded_log

CMD = 'C:\\Windows\\System32\\cmd.exe'
PLD = 'C:\\ProgramData\\MyCompany\\MyApp\\cache\\pld.cmd'
QUIET = 'C:\\Program Files\\Quiet\\quiet.exe'
PLD_SHA = '2F7922CC591D7A3196AC9E06B0D0065C5101179E6ECF827ECEE7982449CCA4FB'

SPOR = '\n'.join([
    '==================== Spor 0.12.0 - forensic triage log =============================================',
    'Created:   2026-11-28 05:05:01 UTC (local time 13:05, UTC+08:00)',
    'Times:     UTC, except created and modified in FILES (local time of this PC, as FRST shows them)',
    '',
    '==================== PREFETCH - programs run and the files they loaded =============================',
    '',
    '--- Files loaded by programs run in the last 30 days ---',
    '(loaded: file [status] <==== flags)',
    '',
    f'2026-11-27 23:48:09 {CMD} <==== !lolbin',
    f'    loaded: {PLD}',
    f'2026-11-27 23:50:00 {QUIET}',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '(line: file => sha256, signature)',
    '',
    f'{CMD} => {"C" * 64}, signature valid; signer Microsoft Windows',
    f'{PLD} => {PLD_SHA}',
    '    file: md5 FEDB3594BA699EA075C389D13CE91E45; size 395673; created 2026-11-25 08:33:30; modified 2026-11-25 08:33:31',
    '',
    '==================== End of log. Scan took 12.0 s ====',
])
LINES = SPOR.split('\n')


def no_of(prefix):
    return str(next(no for no, text in enumerate(LINES, start=1) if text.strip().startswith(prefix)))


LOADED = no_of(f'loaded: {PLD}')
PROGRAM = no_of(f'2026-11-27 23:48:09 {CMD}')
FILES_PLD = no_of(f'{PLD} =>')


class HashLinesTests(SimpleTestCase):
    def setUp(self):
        self.links = compute('spor-hash', SPOR)

    def test_a_loaded_line_linked_to_its_files_hash_is_a_hash_line(self):
        # Nothing notable about it: hover icon only by its code...
        self.assertEqual(self.links.codes[LOADED], '')
        self.assertIn(FILES_PLD, {str(entry['line_no']) for entry in self.links.entries(LOADED)})
        # ...but it links its own file's hash.
        self.assertIn(LOADED, self.links.hash_lines())

    def test_a_program_linked_only_through_what_it_loaded_is_not(self):
        # cmd.exe's line reaches pld.cmd's FILES line as 'loads' (informational).
        matches = {str(entry['line_no']): entry.get('match') for entry in self.links.entries(PROGRAM)}
        self.assertEqual(matches.get(FILES_PLD), 'loads')
        self.assertNotIn(PROGRAM, self.links.hash_lines())


class PageContextTests(TestCase):
    def test_hash_lines_go_into_the_page_context_with_the_codes_unchanged(self):
        upload = make_uploaded_log('spor-hash', log_type=LOG_TYPE_SPOR, content=SPOR)
        links = compute('spor-hash', SPOR)
        context = add_self_link_context(upload, {})
        self.assertEqual(context['self_lines'], links.codes)
        self.assertIn(LOADED, context['self_hash_lines'])
        # Lines with a marker of their own already are not listed again.
        self.assertFalse(any(context['self_lines'][no] for no in context['self_hash_lines']))
        self.assertEqual(context['self_hash_lines'], sorted(context['self_hash_lines'], key=int))
