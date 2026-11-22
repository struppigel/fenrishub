"""File path rules on Spor lines: each Spor line has its one path (item,
target, or a sub-line's path), in Spor logs only, and the path is coloured."""

from .. import frst_extractors as ex
from ..analyzer import analyze_log_text
from ..models import ClassificationRule
from .log_analyzer_api_shared import LogAnalyzerApiBaseTestCase

B = ClassificationRule.STATUS_MALWARE
TELEGRAM = 'C:\\Users\\Bob\\AppData\\Roaming\\TELEGRAM DESKTOP\\TELEGRAM.EXE'
LOADED = f'    loaded: {TELEGRAM} [gone]'
SPOR = '\n'.join([
    '==================== Spor 0.7.1 - forensic triage log ====================',
    '==================== PREFETCH - programs run and the files they loaded ====================',
    '2026-10-26 17:26:03 C:\\Windows\\SystemApps\\Host\\StartMenuExperienceHost.exe',
    '    loaded: C:\\Users\\Bob\\AppData\\Local\\Wand\\Wand.exe',
    LOADED,
    '==================== RUNNING PROCESSES - programs running now ====================',
    f'2026-11-21 08:36:59 [21536] {TELEGRAM} => parent Explorer.EXE (15464)',
    '==================== SOFTWARE - programs installed ====================',
    f'2026-11-09 11:25:19 [user Bob] Telegram => {TELEGRAM}, publisher Telegram FZ-LLC',
])


class SporLinePathTests(LogAnalyzerApiBaseTestCase):
    def setUp(self):
        super().setUp()
        # Another user's folder: paths compare with the user normalized.
        path = TELEGRAM.replace('\\Bob\\', '\\anna\\')
        ClassificationRule.objects.create(
            owner=self.user, status=B, match_type=ClassificationRule.MATCH_FILEPATH, source_text=path,
            filepath=path, normalized_filepath=ex.path_key(path), all_log_types=True,
        )

    def test_item_target_and_sub_line_paths_match(self):
        lines = analyze_log_text(SPOR, log_type='Spor')['lines']
        self.assertEqual([line['dominant_status'] for line in lines],
                         ['?', '?', '?', '?', B, '?', B, '?', B])

    def test_only_in_spor_logs(self):
        lines = analyze_log_text(SPOR, log_type='FRST')['lines']
        self.assertEqual(lines[4]['dominant_status'], '?')

    def test_the_path_is_coloured_and_copyable(self):
        lines = analyze_log_text(SPOR, log_type='Spor')['lines']
        loaded = lines[4]
        start = loaded['line'].index('C:\\')
        self.assertEqual([(span['start'], span['end'], span['status']) for span in loaded['highlights']],
                         [(start, start + len(TELEGRAM), B)])
        self.assertEqual(loaded['components']['filepath'], TELEGRAM)


class SporFileLineRuleTests(LogAnalyzerApiBaseTestCase):
    """A Spor file line ("path => sha256, signature ...; size ...") becomes a
    file path rule for its path alone, never for the whole line."""

    DRIVER = 'C:\\Windows\\System32\\drivers\\spaceport.sys'
    LINE = (f'{DRIVER} => 96E46C3571CBE72B33E21258EB4F29D3DCFEEFF503D273AEF1F3327E9C3FD008, '
            'signature valid; signer Microsoft Windows; description Storage Spaces Driver; '
            'md5 B44700BAF28AAB7344B607BC5296790F; size 1035608; created 2026-11-11 04:07:11')

    def test_spor_rule_takes_the_path(self):
        from ..analyzer import parse_rule_for_line
        rule = parse_rule_for_line(self.LINE, B, log_type='Spor')
        self.assertEqual(rule['match_type'], ClassificationRule.MATCH_FILEPATH)
        self.assertEqual(rule['filepath'], self.DRIVER)
        self.assertEqual(rule['normalized_filepath'], ex.path_key(self.DRIVER))

    def test_elsewhere_no_whole_line_path(self):
        from ..analyzer import parse_rule_for_line
        for log_type in (None, 'FRST'):
            rule = parse_rule_for_line(self.LINE, B, log_type=log_type)
            self.assertEqual(rule['match_type'], ClassificationRule.MATCH_EXACT)
            self.assertEqual(rule['filepath'], '')
