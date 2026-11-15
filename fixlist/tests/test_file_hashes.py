"""SHA256 extraction for the centralbox markers (fixlist/file_hashes.py)."""

from django.test import TestCase

from ..file_hashes import MAX_AUTO_PER_LOG, extract_file_hashes, is_sha256
from ..models import UploadedLogFileHash
from .factories import make_uploaded_log
from .test_log_highlighting import HITMANPRO, MALWAREBYTES

H1 = 'a1' * 32
H2 = 'b2' * 32
H3 = 'c3' * 32
H4 = 'd4' * 32

FIXLOG_FILE_BLOCK = '\n'.join([
    'Fix result of Farbar Recovery Scan Tool (x64) Version: 01-11-2026',
    '========================= File: C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe;C:\\Temp\\b.dll ========================',
    '',
    'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe',
    'File not signed',
    'MD5: 86D48A8D73CD817A3BD55C699311294A',
    '',
    'SHA1: D8026F6A33B62702C2BDBA8C534E25E4DA48BA63',
    'SHA1 Base64: 2AJvajO2JwLCvbqMU04l5NpIumM=',
    '',
    f'SHA256: {H1.upper()}',
    'SHA256 Base64: wqf/gThifUf8emXcZDViBqbBCsSOhsKfUmocGXJl+MI=',
    '',
    'Size: 000012345',
    '',
    'C:\\Temp\\b.dll [symlink -> C:\\Other\\b.dll]',
    'File not signed',
    f'SHA256: {H2}',
    '',
    '====== End of File: ======',
    '',
    '========================= Folder: C:\\Program Files (x86)\\Vendor ========================',
    f'  [{H3}] 03/08/2026 04:56:42 - 03/08/2026 04:56:42 -  1.54 MB - Signer: Vendor Inc. - C:\\Program Files (x86)\\Vendor\\app.exe',
    '====== End of Folder: ======',
    '========= Powershell: =========',
    'FullPath   : C:\\Users\\Bob\\x.ps1',
    f'SHA256     : {H4}',
    '========= End of Powershell: =========',
])

MAU_FILES = '\n'.join([
    '                                            FILES',
    '----------------------------------------------------------------------------------------------',
    '',
    '  c:\\users\\bob\\appdata\\local\\via\\via chrome runtime\\.gitattributes',
    f'  SHA256: {H1}',
    '  [File] c:\\users\\bob\\appdata\\local\\via\\x.cfg',
    f'  SHA256: {H2}',
    'Cached MSI:',
    '  Path: C:\\WINDOWS\\Installer\\cc4676.msi',
    f'  SHA256: {H3}',
    f'  VirusTotal Report: https://www.virustotal.com/gui/file/{H3}',
])


def by_sha(rows):
    return {row.sha256: row for row in rows}


class ExtractFileHashesTests(TestCase):
    def test_malwarebytes_detection_line_carries_path_name_and_hash(self):
        rows = [r for r in extract_file_hashes('Malwarebytes', MALWAREBYTES) if r.auto]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.sha256, '033bb9eef12e0e23adb36c9788edaa342704362512a8113d6aaeec3e01bf83ad')
        self.assertEqual(row.source, 'malwarebytes')
        self.assertEqual(row.detection, 'PUP.Optional.TLauncher')
        self.assertEqual(row.anchor_line_no, row.line_no)
        self.assertEqual(row.normalized_path, 'c:\\users\\username\\appdata\\roaming\\.tlauncher\\tlauncher.exe')
        line = MALWAREBYTES.split('\n')[row.line_no - 1]
        self.assertIn(row.sha256.upper(), line)

    def test_hitmanpro_hash_belongs_to_the_path_line_above(self):
        rows = [r for r in extract_file_hashes('HitmanPro', HITMANPRO) if r.auto]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        lines = HITMANPRO.split('\n')
        self.assertIn('Love Town.exe', lines[row.anchor_line_no - 1])
        self.assertIn('SHA-256', lines[row.line_no - 1])
        self.assertEqual(row.detection, 'Mal/Generic-S')
        self.assertEqual(row.path, 'C:\\Users\\User\\Desktop\\Love Town.exe')

    def test_fixlog_only_file_blocks_are_automatic(self):
        rows = by_sha(extract_file_hashes('Fixlog', FIXLOG_FILE_BLOCK))
        self.assertTrue(rows[H1].auto)
        self.assertEqual(rows[H1].source, 'fixlog_file')
        self.assertEqual(rows[H1].path, 'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe')
        self.assertTrue(rows[H2].auto)
        self.assertEqual(rows[H2].path, 'C:\\Temp\\b.dll')
        # Folder listings and PowerShell output: manual check only, path kept.
        self.assertFalse(rows[H3].auto)
        self.assertEqual(rows[H3].source, 'fixlog_folder')
        self.assertEqual(rows[H3].path, 'C:\\Program Files (x86)\\Vendor\\app.exe')
        self.assertFalse(rows[H4].auto)
        self.assertEqual(rows[H4].path, 'C:\\Users\\Bob\\x.ps1')

    def test_mau_hashes_take_the_path_from_the_line_above(self):
        rows = [r for r in extract_file_hashes('MAU', MAU_FILES) if r.auto]
        found = by_sha(rows)
        self.assertEqual(found[H1].path, 'c:\\users\\bob\\appdata\\local\\via\\via chrome runtime\\.gitattributes')
        self.assertEqual(found[H2].path, 'c:\\users\\bob\\appdata\\local\\via\\x.cfg')
        self.assertEqual(found[H3].path, 'C:\\WINDOWS\\Installer\\cc4676.msi')
        # The VirusTotal link repeats H3 inside a URL: no second automatic row.
        self.assertEqual(sum(1 for r in rows if r.sha256 == H3), 1)

    def test_frst_and_other_types_yield_nothing(self):
        frst = f'2026-01-01 10:00 - 2026-01-01 10:00 - 000000000 ____D C:\\Users\\Bob\\AppData\\LocalLow\\{H1}\n'
        addition = f'BucketId: {H2}\n'
        for log_type, content in (('FRST', frst), ('Addition', addition), ('FRST&Addition', frst + addition),
                                  ('SecurityCheck', f'https://x/{H1}'), ('ESET', H1), ('Unknown', H1)):
            self.assertEqual(extract_file_hashes(log_type, content), [], log_type)

    def test_only_sha256_is_extracted(self):
        content = 'MD5: 86D48A8D73CD817A3BD55C699311294A\nSHA1: D8026F6A33B62702C2BDBA8C534E25E4DA48BA63\n'
        self.assertEqual(extract_file_hashes('Fixlog', content), [])

    def test_line_numbers_match_the_highlighter_with_crlf(self):
        content = MAU_FILES.replace('\n', '\r\n')
        rows = by_sha(extract_file_hashes('MAU', content))
        self.assertIn(H1, content.split('\n')[rows[H1].line_no - 1])

    def test_automatic_rows_are_capped(self):
        content = '\n'.join(f'C:\\f{i}.exe\nSHA256: {i:064x}' for i in range(MAX_AUTO_PER_LOG + 5))
        rows = extract_file_hashes('MAU', content)
        self.assertEqual(sum(r.auto for r in rows), MAX_AUTO_PER_LOG)

    def test_is_sha256(self):
        self.assertTrue(is_sha256(H1.upper()))
        self.assertFalse(is_sha256(H1[:-1]))
        self.assertFalse(is_sha256('z' * 64))


class UploadedLogFileHashTests(TestCase):
    def test_stats_recalculation_stores_the_rows(self):
        upload = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MALWAREBYTES)
        upload.recalculate_analysis_stats()
        rows = list(UploadedLogFileHash.objects.filter(upload=upload, auto=True))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].detection, 'PUP.Optional.TLauncher')

    def test_rebuild_replaces_old_rows_and_never_raises(self):
        upload = make_uploaded_log('mau-log', log_type='MAU', content=MAU_FILES)
        UploadedLogFileHash.rebuild_for(upload)
        UploadedLogFileHash.rebuild_for(upload)
        self.assertEqual(UploadedLogFileHash.objects.filter(upload=upload, sha256=H1).count(), 1)
        upload.content = 'nothing here'
        UploadedLogFileHash.rebuild_for(upload)
        self.assertFalse(UploadedLogFileHash.objects.filter(upload=upload).exists())
