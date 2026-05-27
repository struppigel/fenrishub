"""Tests for the redetect_log_types management command."""

from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from fixlist.models import UploadedLog


class RedetectLogTypesCommandTests(TestCase):
    def _make_log(self, content, upload_id):
        return UploadedLog.objects.create(
            upload_id=upload_id,
            forum_username='u',
            original_filename='log.txt',
            content=content,
            log_type='Unknown',
        )

    def test_reclassifies_localized_frst(self):
        log = self._make_log(
            'Untersuchungsergebnis von Farbar Recovery Scan Tool (FRST) (x64)\n',
            upload_id='loc-1',
        )
        out = StringIO()
        call_command('redetect_log_types', stdout=out)
        log.refresh_from_db()
        self.assertEqual(log.log_type, 'FRST')

    def test_only_unknown_skips_typed_logs(self):
        typed = UploadedLog.objects.create(
            upload_id='typed-1',
            forum_username='u',
            original_filename='x.txt',
            content='HitmanPro 3.8.50.346\nwww.hitmanpro.com',
            log_type='FRST',  # intentionally mismatched
        )
        unknown_log = self._make_log(
            'Emsisoft Emergency Kit - Version 2025.7\nLast update: N/A',
            upload_id='unk-1',
        )
        call_command('redetect_log_types', '--only-unknown', stdout=StringIO())
        typed.refresh_from_db()
        unknown_log.refresh_from_db()
        self.assertEqual(typed.log_type, 'FRST')  # unchanged (filtered out)
        self.assertEqual(unknown_log.log_type, 'Emsisoft')

    def test_dry_run_does_not_save(self):
        log = self._make_log(
            'Untersuchungsergebnis von Farbar Recovery Scan Tool (FRST) (x64)\n',
            upload_id='dry-1',
        )
        call_command('redetect_log_types', '--dry-run', stdout=StringIO())
        log.refresh_from_db()
        self.assertEqual(log.log_type, 'Unknown')
