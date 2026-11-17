"""Machine signals (fixlist/machine_signals.py): which machine a log comes
from, stored hashed per log, and the "possibly the same machine" list of the
related-logs tab."""

from django.test import TestCase
from django.urls import reverse

from ..case_correlations import same_machine_logs, same_system
from ..machine_signals import compare, extract_signals, log_signals
from ..models import InfectionCase, InfectionCaseLog, UploadedLogMachineSignal
from .factories import make_uploaded_log, make_user

SID = 'S-1-5-21-3694637330-154208023-497541903'
ADDITION = '\n'.join([
    'Additional scan result of Farbar Recovery Scan Tool (x64) Version: 10-11-2026 01',
    'Ran by Bob (13-11-2026 11:11:39)',
    'Running from C:\\Users\\Bob\\Downloads',
    '==================== Accounts: =============================',
    '',
    f'Administrator ({SID}-500 - Administrators - Disabled)',
    f'Bob ({SID}-1001 - Administrators - Enabled) => C:\\Users\\Bob',
    '',
    '==================== Memory info =========================== ',
    '',
    'BIOS: LENOVO H3CN39WW(V2.09) 05/31/2023',
    'Motherboard: LENOVO LNVNB161216',
    'Processor: AMD Ryzen 7 5800H with Radeon Graphics ',
    '',
    '==================== MBR & Partition Table ====================',
    'Disk: 0 (Protective MBR) (Size: 476.94 GB)',
    'Disk ID          : {65F12FD3-599E-4FB3-90C5-80B5C6BEE4B6}',
    'Disk: 1 (Size: 476.94 GB) (Disk ID: 3CB325E2)',
    'Disk: 2 (Size: 1 GB) (Disk ID: 00000000)',
])
FRST = '\n'.join([
    'Scan result of Farbar Recovery Scan Tool (FRST) (x64) Version: 10-11-2026 01',
    'Ran by Bob (administrator) on DESKTOP-BOB (LENOVO 82K2) (13-11-2026 11:04:20)',
    f'HKU\\{SID}-1001\\...\\Run: [x] => C:\\Users\\Bob\\x.exe',
])
FRST_GERMAN = 'durchgeführt von Bob (Administrator) auf DESKTOP-BOB (LENOVO 82K2) (13-11-2026 11:04:20)\n'
FRST_POLISH = 'Uruchomiony przez Bob (administrator)  DESKTOP-BOB (13-11-2026 11:04:20)\n'


class ExtractTests(TestCase):
    def test_addition_signals(self):
        signals = extract_signals(ADDITION)
        self.assertEqual(signals['sid'], {SID.lower()})
        self.assertEqual(signals['disk'], {'65f12fd3-599e-4fb3-90c5-80b5c6bee4b6', '3cb325e2'})
        self.assertEqual(signals['hw'], {'board:lenovo lnvnb161216|amd ryzen 7 5800h with radeon graphics'})
        self.assertEqual(signals['profile'], {'bob'})
        self.assertNotIn('computer', signals)

    def test_frst_header_in_any_language(self):
        signals = extract_signals(FRST)
        self.assertEqual(signals['computer'], {'desktop-bob'})
        self.assertEqual(signals['usersid'], {SID.lower()})
        self.assertEqual(signals['hw'], {'model:lenovo 82k2'})
        self.assertEqual(extract_signals(FRST_GERMAN)['computer'], {'desktop-bob'})
        self.assertEqual(extract_signals(FRST_GERMAN)['hw'], {'model:lenovo 82k2'})
        self.assertEqual(extract_signals(FRST_POLISH)['computer'], {'desktop-bob'})
        self.assertNotIn('hw', extract_signals(FRST_POLISH))
        # Addition / Fixlog headers have no computer name.
        self.assertNotIn('computer', extract_signals('Ran by Bob (13-11-2026 11:11:39) Run:1\n'))

    def test_values_are_stored_hashed(self):
        upload = make_uploaded_log('add-log', log_type='Addition', content=ADDITION)
        UploadedLogMachineSignal.rebuild_for(upload)
        values = list(UploadedLogMachineSignal.objects.filter(upload=upload).values_list('kind', 'value'))
        self.assertEqual({kind for kind, _value in values}, {'sid', 'disk', 'hw', 'profile'})
        self.assertTrue(all(len(value) == 40 and 'S-1-5' not in value for _kind, value in values))

    def test_stats_recalculation_rebuilds_the_rows(self):
        upload = make_uploaded_log('add-log', log_type='Addition', content=ADDITION)
        upload.recalculate_analysis_stats()
        self.assertTrue(UploadedLogMachineSignal.objects.filter(upload=upload, kind='sid').exists())


class CompareTests(TestCase):
    def test_precedence(self):
        same_sid_other_name = {'sid': {'a'}, 'computer': {'x'}}
        self.assertEqual(compare(same_sid_other_name, {'sid': {'a'}, 'computer': {'y'}}), 'same')
        self.assertEqual(compare({'sid': {'a'}}, {'sid': {'b'}, 'disk': {'d'}}), 'different')
        self.assertEqual(compare({'computer': {'x'}, 'profile': {'bob'}}, {'computer': {'y'}, 'profile': {'bob'}}),
                         'different')
        self.assertEqual(compare({'disk': {'d'}}, {'disk': {'d'}, 'hw': {'h'}}), 'same')
        self.assertEqual(compare({'hw': {'h'}}, {'hw': {'h'}}), 'likely')
        self.assertEqual(compare({'hw': {'h'}}, {'hw': {'g'}}), 'unknown')
        self.assertEqual(compare({}, {'sid': {'a'}}), 'unknown')

    def test_addition_and_frst_of_one_scan_are_the_same_system(self):
        # The Addition has no computer name; the FRST's HKU SIDs are no
        # account SIDs, so the shared profile name decides.
        self.assertEqual(compare(log_signals(ADDITION), log_signals(FRST)), 'same')
        self.assertEqual(same_system(log_signals(ADDITION), log_signals(FRST)), 'same')


class SameMachineLogsTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.case = InfectionCase.objects.create(owner=self.user, username='bob', auto_assign_new_items=False)
        self.addition = self.add('add-log', 'Addition', ADDITION, forum_username='bob')
        InfectionCaseLog.objects.create(case=self.case, uploaded_log=self.addition)

    def add(self, upload_id, log_type, content, forum_username='someone'):
        upload = make_uploaded_log(upload_id, log_type=log_type, content=content, forum_username=forum_username)
        UploadedLogMachineSignal.rebuild_for(upload)
        return upload

    def test_logs_sharing_the_sid_or_a_disk_under_another_name(self):
        renamed = self.add('renamed-log', 'Addition', ADDITION.replace('Bob', 'Robert'), forum_username='robert')
        disk_only = self.add('disk-log', 'Unknown', 'Disk: 1 (Size: 476.94 GB) (Disk ID: 3CB325E2)\n')
        other_sid = self.add('other-log', 'Addition', ADDITION.replace('497541903', '111111111'), forum_username='x')
        self.add('nothing-log', 'Addition', 'Additional scan result\n', forum_username='bob')
        found = dict(same_machine_logs(self.addition))
        self.assertEqual(set(found), {renamed.pk, disk_only.pk})
        self.assertEqual(found[renamed.pk], ['machine SID', 'disk ID'])
        self.assertEqual(found[disk_only.pk], ['disk ID'])
        self.assertNotIn(other_sid.pk, found)  # shares the disks but another Windows install
        self.assertEqual(dict(same_machine_logs(self.addition, exclude_pks=[renamed.pk])), {disk_only.pk: ['disk ID']})

    def test_computer_name_counts_only_with_the_same_hardware(self):
        frst = self.add('frst-log', 'FRST', FRST, forum_username='bob')
        same_pc = self.add('pc-log', 'FRST', FRST.replace('Bob', 'Eve'), forum_username='eve')
        other_hw = self.add('hw-log', 'FRST', FRST.replace('82K2', '99ZZ'), forum_username='eve')
        found = dict(same_machine_logs(frst))
        self.assertEqual(found.get(same_pc.pk), ['computer name and hardware'])
        self.assertNotIn(other_hw.pk, found)

    def test_related_logs_tab_lists_them_without_the_values(self):
        self.add('renamed-log', 'Addition', ADDITION.replace('Bob', 'Robert'), forum_username='robert')
        html = self.client.get(reverse('uploaded_log_related', args=['add-log'])).content.decode()
        self.assertIn('possibly the same machine', html)
        self.assertIn('renamed-log', html)
        self.assertIn('same machine SID, disk ID', html)
        self.assertNotIn(SID, html)
        self.assertNotIn('3CB325E2', html)
