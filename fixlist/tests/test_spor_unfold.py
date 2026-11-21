"""Spor 0.7.0+ writes long details on sub-lines of their own (program: /
arguments: under Run and task lines, file: / process: under Defender lines,
from: / page: under downloads, folder: / key: / signer: under SOFTWARE
entries). spor_log.unfold folds them back, so a log of either layout reads
the same: the same entries, targets, statuses, detections and facts."""

from django.test import SimpleTestCase

from .. import spor_log
from ..file_hashes import _spor_flagged_paths, normalized_path


def _log(version, body):
    head = f'==================== Spor {version} - forensic triage log ====================\n'
    return (head + body.strip('\n') + '\n==================== LEGEND ====================\n').split('\n')


# Spor 0.6: everything on the line.
OLD = _log('0.6.1', r'''
==================== SUMMARY - flagged items; details in the sections below ====================
2026-11-14 14:57:54 [timeline NEW DL] C:\Users\anna\Downloads\setup.exe => Edge from dl.example.com/setup.exe, page www.example.com/download <==== !kept-despite-warning
2026-11-19 16:11:30 [Defender] Defender detected: Trojan:Script/Wacatac.B!ml => C:\Users\anna\AppData\Local\Temp\tmp-1\ETWProviders.dll; process: C:\Users\anna\x\javaw.exe, pid:24444:1195

==================== TIMELINE - last 30 days, oldest first ====================
2026-10-29 15:19:37 [INS] installed or updated: Thunderstore Mod Manager 1.126.0 (Overwolf app), per user => key HKU\S-1-5-21-1-2-3-1001\...\Overwolf_abc
2026-11-14 14:57:54 [NEW DL] C:\Users\anna\Downloads\setup.exe => Edge from dl.example.com/setup.exe, page www.example.com/download <==== !kept-despite-warning
2026-11-18 17:38:19 [INS] Store app register: 5319275A.WhatsAppDesktop_2.2644.101.0_neutral_~_cv1g1gvanyjgm, from Windows Update => folder C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2644.101.0_neutral_~_cv1g1gvanyjgm
2026-11-19 16:11:30 [DEF] Defender detected: Trojan:Script/Wacatac.B!ml => C:\Users\anna\AppData\Local\Temp\tmp-1\ETWProviders.dll

==================== SOFTWARE - programs installed, updated or removed recently ====================
--- Installed programs, installed or updated in the last 30 days (Uninstall keys) ---
2026-11-17 23:14:44 [machine 32-bit] Google Chrome => C:\Program Files\Google\Chrome\Application\chrome.exe, version 158.0; publisher Google LLC; install date 2026-11-18; folder C:\Program Files\Google\Chrome\Application\; key HKLM-x32\...\Google Chrome
2026-10-24 04:42:52 [machine] 4 entries from Learning Machines LLC
    programs: PhotoCraft 0.15.1, DesignCraft 0.12.0
    key: HKLM\...\{A}; name PhotoCraft; version 0.15.1
    key: HKLM\...\{B}; name DesignCraft; version 0.12.0

--- Store and MSIX apps: added, registered, removed or failed in the last 30 days (AppXDeploymentServer log) ---
2026-11-18 17:38:19 [Register] 5319275A.WhatsAppDesktop_2.2644.101.0_neutral_~_cv1g1gvanyjgm => times 1; from (AppxBundleManifest.xml); source Windows Update; signer 24803D75-212C-471A-BC57-9EF86AB91435 (package); folder C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2644.101.0_neutral_~_cv1g1gvanyjgm

==================== PERSISTENCE - Run keys, services, scheduled tasks, Startup folders, WMI, with times ====================
--- Run keys (all entries) ---
2026-09-11 03:25:18 [runonce] HKU\anna\Software\Microsoft\Windows\CurrentVersion\RunOnce\Restart #3 => E:\Download\T\T.exe [unsigned], arguments --nwapp="E:\Download\T" --restart; value Restart #3 <==== !hidden-name
2026-11-15 16:35:36 [run] HKU\anna\Software\Microsoft\Windows\CurrentVersion\Run\Back\Slash => C:\Program Files\A\a.exe; value Back\Slash
--- Scheduled tasks ---
2026-06-20 08:17:54 [task] \ZoomUpdate => C:\Users\anna\AppData\Roaming\Zoom\bin\Zoom.exe, changed 2026-06-21 08:00:00; arguments --action=UpdateSchedule
    info: author Zoom

==================== DEFENDER - detections, setting changes, cloud lookups (MPLog), cleared event logs ====================
2026-11-19 16:13:22 [1117] Defender action taken: HackTool:MSIL/AutoKMS.I!MTB => F:\A\[BAGAS31] KMSAutoLite1.5.6.zip; F:\A\KMSAuto x64.exe; F:\A\[BAGAS31] KMSAutoLite1.5.6.zip->KMSAuto Lite Portable v1.5.6/KMSAuto x64.exe; action Remove
2026-11-20 02:07:02 [1117] Defender action taken: Behavior:Win32/SuspEtherRpcConn.B => process: C:\Users\anna\x\javaw.exe, pid:24444:119519315058560; action Remove
''')

# Spor 0.7.0: the long details on sub-lines.
NEW = _log('0.7.0', r'''
==================== SUMMARY - flagged items; details in the sections below ====================
2026-11-14 14:57:54 [timeline NEW DL] C:\Users\anna\Downloads\setup.exe => Edge <==== !kept-despite-warning
    from: dl.example.com/setup.exe
    page: www.example.com/download
2026-11-19 16:11:30 [Defender] Defender detected: Trojan:Script/Wacatac.B!ml
    file: C:\Users\anna\AppData\Local\Temp\tmp-1\ETWProviders.dll
    process: C:\Users\anna\x\javaw.exe, pid:24444:1195

==================== TIMELINE - last 30 days, oldest first ====================
2026-10-29 15:19:37 [INS] installed or updated: Thunderstore Mod Manager 1.126.0 (Overwolf app), per user
    key: HKU\S-1-5-21-1-2-3-1001\...\Overwolf_abc
2026-11-14 14:57:54 [NEW DL] C:\Users\anna\Downloads\setup.exe => Edge <==== !kept-despite-warning
    from: dl.example.com/setup.exe
    page: www.example.com/download
2026-11-18 17:38:19 [INS] Store app register: 5319275A.WhatsAppDesktop_2.2644.101.0_neutral_~_cv1g1gvanyjgm, from Windows Update
    folder: C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2644.101.0_neutral_~_cv1g1gvanyjgm
2026-11-19 16:11:30 [DEF] Defender detected: Trojan:Script/Wacatac.B!ml
    file: C:\Users\anna\AppData\Local\Temp\tmp-1\ETWProviders.dll

==================== SOFTWARE - programs installed, updated or removed recently ====================
--- Installed programs, installed or updated in the last 30 days (Uninstall keys) ---
2026-11-17 23:14:44 [machine 32-bit] Google Chrome => C:\Program Files\Google\Chrome\Application\chrome.exe, version 158.0; publisher Google LLC; install date 2026-11-18
    folder: C:\Program Files\Google\Chrome\Application\
    key: HKLM-x32\...\Google Chrome
2026-10-24 04:42:52 [machine] 4 entries from Learning Machines LLC
    key: HKLM\...\{A}; name PhotoCraft; version 0.15.1
    key: HKLM\...\{B}; name DesignCraft; version 0.12.0

--- Store and MSIX apps: added, registered, removed or failed in the last 30 days (AppXDeploymentServer log) ---
2026-11-18 17:38:19 [Register] 5319275A.WhatsAppDesktop_2.2644.101.0_neutral_~_cv1g1gvanyjgm => times 1; from (AppxBundleManifest.xml); source Windows Update
    signer: 24803D75-212C-471A-BC57-9EF86AB91435 (package)
    folder: C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2644.101.0_neutral_~_cv1g1gvanyjgm

==================== PERSISTENCE - Run keys, services, scheduled tasks, Startup folders, WMI, with times ====================
--- Run keys (all entries) ---
2026-09-11 03:25:18 [runonce] HKU\anna\Software\Microsoft\Windows\CurrentVersion\RunOnce\Restart #3 <==== !hidden-name
    program: E:\Download\T\T.exe [unsigned]
    arguments: --nwapp="E:\Download\T" --restart
2026-11-15 16:35:36 [run] HKU\anna\Software\Microsoft\Windows\CurrentVersion\Run\Back\Slash
    program: C:\Program Files\A\a.exe
    value: Back\Slash
--- Scheduled tasks ---
2026-06-20 08:17:54 [task] \ZoomUpdate => changed 2026-06-21 08:00:00
    program: C:\Users\anna\AppData\Roaming\Zoom\bin\Zoom.exe
    arguments: --action=UpdateSchedule
    info: author Zoom

==================== DEFENDER - detections, setting changes, cloud lookups (MPLog), cleared event logs ====================
2026-11-19 16:13:22 [1117] Defender action taken: HackTool:MSIL/AutoKMS.I!MTB => action Remove
    file: F:\A\[BAGAS31] KMSAutoLite1.5.6.zip
    file: F:\A\KMSAuto x64.exe
    file: F:\A\[BAGAS31] KMSAutoLite1.5.6.zip->KMSAuto Lite Portable v1.5.6/KMSAuto x64.exe
2026-11-20 02:07:02 [1117] Defender action taken: Behavior:Win32/SuspEtherRpcConn.B => action Remove
    process: C:\Users\anna\x\javaw.exe, pid:24444:119519315058560
''')


class SporUnfoldTests(SimpleTestCase):
    def test_old_logs_are_left_as_they_are(self):
        self.assertIs(spor_log.unfold(OLD), OLD)

    def test_line_numbers_stay(self):
        unfolded = spor_log.unfold(NEW)
        self.assertEqual(len(unfolded), len(NEW))
        self.assertEqual([no for no, line in enumerate(NEW) if spor_log.is_sub_line(line)],
                         [no for no, line in enumerate(unfolded) if spor_log.is_sub_line(line)])

    def test_run_and_task_lines_read_the_same(self):
        def persistence(lines):
            return [(m.identity, m.path, m.role, m.status, m.flags) for m in spor_log.iter_mentions(lines)
                    if m.section == spor_log.SECTION_PERSISTENCE]
        self.assertEqual(persistence(OLD), persistence(NEW))
        self.assertIn((('run', 'Restart #3'), r'E:\Download\T\T.exe', 'target', 'unsigned', ['!hidden-name']), persistence(NEW))
        # a value name with a backslash comes from its value: line
        self.assertIn(('run', r'Back\Slash'), [m[0] for m in persistence(NEW)])

    def test_run_value_without_a_value_line_is_the_entrys_last_part(self):
        lines = _log('0.7.0', r'''
==================== PERSISTENCE - Run keys ====================
2026-11-15 16:35:36 [run] HKU\anna\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftEdgeAutoLaunch_28CC
    program: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
    arguments: --win-session-start
''')
        identities = [m.identity for m in spor_log.iter_mentions(lines) if m.identity]
        self.assertEqual([('run', 'MicrosoftEdgeAutoLaunch_28CC')], identities)

    def test_defender_detections_read_the_same(self):
        def detections(lines):
            return sorted((threat, action, path) for _no, threat, action, path in spor_log.iter_defender_detections(lines))
        self.assertEqual(detections(OLD), detections(NEW))
        self.assertIn(('HackTool:MSIL/AutoKMS.I!MTB', 'Remove', r'F:\A\KMSAuto x64.exe'), detections(NEW))

    def test_software_facts_read_the_same(self):
        def facts(lines):
            return [(f.kind, f.name, f.status, f.details.get('folder'), f.details.get('key'), f.details.get('signer'), f.details.get('program'))
                    for f in spor_log.iter_software(lines)]
        self.assertEqual(facts(OLD), facts(NEW))
        names = [fact[1] for fact in facts(NEW)]
        self.assertEqual(['Google Chrome', 'PhotoCraft', 'DesignCraft', '5319275A.WhatsAppDesktop_2.2644.101.0_neutral_~_cv1g1gvanyjgm'], names)

    def test_timeline_install_keys_read_the_same(self):
        def keys(lines):
            return [spor_log.parse_labelled(item.rest, spor_log.SOFTWARE_LABELS)[0].get('key', '')
                    for _no, item in spor_log.iter_timeline_items(lines) if 'INS' in item.tags.split()]
        self.assertEqual(keys(OLD), keys(NEW))
        self.assertEqual(r'HKU\S-1-5-21-1-2-3-1001\...\Overwolf_abc', keys(NEW)[0])

    def test_timeline_evidence_reads_the_same_files(self):
        def evidence(lines):
            return [(e.path, e.sources, e.flags) for e in spor_log.iter_timeline_evidence(lines)]
        self.assertEqual(evidence(OLD), evidence(NEW))

    def test_summary_flags_the_same_files(self):
        def flagged(lines):
            return _spor_flagged_paths(lines, spor_log.iter_defender_detections(lines))
        self.assertEqual(flagged(OLD), flagged(NEW))

    def test_summary_defender_line_names_its_file(self):
        def summary(lines):
            return [(item.item, spor_log.defender_paths(item.rest)) for _no, item in spor_log.iter_summary_items(lines)]
        self.assertEqual(summary(OLD), summary(NEW))

    def test_amcache_files_lines_of_one_folder_are_one_mention(self):
        lines = _log('0.7.0', r'''
==================== AMCACHE - files and drivers Windows recorded ====================
--- Inventory scans (not in the timeline) ---
2026-10-26 12:08:44 136 entries => mostly in C:\Users\anna\AppData\Roaming\Zoom\bin (13)
    files: C:\Users\anna\AppData\Roaming\Zoom\bin\ => CptControl.exe, CptHost.exe
    files: C:\Users\anna\AppData\Roaming\Zoom\bin\ => ZoomDocConverter.exe, zTscoder.exe
    files: D:\Games\ => a.exe
''')
        files = [m.path for m in spor_log.iter_mentions(lines) if m.role == 'files']
        self.assertEqual([r'C:\Users\anna\AppData\Roaming\Zoom\bin' + '\\', 'D:\\Games\\'], files)


FILES_OLD = _log('0.6.1', r'''
==================== FILES - SHA256, signature and version of the files as they are on disk now ====================
C:\Windows\System32\drivers\amdgpio3.sys => 8E6D91B8CA754799BBF3AB775F81309E3DBC1B5149FEF4BB435AE050208CA16D, signature valid; signer ASMedia Technology Inc.; thumbprint 7B10E024D9B9F6AA95569BAC2A6A2292E5D2889B; file version 3.0.5.0000; description AMD GPIO Driver; original name amdgpio3.sys; md5 541EB09C9F1A0CBACC44CA06B7685523; size 33664; created 2025-12-03 03:33:16; modified 2025-12-03 03:33:16
C:\Users\anna\Downloads\x.exe [gone] => not hashed, signature unsigned
''')

FILES_NEW = _log('0.7.0', r'''
==================== FILES - SHA256, signature and version of the files as they are on disk now ====================
C:\Windows\System32\drivers\amdgpio3.sys => 8E6D91B8CA754799BBF3AB775F81309E3DBC1B5149FEF4BB435AE050208CA16D, signature valid; signer ASMedia Technology Inc.
    file: md5 541EB09C9F1A0CBACC44CA06B7685523; size 33664; created 2025-12-03 03:33:16; modified 2025-12-03 03:33:16
    version: file version 3.0.5.0000; description AMD GPIO Driver; original name amdgpio3.sys; thumbprint 7B10E024D9B9F6AA95569BAC2A6A2292E5D2889B
C:\Users\anna\Downloads\x.exe [gone] => not hashed, signature unsigned
''')


class SporUnfoldFilesTests(SimpleTestCase):
    def test_files_lines_read_the_same(self):
        def files(lines):
            return [(f.path, f.hash, f.status, f.signature, f.details) for f in spor_log.iter_file_lines(lines)]
        self.assertEqual(files(FILES_OLD), files(FILES_NEW))
        [driver, _gone] = files(FILES_NEW)
        self.assertEqual('541EB09C9F1A0CBACC44CA06B7685523', driver[4]['md5'])
        self.assertEqual('7B10E024D9B9F6AA95569BAC2A6A2292E5D2889B', driver[4]['thumbprint'])

    def test_files_hash_rows_keep_their_md5(self):
        from ..file_hashes import extract_file_hashes
        from ..log_types import LOG_TYPE_SPOR
        def rows(lines):
            return sorted((r.sha256, r.md5, r.path) for r in extract_file_hashes(LOG_TYPE_SPOR, '\n'.join(lines)))
        self.assertEqual(rows(FILES_OLD), rows(FILES_NEW))
        self.assertIn(('8e6d91b8ca754799bbf3ab775f81309e3dbc1b5149fef4bb435ae050208ca16d', '541eb09c9f1a0cbacc44ca06b7685523',
                       r'C:\Windows\System32\drivers\amdgpio3.sys'), rows(FILES_NEW))


def _line_key(lines, no):
    """What a line is about, the same in both layouts: (time, tags, item) of
    an item line, the text of a sub-line."""
    body = lines[no - 1]
    if spor_log.is_sub_line(body):
        return body.strip()
    item = spor_log.split_item(body)
    return item.time, item.tags, item.item


def _entries_of(lines):
    """{line no: [entry]} of the entries the log's own lines are indexed with."""
    from ..correlations.spor_source import build
    found = {}
    for entries in build('u', lines).index.values():
        for entry in entries:
            found.setdefault(entry['line_no'], []).append(entry)
    return found


def _line_no(lines, start):
    return next(no for no, line in enumerate(lines, 1) if line.startswith(start))


class SporSplitLineEntriesTests(SimpleTestCase):
    """Correlation entries of a Spor 0.7.0 line show it as the log does: the
    line itself, its detail sub-lines as `extra` rows."""

    def test_links_are_the_same_in_both_layouts(self):
        from ..correlations import spor_self

        def links(lines):
            found = spor_self.compute('u', '\n'.join(lines))
            return {
                _line_key(lines, int(no)): {
                    (_line_key(lines, entry['line_no']), entry['kind'], entry.get('match') or '')
                    for entry in found.entries(no)
                }
                for no in found.codes
            }
        self.assertEqual(links(OLD), links(NEW))
        self.assertTrue(links(NEW))

    def test_summary_defender_entry_shows_its_file_sub_line(self):
        no = _line_no(NEW, '2026-11-19 16:11:30 [Defender]')
        [entry] = [e for e in _entries_of(NEW)[no] if e['kind'] == 'mention']
        self.assertEqual('2026-11-19 16:11:30 [Defender] Defender detected: Trojan:Script/Wacatac.B!ml', entry['text'])
        self.assertEqual([['file', r'C:\Users\anna\AppData\Local\Temp\tmp-1\ETWProviders.dll'],
                          ['process', r'C:\Users\anna\x\javaw.exe, pid:24444:1195']], entry['extra'])

    def test_run_mention_shows_program_and_arguments_rows(self):
        no = _line_no(NEW, '2026-09-11 03:25:18 [runonce]')
        mentions = [e for e in _entries_of(NEW)[no] if e['kind'] == 'mention' and e['section'] == spor_log.SECTION_PERSISTENCE]
        self.assertTrue(mentions)
        for entry in mentions:
            self.assertNotIn(' => ', entry['text'])
            self.assertEqual([['program', r'E:\Download\T\T.exe [unsigned]'],
                              ['arguments', r'--nwapp="E:\Download\T" --restart']], entry['extra'])

    def test_software_fact_shows_folder_and_key_rows(self):
        no = _line_no(NEW, '2026-11-17 23:14:44 [machine 32-bit]')
        [fact] = [f for f in spor_log.iter_software(NEW) if f.line_no == no]
        self.assertEqual(NEW[no - 1].strip(), fact.text)
        self.assertEqual([['folder', 'C:\\Program Files\\Google\\Chrome\\Application\\'],
                          ['key', r'HKLM-x32\...\Google Chrome']], fact.extra)
        entries = [e for e in _entries_of(NEW)[no] if e.get('role') == 'uninstall entry']
        self.assertTrue(entries)
        self.assertEqual(fact.extra, entries[0]['extra'])

    def test_timeline_install_entry_shows_its_key_row(self):
        no = _line_no(NEW, '2026-10-29 15:19:37 [INS]')
        [entry] = [e for e in _entries_of(NEW)[no] if e['kind'] == 'mention']
        self.assertEqual(NEW[no - 1].strip(), entry['text'])
        self.assertEqual([['key', r'HKU\S-1-5-21-1-2-3-1001\...\Overwolf_abc']], entry['extra'])

    def test_download_evidence_shows_its_addresses_as_rows(self):
        no = _line_no(NEW, '2026-11-14 14:57:54 [NEW DL]')
        [evidence] = [e for e in spor_log.iter_timeline_evidence(NEW) if e.line_no == no]
        self.assertEqual('Edge', evidence.details)
        self.assertEqual([['from', 'dl.example.com/setup.exe'], ['page', 'www.example.com/download']], evidence.extra)
        [entry] = [e for e in _entries_of(NEW)[no] if e['kind'] == 'evidence']
        self.assertEqual('Edge', entry['details'])
        self.assertEqual(evidence.extra, entry['extra'])

    def test_old_layout_entries_are_as_before(self):
        entries = _entries_of(OLD)
        no = _line_no(OLD, '2026-11-19 16:11:30 [Defender]')
        [entry] = [e for e in entries[no] if e['kind'] == 'mention']
        self.assertEqual(OLD[no - 1].strip(), entry['text'])
        self.assertEqual([], entry['extra'])
        no = _line_no(OLD, '2026-11-14 14:57:54 [NEW DL]')
        [evidence] = [e for e in entries[no] if e['kind'] == 'evidence']
        self.assertEqual('Edge from dl.example.com/setup.exe, page www.example.com/download', evidence['details'])
        self.assertEqual([], evidence['extra'])
        no = _line_no(OLD, '2026-09-11 03:25:18 [runonce]')
        for entry in entries[no]:
            if entry['kind'] == 'mention':
                self.assertEqual(OLD[no - 1].strip(), entry['text'])
                self.assertEqual([], entry['extra'])


class SporReviewFixTests(SimpleTestCase):
    def test_unfold_twice_is_unfold_once(self):
        once = spor_log.unfold(NEW)
        self.assertIs(spor_log.unfold(once), once)
        self.assertIs(spor_log.unfold(NEW), once)   # the readers of one log share one pass
        self.assertEqual(once, spor_log.unfold(list(NEW)))
        self.assertEqual(spor_log.known_paths(NEW), spor_log.known_paths(once))

    def test_flagged_files_line_keeps_its_sub_line_details(self):
        lines = _log('0.7.0', r'''
==================== FILES - SHA256, signature and version of the files as they are on disk now ====================
C:\Users\anna\x => y.exe => 8E6D91B8CA754799BBF3AB775F81309E3DBC1B5149FEF4BB435AE050208CA16D, signature unsigned <==== !log-syntax-in-name
    file: md5 541EB09C9F1A0CBACC44CA06B7685523; size 33664
''')
        [parsed] = spor_log.iter_file_lines(lines)
        self.assertEqual('541EB09C9F1A0CBACC44CA06B7685523', parsed.details.get('md5'))
        self.assertEqual('33664', parsed.details.get('size'))
        self.assertEqual('unsigned', parsed.signature)

    def test_summary_defender_process_is_not_a_flagged_file(self):
        for lines in (OLD, NEW):
            flagged = _spor_flagged_paths(lines, spor_log.iter_defender_detections(lines))
            self.assertIn(normalized_path(r'C:\Users\anna\AppData\Local\Temp\tmp-1\ETWProviders.dll'), flagged)
            self.assertNotIn(normalized_path(r'C:\Users\anna\x\javaw.exe'), flagged)

    def test_merged_line_paths_show_the_details_of_their_line(self):
        lines = _log('0.7.0', r'''
==================== TIMELINE - last 30 days, oldest first ====================
2026-11-14 14:57:54 [NEW DL] C:\Users\anna\Downloads\v2\setup.exe => Edge; +1 more times (below)
    path: C:\Users\anna\Downloads\v1\setup.exe => 2026-11-13 10:00:00
    path: C:\Users\anna\Downloads\v2\setup.exe => 2026-11-14 14:57:54
    from: dl.example.com/setup.exe
''')
        evidence = spor_log.iter_timeline_evidence(lines)
        self.assertEqual(2, len(evidence))
        for found in evidence:
            self.assertEqual('Edge; +1 more times (below)', found.details)
            self.assertEqual([['from', 'dl.example.com/setup.exe']], found.extra)
