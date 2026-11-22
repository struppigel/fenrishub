"""A made-up Spor 0.8.0 log (user Bob, invented hashes and GUIDs) with the
lines Spor 0.8.0 added: DROP FOLDERS (PavinLoader project folders, one of
them hidden and found by the sweep alone, linked by "group:"), a copied
MSBuild.exe with !lolbin-copy and a "shimcache:" sub-line, and a cached
Windows Installer package with !msi-script-action. A leaf module."""

LOCAL = 'C:\\Users\\Bob\\AppData\\Local'
ROAMING = 'C:\\Users\\Bob\\AppData\\Roaming'
AMQP = LOCAL + '\\Microsoft\\Windows\\WebCache\\AmqpNet'
PROTECT = ROAMING + '\\Microsoft\\Protect\\RecruitmentTracker'
THIRD = LOCAL + '\\Microsoft\\Windows\\WebCache\\RecruitmentTracker'
CODE = '9C1E2F3A-4B5C-4D6E-8F70-81A2B3C4D5E6'
MSI = 'C:\\Windows\\Installer\\4f1a2b.msi'
MSBUILD_SHA = 'ab' * 32
RESX_SHA = 'cd' * 32
WSF_SHA = 'ef' * 32
MSI_SHA = '12' * 32
REASON = 'project folder (MSBuild.exe, {0}.wsf, {0}.sln, {0}.csproj, +4 more; Resources.resx 25165824 bytes)'


def _drop(folder, name, created, attributes, group):
    lines = [
        f'{created} {folder}\\ => {attributes}; known malware PavinLoader: {REASON.format(name)}; 24 files'
        ' <==== !known-malware !lolbin-copy',
        f'    entry: {folder}\\MSBuild.exe [invalid signature] => 251904 bytes; created {created}; copy of MSBuild.exe'
        ' outside its usual folders; invalid signature; in a Windows cache folder <==== !lolbin !lolbin-copy',
        f'    entry: {folder}\\{name}.wsf => 1024 bytes; created {created}',
        f'    entry: {folder}\\Resources.resx => 25165824 bytes; created {created}',
        f'    others: .gitattributes, .gitignore, app.config, Directory.Build.props, LICENSE, README.md, {name}.csproj, {name}.sln',
    ]
    if group:
        lines.append(f'    group: {AMQP}\\')
    return lines


def _files(folder, name):
    return [
        f'{folder}\\MSBuild.exe => {MSBUILD_SHA}, signature invalid; signer Microsoft Corporation; note file changed after signing (bad digest)',
        '    file: md5 ' + '34' * 16 + '; size 251904; created 2026-11-20 10:11:12; modified 2026-07-05 10:00:00',
        '    version: file version 4.8.9032.0; description MSBuild.exe; company Microsoft Corporation; original name MSBuild.exe',
        f'{folder}\\{name}.wsf => {WSF_SHA}',
        '    file: md5 ' + '56' * 16 + '; size 1024; created 2026-11-20 10:11:12; modified 2026-11-20 10:11:12',
        f'{folder}\\Resources.resx => {RESX_SHA}',
        '    file: md5 ' + '78' * 16 + '; size 25165824; created 2026-11-20 10:11:12; modified 2026-11-20 10:11:12',
    ]


SPOR8 = '\n'.join([
    '==================== Spor 0.8.0 - forensic triage log ==============================================',
    'Created:   2026-11-22 09:00:00 UTC (local time 10:00, UTC+01:00)',
    'Computer:  PC-BOB, Windows 11 Home 26H2, build 26300.9974, 64-bit',
    'Users:     Bob',
    'Times:     UTC, except created and modified in FILES (local time of this PC, as FRST shows them)',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '',
    f'2026-11-19 08:00:00 [Software] {MSI} [unsigned] => cached Windows Installer package Card Reader Helper 2.6'
    f' (Realtek Semiconductor Corp.); product code {{{CODE}}}; custom action LaunchHelper: INSTALLFOLDER wscript.exe //B'
    f' //NoLogo "[Helper.wsf]"; installs into {LOCAL}\\Realtek\\Card Reader Helper\\ <==== !msi-script-action',
    f'2026-11-20 09:11:12 [timeline DRP] {AMQP}\\ => known malware PavinLoader: {REASON.format("AmqpNet")}; 24 files'
    ' <==== !known-malware !lolbin-copy',
    f'2026-11-20 09:11:12 [timeline DRP] {PROTECT}\\ => known malware PavinLoader: {REASON.format("RecruitmentTracker")};'
    ' 24 files <==== !known-malware !lolbin-copy',
    f'    group: {AMQP}\\',
    f'2026-11-20 09:11:12 [timeline DRP] {THIRD}\\ => known malware PavinLoader: {REASON.format("RecruitmentTracker")};'
    ' attributes hidden, folder; 24 files <==== !known-malware !lolbin-copy',
    f'    group: {AMQP}\\',
    f'2026-11-20 09:15:00 [timeline AM SRU] {AMQP}\\MSBuild.exe [invalid signature] => copy of MSBuild.exe outside its'
    ' usual folders; invalid signature; in a Windows cache folder <==== !lolbin !lolbin-copy',
    '    shimcache: file modified 2026-07-05 09:00:00 (before it was created: a copy keeps the original\'s time)',
    '',
    '==================== TIMELINE - last 30 days, oldest first =========================================',
    '(line: time [sources] file or event [status] => details <==== flags)',
    '',
    f'2026-11-19 08:00:05 [INS] Windows Installer installed: Card Reader Helper 2.6 (Realtek Semiconductor Corp.) => product code {{{CODE}}}',
    f'2026-11-20 09:11:12 [DRP] {AMQP}\\ => known malware PavinLoader: {REASON.format("AmqpNet")}; 24 files'
    ' <==== !known-malware !lolbin-copy',
    f'2026-11-20 09:11:12 [DRP] {PROTECT}\\ => known malware PavinLoader: {REASON.format("RecruitmentTracker")}; 24 files'
    ' <==== !known-malware !lolbin-copy',
    f'    group: {AMQP}\\',
    f'2026-11-20 09:11:12 [DRP] {THIRD}\\ => known malware PavinLoader: {REASON.format("RecruitmentTracker")};'
    ' attributes hidden, folder; 24 files <==== !known-malware !lolbin-copy',
    f'    group: {AMQP}\\',
    f'2026-11-20 09:15:00 [AM SRU] {AMQP}\\MSBuild.exe [invalid signature] => copy of MSBuild.exe outside its usual'
    ' folders; invalid signature; in a Windows cache folder <==== !lolbin !lolbin-copy',
    '    shimcache: file modified 2026-07-05 09:00:00 (before it was created: a copy keeps the original\'s time)',
    '',
    '==================== SOFTWARE - programs installed, updated or removed recently ====================',
    '--- Windows Installer: installs and removals in the last 30 days (Application log) ---',
    '(line: time [event] what => user; name; product code)',
    '',
    f'2026-11-19 08:00:05 [1033] installed: Card Reader Helper 2.6 (Realtek Semiconductor Corp.) => Bob; name Card Reader Helper; product code {{{CODE}}}',
    '',
    '--- Cached Windows Installer packages (C:\\Windows\\Installer) ---',
    '(line: cached [kind] package [status] => name; version; publisher; product code <==== flags)',
    '',
    f'2026-11-19 08:00:00 [cached msi] {MSI} [unsigned] => name Card Reader Helper; version 2.6;'
    f' publisher Realtek Semiconductor Corp.; product code {{{CODE}}} <==== !msi-script-action',
    '    custom action: LaunchHelper: INSTALLFOLDER wscript.exe //B //NoLogo "[Helper.wsf]"',
    f'    folder: {LOCAL}\\Realtek\\Card Reader Helper\\',
    '(Read 212 cached packages, 1 with a script custom action into LocalAppData.)',
    '',
    '==================== DROP FOLDERS - loader project folders in Windows cache and system folders, found without other evidence ====',
    '--- Loader project folders ---',
    '(line: created folder => attributes; details <==== flags)',
    '',
    *_drop(AMQP, 'AmqpNet', '2026-11-20 09:11:12', 'attributes folder', False),
    *_drop(PROTECT, 'RecruitmentTracker', '2026-11-20 09:11:12', 'attributes folder', True),
    *_drop(THIRD, 'RecruitmentTracker', '2026-11-20 09:11:12', 'attributes hidden, folder', True),
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '(line: file => sha256, signature)',
    '',
    *_files(AMQP, 'AmqpNet'),
    *_files(PROTECT, 'RecruitmentTracker'),
    *_files(THIRD, 'RecruitmentTracker'),
    f'{MSI} => {MSI_SHA}, signature unsigned',
    '    file: md5 ' + '9a' * 16 + '; size 2048000; created 2026-11-19 09:00:00; modified 2026-11-19 09:00:00',
    '',
    '==================== LEGEND ========================================================================',
    '==================== End of log. Scan took 9.9 s ====',
])
