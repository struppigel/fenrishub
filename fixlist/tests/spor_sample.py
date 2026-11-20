"""A trimmed, anonymised Spor log (forensic triage) for the tests: every
kind of line the parser and the highlighter know. A leaf module, so other
test modules can import it without import cycles."""

EVIL = 'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.exe'
DROPPER = 'C:\\Users\\Bob\\Downloads\\dropper.exe'
INVOICE = 'C:\\Users\\Bob\\Desktop\\invoice.pdf.exe'
EVIL_SHA = 'e5' * 32
DROP_SHA = 'd7' * 32
OK_SHA = 'a1' * 32
NOTES_MD5 = 'c3' * 16
SHA1 = 'f0' * 20
# The MD5 of EVIL (FRST Search's File: entry, and Spor's newest FILES line).
SEARCH_MD5 = '389700d32db7ecc74af1dcf801f05a05'

SPOR = '\n'.join([
    '==================== Spor 0.1.0 - forensic triage log ==============================================',
    'Created:   2026-11-18 07:49:43 UTC (local time 08:49, UTC+01:00)',
    'Computer:  PC-BOB, Windows 11 Home 26H2, build 26300.9974, 64-bit',
    'Run by:    Bob (administrator)',
    'Format:    one item per line: time [sources] item [status] => details <==== flags (parts left out when empty);',
    '           (lines in brackets) are comments, "(line: ...)" names the parts.',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '2026-11-17 16:12:59 [timeline DEF] Defender paths exclusions changed (now 1: C:\\Users\\Bob\\Downloads)'
    ' <==== !defender-exclusion',
    f'2026-09-30 03:55:49 [Persistence] service EvilSvc (auto): {EVIL} [unsigned]',
    f'2026-11-14 07:21:07 [Defender] Defender detected: Trojan:Win32/Malgent!MSR => {DROPPER};'
    ' process C:\\Windows\\explorer.exe',
    '2026-11-14 07:21:08 [Defender] Defender detected: PUA:Win32/Presenoker => C:\\Users\\Bob\\Downloads\\bundle.exe',
    '[ClickFix] Run dialog cmd /c calc.exe',
    '(LOLBins run in the last 30 days (normal on many PCs, see the timeline): mshta.exe)',
    '',
    '==================== TIMELINE - last 30 days, newest first =========================================',
    '(line: time [sources] file or event [status] => details <==== flags)',
    f'2026-11-18 07:48:46 [PF PCA BAM] {EVIL} [unsigned] => PCA: Installer failed; +2 more times since 2026-11-18 05:23',
    '2026-11-18 07:37:00 [PF] C:\\Windows\\System32\\mshta.exe => +1 more times since 2026-11-18 06:45 <==== !lolbin',
    f'2026-11-17 07:49:28 [DL OPN] {INVOICE} [gone] => Brave from example.com/invoice.pdf.exe, page example.com/;'
    ' opened <==== !double-extension',
    '2026-11-14 05:36:00 [SRU] C:\\Users\\Bob\\AppData\\Local\\App\\1.0.1\\app.exe => SRUM first activity in the window',
    '    path: C:\\Users\\Bob\\AppData\\Local\\App\\1.0.1\\app.exe => 2026-11-14 05:36:00',
    '    path: C:\\Users\\Bob\\AppData\\Local\\App\\1.0.0\\app.exe [gone] => 2026-10-23 19:29:00',
    '2026-11-13 14:42:22 [DEF] Defender detection history deleted',
    '',
    '==================== PREFETCH - programs run and the files they loaded =============================',
    '--- Files loaded by programs run in the last 30 days ---',
    '2026-11-18 07:48:44 C:\\Windows\\System32\\consent.exe',
    f'    loaded: {EVIL} [unsigned]',
    '',
    '==================== DEFENDER - detections, setting changes, cloud lookups (MPLog), cleared event logs ====',
    '--- Defender events (newest first) ---',
    '(line: time [event] what <==== flags)',
    f'2026-11-14 07:22:00 [1117] Defender action taken: Trojan:Win32/Malgent!MSR => {DROPPER}; action Quarantine;'
    ' process C:\\Windows\\explorer.exe',
    f'2026-11-14 07:21:07 [1116] Defender detected: Trojan:Win32/Malgent!MSR => {DROPPER};'
    ' process C:\\Windows\\explorer.exe',
    '2026-11-14 07:21:08 [1116] Defender detected: PUA:Win32/Presenoker => C:\\Users\\Bob\\Downloads\\bundle.exe',
    '',
    '==================== CLICKFIX - Run dialog, Explorer address bar, PowerShell history ===============',
    '--- PowerShell console history: ConsoleHost_history.txt ---',
    '(line: line [part] command <==== flags)',
    '789 [suspicious] Set-MpPreference -ExclusionPath "C:\\Users\\Bob" <==== !suspicious',
    '790 [last] git status',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '(line: file => sha256, signature; version; amcache sha1)',
    f'{EVIL} => {EVIL_SHA.upper()}, signature unsigned; amcache sha1 {SHA1.upper()}',
    f'{DROPPER} => {DROP_SHA.upper()}, signature invalid; signer Evil Ltd; thumbprint {SHA1.upper()}',
    f'C:\\Program Files\\Ok\\ok.exe => {OK_SHA.upper()}, signature valid; signer Ok Inc.; thumbprint {SHA1.upper()}',
    f'C:\\Users\\Bob\\Desktop\\notes.ps1 => {NOTES_MD5.upper()}',
    'C:\\Users\\Bob\\Desktop\\big.iso [> 600 MB, not hashed]',
    f'C:\\Users\\Bob\\Desktop\\sha1only.exe => {SHA1.upper()}, signature unsigned',
    '',
    '==================== AMCACHE FILES - SHA1 from Amcache of files not listed above ====',
    f'C:\\Users\\Bob\\Desktop\\old.exe => {SHA1.upper()}',
    '',
    '==================== LEGEND ========================================================================',
    'Sources (timeline, in brackets after the time):',
    '    PF    Prefetch: program run',
    'Flags (after <====):',
    '    !lolbin                     Windows tool that malware likes to use (normal on many PCs)',
    '==================== End of log. Scan took 57.1 s ====',
])
LINES = SPOR.split('\n')


# A log of the newer format (README with SOFTWARE and !log-syntax-in-name):
# a path made to look like log text, the SOFTWARE module, "not hashed" in
# FILES, an original name that differs, a Defender path exclusion, a Prefetch
# "loaded:" line, a Run key and a download with its address and page.
SYNTAX_PATH = 'C:\\Users\\Bob\\Desktop\\a => [gone] x.exe'
EVIL_DLL = 'C:\\Users\\Bob\\AppData\\Roaming\\evil\\evil.dll'
TEAMVIEWER = 'C:\\Program Files\\TeamViewer\\TeamViewer.exe'
NEXTCLOUD_GUID = '2D4C29A9-A516-4DA1-AD5A-313957614A0A'
TAILSCALE_GUID = '795F9101-3A31-5313-82FC-13CFC9E0FE17'
DOTNET_GUID = 'D03467F7-2366-46E4-A6CB-66FD9BA9B91F'
BOB_SID = 'S-1-5-21-1-2-3-1001'
EVIL_TOOL_FOLDER = 'C:\\Users\\Bob\\AppData\\Local\\EvilTool'
EVIL_TOOL = EVIL_TOOL_FOLDER + '\\tool.exe'
EVIL_PACKAGE = 'Evil.App_1.0.0.0_x64__abc'
EVIL_PACKAGE_FOLDER = 'C:\\Program Files\\WindowsApps\\' + EVIL_PACKAGE
X_SHA = 'b4' * 32
DLL_SHA = 'c8' * 32

SPOR_V2 = '\n'.join([
    '==================== Spor 0.1.0 - forensic triage log ==============================================',
    'Created:   2026-11-18 08:45:07 UTC (local time 09:45, UTC+01:00)',
    'Computer:  PC-BOB, Windows 11 Home 26H2, build 26300.9974, 64-bit',
    'Run by:    Bob (administrator)',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '',
    f'2026-11-18 08:00:00 [timeline NEW] {SYNTAX_PATH} <==== !log-syntax-in-name',
    '',
    '==================== TIMELINE - last 30 days, newest first =========================================',
    '(line: time [sources] file or event [status] => details <==== flags)',
    '',
    f'2026-11-18 08:00:00 [NEW] {SYNTAX_PATH} [unsigned] => from https://example.com/ <==== !log-syntax-in-name',
    '2026-11-18 07:00:00 [NEW] C:\\Users\\Bob\\Desktop\\b => fake.exe <==== !log-syntax-in-name',
    '2026-11-17 10:00:00 [INS] installed or updated: TeamViewer 15.83.7 (TeamViewer) => key HKLM\\...\\TeamViewer',
    '',
    '==================== PREFETCH - programs run and the files they loaded =============================',
    '--- Files loaded by programs run in the last 30 days ---',
    '(loaded: file [status] <==== flags)',
    '',
    '2026-11-18 07:48:44 C:\\Windows\\System32\\rundll32.exe <==== !lolbin',
    f'    loaded: {EVIL_DLL} [unsigned]',
    '',
    '==================== SOFTWARE - programs installed, updated or removed recently ====================',
    '--- Installed programs, installed or updated in the last 30 days (Uninstall keys) ---',
    '(line: time [scope] name => program [status], version; publisher; install date; folder; key; hidden <==== flags)',
    '',
    f'2026-11-17 10:00:00 [machine] TeamViewer => {TEAMVIEWER} [unsigned], version 15.83.7; publisher TeamViewer;'
    ' folder C:\\Program Files\\TeamViewer\\; key HKLM\\...\\TeamViewer',
    '2026-11-14 16:47:34 [machine] Some Game => C:\\Program Files (x86)\\Steam\\steam.exe, publisher Games Inc;'
    ' folder C:\\Program Files (x86)\\Steam\\steamapps\\common\\Some Game\\; key HKLM\\...\\Steam App 12345',
    '2026-11-12 03:46:25 [machine] Nextcloud => Windows Installer (msiexec), version 35.0.2; publisher Nextcloud GmbH;'
    f' key HKLM\\...\\{{{NEXTCLOUD_GUID}}}',
    f'2026-11-12 03:40:00 [user Bob] Evil Tool => {EVIL_TOOL} [unsigned], version 1.0; publisher Evil;'
    f' folder {EVIL_TOOL_FOLDER}\\; key HKU\\{BOB_SID}\\...\\EvilTool; hidden yes',
    '2026-10-23 13:50:41 [machine] 2 entries from Microsoft Corporation',
    '    programs: Microsoft .NET Host 10.0.13, Microsoft .NET Runtime 10.0.13',
    f'    key: HKLM\\...\\{{{DOTNET_GUID}}}',
    '    key: HKLM\\...\\{11111111-2222-3333-4444-555555555555}',
    '',
    '--- Windows Installer: installs and removals in the last 30 days (Application log) ---',
    '(line: time [event] what => user; name; product code)',
    '',
    f'2026-11-18 06:50:58 [1033] installed: Tailscale 1.104.7 (Tailscale Inc.) => SYSTEM; name Tailscale;'
    f' product code {{{TAILSCALE_GUID}}}',
    '2026-11-08 05:42:45 [1034] removed: Teams Add-in 1.26 (Microsoft) => Bob; name Teams Add-in;'
    ' product code {A7AB73A3-CB10-4AA5-9D38-6AEFFBDE4C91}',
    '2026-11-08 05:40:00 [11708] install failed: Evil Thing 1.0 (Evil) => Bob; name Evil Thing',
    '',
    '--- Store and MSIX apps: added, registered, removed or failed in the last 30 days (AppXDeploymentServer log) ---',
    '(line: last [operation] package [status] => display name; first; times; from; source; full trust; signer; folder <==== flags)',
    '',
    f'2026-11-14 02:35:08 [Add] {EVIL_PACKAGE} => Evil App; times 1; from https://evil.example/app.msix;'
    f' signer Evil Ltd (package); folder {EVIL_PACKAGE_FOLDER} <==== !from-web',
    '',
    '==================== PERSISTENCE - Run keys, services, scheduled tasks, Startup folders, WMI, with times ====',
    '--- Run keys (all entries) ---',
    '',
    f'2026-11-18 04:50:37 HKU\\Bob\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil => {EVIL} [unsigned],'
    ' arguments -silent',
    '',
    '==================== DOWNLOADS AND OPENED FILES - browser downloads, files opened, ISO mounts, archive history ====',
    '--- Browser downloads: executables, scripts, archives, disk images ---',
    '',
    '2026-11-17 07:49:24 [Brave] C:\\Users\\Bob\\Downloads\\tool.zip [gone]',
    '    from: https://files.example/tool.zip',
    '    page: https://www.virustotal.com/gui/file/abc',
    '',
    '==================== DEFENDER - detections, setting changes, cloud lookups (MPLog), cleared event logs ====',
    '--- Defender exclusions (current) ---',
    '(line: time [kind] exclusion)',
    '',
    '2026-11-17 16:12:59 [Paths] C:\\Users\\Bob\\AppData\\Roaming\\evil',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '(line: file => sha256, signature; version; amcache sha1)',
    '',
    f'{EVIL} => {EVIL_SHA.upper()}, signature unsigned; file version 1.0; description Windows Host;'
    f' company Microsoft Corporation; original name svchost.exe; amcache sha1 {SHA1.upper()}',
    f'{SYNTAX_PATH} => {X_SHA.upper()}, signature invalid; signer Evil Ltd',
    f'{TEAMVIEWER} => not hashed, signature unsigned',
    f'{EVIL_DLL} => {DLL_SHA.upper()}, signature unsigned; original name evil.dll',
    '',
    '==================== AMCACHE FILES - SHA1 from Amcache of files not listed above ====',
    '',
    f'C:\\Users\\Bob\\Desktop\\old.exe => {SHA1.upper()}',
    '',
    '==================== LEGEND ========================================================================',
    'Flags (after <====):',
    '    !log-syntax-in-name         the path contains " => " or a status word in brackets',
    '==================== End of log. Scan took 60.5 s ====',
])
LINES_V2 = SPOR_V2.split('\n')

# The newest format: details for linking with FRST logs (README "Details for
# linking with FRST logs"): the Machine SID and account SIDs, MD5 / size /
# times in FILES, the kind tag and Run value names in PERSISTENCE, svchost
# service DLLs, named "key:" lines of a grouped Uninstall entry, and SUMMARY
# lines with their flags inline.
MACHINE_SID = 'S-1-5-21-1-2-3'
SVC_DLL = 'C:\\ProgramData\\Evil\\evilsvc.dll'
OTHER_DLL = 'C:\\ProgramData\\Evil\\other.dll'
DRIVER = 'C:\\Users\\Bob\\AppData\\Local\\Temp\\evil.sys'
REPORT_LNK = 'C:\\Users\\Bob\\Desktop\\report.pdf.lnk'
LOADER = 'C:\\Program Files (x86)\\Host\\host.exe'
SVC_DLL_SHA = '9a' * 32
SVC_DLL_MD5 = '9b' * 16
LNK_SHA = '7c' * 32
LOADER_SHA = '6d' * 32
DOTNET_HOST_GUID = '11111111-2222-3333-4444-555555555555'

SPOR_V3 = '\n'.join([
    '==================== Spor 0.1.0 - forensic triage log ==============================================',
    'Created:   2026-11-18 12:45:48 UTC (local time 13:45, UTC+01:00)',
    'Computer:  PC-BOB, Windows 11 Home 26H2, build 26300.9974, 64-bit',
    'Run by:    Bob (administrator)',
    f'Machine SID: {MACHINE_SID}',
    'Users:     Bob',
    'Times:     UTC',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '',
    f'2026-11-17 14:47:04 [Prefetch] {REPORT_LNK}  !double-extension  (loaded by {LOADER})',
    '',
    '==================== SOFTWARE - programs installed, updated or removed recently ====================',
    '--- Installed programs, installed or updated in the last 30 days (Uninstall keys) ---',
    '(line: time [scope] name => program [status], version; publisher; install date; folder; key; hidden <==== flags)',
    '',
    '2026-10-23 13:50:41 [machine] 2 entries from Microsoft Corporation',
    '    programs: Microsoft .NET Runtime - 10.0.13 (x64), Microsoft .NET Host - 10.0.13 (x64)',
    f'    key: HKLM\\...\\{{{DOTNET_GUID}}}; name Microsoft .NET Runtime - 10.0.13 (x64); version 80.52.61384',
    f'    key: HKLM\\...\\{{{DOTNET_HOST_GUID}}}; name Microsoft .NET Host - 10.0.13 (x64); version 80.52.61384',
    '',
    '==================== PERSISTENCE - Run keys, services, scheduled tasks, Startup folders, WMI, with times ====',
    '--- Run keys (all entries) ---',
    '(line: time [kind] entry => program [status], arguments; value <==== flags)',
    '',
    f'2026-11-18 04:50:37 [run] HKU\\Bob\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil\\Name => {EVIL}'
    ' [unsigned], arguments -silent; value Evil\\Name',
    '2026-11-18 04:40:00 [policy-run] HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\Upd'
    ' => C:\\Users\\Bob\\AppData\\Local\\Upd\\upd.exe [gone], value Upd',
    '',
    '--- Services and drivers outside trusted locations ---',
    '(line: time [kind] service => program [status], start <==== flags)',
    '',
    f'2026-11-01 10:00:00 [service] EvilSvc => {SVC_DLL} (svchost DLL) [unsigned], start auto',
    f'    dll: {SVC_DLL} [unsigned]',
    f'2026-11-01 10:05:00 [driver] evildrv => {DRIVER} [unsigned], start boot',
    '',
    '--- Services installed in the last 30 days (System event 7045), except signed programs in trusted locations ---',
    '(line: time [kind] service => program [status], account <==== flags)',
    '',
    '2026-11-01 09:59:00 [service] OtherSvc => C:\\Windows\\System32\\svchost.exe, account LocalSystem',
    f'    dll: {OTHER_DLL} [unsigned]',
    '',
    '--- Scheduled tasks, except Microsoft tasks that run trusted programs ---',
    '(line: created [kind] task => program [status], changed; arguments <==== flags)',
    '',
    f'2026-11-02 08:00:00 [task] \\Evil\\Updater => {EVIL} [unsigned], changed 2026-11-03 08:00:00; arguments /run',
    '',
    '--- Task Scheduler events in the last 30 days ---',
    '(line: time [kind] [event] task => change; by)',
    '',
    '2026-11-04 08:00:00 [task] [141] \\Evil\\Gone => deleted; by Bob',
    '',
    '--- Startup folders (all items) ---',
    '(line: time [kind] item [status] <==== flags)',
    '',
    '2026-09-05 04:53:50 [startup] C:\\Users\\Bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Ok.lnk',
    '    target: C:\\Program Files\\Ok\\ok.exe',
    '',
    '==================== ACCOUNTS - local accounts, Administrators, account events =====================',
    '--- Local accounts ---',
    '(line: account => password set; enabled; admin; last sign-in; full name; sid)',
    '',
    f'Bob => password set 2026-09-24 02:19:07; enabled; admin; sid {MACHINE_SID}-1001',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '(line: file => sha256, signature; version; amcache sha1; md5; size; created; modified)',
    '',
    f'{EVIL} => {EVIL_SHA.upper()}, signature unsigned; md5 {SEARCH_MD5.upper()}; size 123456;'
    ' created 2026-10-21 17:21:05; modified 2026-10-22 08:00:10',
    f'{SVC_DLL} => {SVC_DLL_SHA.upper()}, signature unsigned; md5 {SVC_DLL_MD5.upper()}; size 4096',
    f'{REPORT_LNK} => {LNK_SHA.upper()}',
    f'{LOADER} => {LOADER_SHA.upper()}, signature valid; signer Host Inc.',
    '',
    '==================== LEGEND ========================================================================',
    'Flags (after <====):',
    '    !double-extension           e.g. invoice.pdf.exe',
    '==================== End of log. Scan took 61.0 s ====',
])
LINES_V3 = SPOR_V3.split('\n')

# FRST Search and Shortcut logs of the same machine.
FRST_SEARCH = '\n'.join([
    'Farbar Recovery Scan Tool (x64) Version: 10-11-2026 01',
    'Ran by Bob (12-11-2026 04:54:30)',
    'Running from C:\\Users\\Bob\\Downloads',
    'Boot Mode: Normal',
    '',
    '================== Search Files: "evil" =============',
    '',
    'File:',
    '========',
    EVIL,
    '[2026-10-21 17:21][2026-10-22 08:00] 000123456 ____A () 389700D32DB7ECC74AF1DCF801F05A05 [File not signed]',
    '',
    'Folder:',
    '========',
    '2026-10-21 17:21 - 2026-10-22 08:00 _____ C:\\Users\\Bob\\AppData\\Roaming\\evil',
    '',
    'Registry:',
    '========',
    '',
    '===================== Search result for "evil" ==========',
    '',
    '[HKEY_USERS\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]',
    f'"Evil"="{EVIL} -silent"',
    '',
    '====== End of Search ======',
])

SHORTCUT = '\n'.join([
    'Users shortcut scan result (x64) Version: 01-11-2026',
    'Ran by Bob (01-11-2026 19:15:18)',
    '',
    '==================== Shortcuts =============================',
    '',
    f'Shortcut: C:\\Users\\Bob\\Desktop\\Evil.lnk -> {EVIL} (No File)',
    'Shortcut: C:\\Users\\Bob\\Desktop\\Ok.lnk -> C:\\Program Files\\Ok\\ok.exe (Ok Inc.)',
])

# Spor 0.3.0: a side-loading loader run by a script-runtime launcher. New
# flags (!motw-removed, !sideload, !renamed-program as a hint, !proxy-exec,
# !runtime-loader, !padded), the RUNNING PROCESSES section with "module:"
# lines, "script:" lines of a launcher, the 4688 / SYSMON / PROC sources and
# the DNS categories, as Spor writes them.
DROP_DIR = 'C:\\Users\\Bob\\AppData\\Local\\Temp\\tmp-1-abc'
SIDE_HOST = DROP_DIR + '\\qwXyZaB.exe'
SIDE_DLL = DROP_DIR + '\\providers.dll'
GAME_DIR = 'C:\\Users\\Bob\\Downloads\\Game'
LAUNCHER = GAME_DIR + '\\Setup.exe'
PADDED = GAME_DIR + '\\data\\libpython.rpmc'
SCRIPT_RPA = GAME_DIR + '\\data\\libwin.rpa'
SCRIPT_DOT = GAME_DIR + '\\data\\.VD6'
LURE = 'C:\\Users\\Bob\\Downloads\\Invoice_2026.exe'
CHILD = 'C:\\Users\\Bob\\Apps\\child.exe'
SIDE_HOST_SHA = '5a' * 32
SIDE_DLL_SHA = '5b' * 32
LURE_SHA = '5c' * 32
SIDE_DETAILS = ('loaded by qwXyZaB.exe (signed by Some Developer); proxy DLL, forwards to providersxyzzy.dll'
                ' (original name providers.dll)')

SPOR_V4 = '\n'.join([
    '==================== Spor 0.3.0 - forensic triage log ==============================================',
    'Created:   2026-11-20 03:44:44 UTC (local time 04:44, UTC+01:00)',
    'Computer:  PC-BOB, Windows 10 Pro 22H2, build 19045.3803, 64-bit',
    'Run by:    Bob (administrator)',
    'Times:     UTC',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '(line: time [from] item [status] => details <==== flags)',
    '',
    f'2026-11-20 03:33:38 [timeline NEW TSK] {LAUNCHER} [unsigned] => task \\Run created; script runtime'
    f' Ren\'Py (Python); padded file {PADDED} <==== !runtime-loader',
    f'2026-11-20 03:33:50 [timeline NEW] {SIDE_HOST} => zone 0; side-loads providers.dll'
    ' <==== !motw-removed !renamed-program',
    f'2026-11-20 03:33:50 [timeline NEW] {SIDE_DLL} [unsigned] => zone 0; {SIDE_DETAILS} <==== !motw-removed !sideload',
    f'2026-11-20 03:33:50 [Files] DLL side-loading: {SIDE_DLL} (unsigned) imported by {SIDE_HOST} (signed by Some Developer)',
    '',
    '==================== TIMELINE - last 7 days, oldest first ==========================================',
    '(line: time [sources] file or event [status] => details <==== flags)',
    '',
    f'2026-11-20 03:33:38 [NEW TSK] {LAUNCHER} [unsigned] => task \\Run created; script runtime Ren\'Py (Python);'
    f' padded file {PADDED} <==== !runtime-loader',
    f'    script: {SCRIPT_DOT} => 2026-11-20 03:33:18; 341 bytes; hidden',
    f'    script: {SCRIPT_RPA} => 2026-11-20 03:33:19; 2048 bytes',
    f'2026-11-20 03:33:40 [NEW] {PADDED} => padded: 324 MB of byte 0x00 <==== !padded',
    f'2026-11-20 03:33:50 [NEW] {SIDE_HOST} => zone 0; side-loads providers.dll; original name EventEmitter.pdb'
    ' (from the PDB path) <==== !motw-removed !renamed-program',
    f'2026-11-20 03:33:50 [NEW] {SIDE_DLL} [unsigned] => zone 0; {SIDE_DETAILS} <==== !motw-removed !sideload',
    f'2026-11-20 03:33:52 [SYSMON] C:\\Windows\\System32\\cmd.exe => parent forfiles.exe; command line cmd /c call'
    f' {SIDE_HOST} <==== !lolbin',
    f'2026-11-20 03:33:53 [4688] {SIDE_HOST} => parent cmd.exe; command line {SIDE_HOST} <==== !proxy-exec',
    f'2026-11-20 03:40:00 [NEW] {LURE} => original name putty.exe <==== !renamed-program',
    '',
    '==================== EXECUTION EVIDENCE - PCA, UserAssist, BAM, ShimCache, Compatibility Assistant ====',
    '(No process creation auditing and no Sysmon: program starts only from Prefetch, BAM and Amcache.)',
    '',
    '==================== PERSISTENCE - Run keys, services, scheduled tasks, Startup folders, WMI, with times ====',
    '',
    '--- Run keys (all entries) ---',
    '(line: time [kind] entry => program [status], arguments; value <==== flags)',
    '',
    f'2026-11-20 03:35:00 [run] HKU\\Bob\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Host => {SIDE_HOST},'
    ' value Host <==== !renamed-program',
    f'    module: {SIDE_DLL} [unsigned] => {SIDE_DETAILS} <==== !sideload',
    '',
    '==================== RUNNING PROCESSES - programs running now from user-writable folders, unsigned, or with unsigned modules ====',
    '(84 processes checked.)',
    '(line: started [pid] program [status] => parent; command line <==== flags)',
    '',
    f'2026-11-20 03:33:53 [4321] {SIDE_HOST} => parent cmd.exe (4300) < pid 4200 (exited); command line "{SIDE_HOST}"'
    ' <==== !proxy-exec !renamed-program',
    f'    module: {SIDE_DLL} [unsigned] => {SIDE_DETAILS} <==== !sideload',
    f'2026-11-20 03:41:30 [5557] {CHILD} => parent unsigned.exe (5556) < explorer.exe (100); command line {CHILD} --log [unsigned]',
    '    modules: no access',
    '',
    '==================== NETWORK - data sent per program (SRUM), connections now, DNS cache ============',
    '',
    '--- DNS cache: remote access, tunnel, paste/file sharing, bot API and IP lookup services, victim IDs, abused TLDs ---',
    '(12 names cached)',
    '(line: [category] name)',
    '',
    '[victim ID in name] 0800272a1b3c.example.click',
    '[abused TLD] 0800272a1b3c.example.click',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '(line: file => sha256, signature; version; amcache sha1; md5; size; created; modified)',
    '',
    f'{LURE} => {LURE_SHA}, signature valid; signer Simon Tatham; original name putty.exe',
    f'{SIDE_DLL} => {SIDE_DLL_SHA}, signature unsigned; original name providers.dll',
    f'{SIDE_HOST} => {SIDE_HOST_SHA}, signature valid; signer Some Developer',
    '',
    '==================== LEGEND ========================================================================',
    'Sources (timeline, in brackets after the time):',
    '    PF      Prefetch: program run',
    '    4688    Security event 4688: process created (only with process creation auditing)',
    '    SYSMON  Sysmon event 1: process created',
    '    PROC    process running now (time = when it started)',
    '',
    'Flags (after <====):',
    '    !sideload                   unsigned DLL next to a validly signed program that imports it',
    '    !renamed-program            hint: a signed program under a random-looking or lure name',
    '==================== End of log. Scan took 9.9 s ====',
])
LINES_V4 = SPOR_V4.split('\n')
