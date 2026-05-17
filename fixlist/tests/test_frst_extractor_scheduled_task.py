"""Tests for the FRST scheduled-task extractors.

Covers the two shapes FRST emits for `Task:` lines:

- **Binary form**: `Task: {GUID} - System32\\Tasks\\... => C:\\...\\binary.exe [size date] (Company)`
- **Command form**: `Task: {GUID} - System32\\Tasks\\... => Command(N): schtasks.exe -> /args /args`

The command form has no real path; before this fix, the binary extractor's
regex backtracked through `Command(1):` and emitted `filepath="Command"`,
which then polluted the filepath bucket and `filepath_highlight` colorisation.
"""

from django.test import TestCase

from ..frst_extractors import (
    extract_any_frst_path,
    extract_frst_scheduled_task,
    extract_frst_scheduled_task_command,
    get_frst_entry,
)


COMMAND_LINE = (
    r"Task: {ECD68699-8BD3-4F53-9BB7-424185C713A4} - "
    r"System32\Tasks\AVAST Software\Gaming mode Task Scheduler recovery => "
    r'Command(1): schtasks.exe -> /Change /TN "\MicrosoftEdgeUpdateTaskMachineCore" /ENABLE'
)

BINARY_LINE = (
    r"Task: {C44E3249-F34C-4259-A841-86818C1FE185} - "
    r"System32\Tasks\GoogleUserPEH\RunPlatformExperienceHelper_Daily => "
    r"C:\Program Files\Google\Chrome\Application\PlatformExperienceHelper"
    r"\platform_experience_helper.exe [3971224 2026-04-18] "
    r"(Google LLC -> Google LLC)"
)


class ScheduledTaskBinaryFormTests(TestCase):
    def test_extracts_filepath_and_company(self):
        entry = extract_frst_scheduled_task(BINARY_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "scheduled_task")
        # Scheduled-task GUIDs are per-system random — intentionally not captured.
        self.assertEqual(entry.clsid, "")
        self.assertEqual(
            entry.filepath,
            r"C:\Program Files\Google\Chrome\Application\PlatformExperienceHelper"
            r"\platform_experience_helper.exe",
        )
        self.assertEqual(entry.filename, "platform_experience_helper.exe")
        self.assertIn("Google LLC", entry.company)

    def test_captures_task_path_into_name(self):
        entry = extract_frst_scheduled_task(BINARY_LINE)
        self.assertEqual(
            entry.name,
            r"System32\Tasks\GoogleUserPEH\RunPlatformExperienceHelper_Daily",
        )

    def test_two_tasks_with_different_paths_but_same_binary_are_unequal(self):
        line_a = (
            r"Task: {CA037D06-C97D-49EF-BBBB-DF2B661CC4E6} - "
            r"System32\Tasks\NetworkDiagnosticService => "
            r"C:\Windows\system32\wscript.exe [181760 2025-05-14] "
            r"(Microsoft Windows -> Microsoft Corporation) -> "
            r'"%LOCALAPPDATA%\DiagnosticsNET\update.vbs"'
        )
        line_b = (
            r"Task: {5EC7F6AD-9140-467C-A0B3-2B87DACB5717} - "
            r"System32\Tasks\SystemCacheMaintenance => "
            r"C:\Windows\system32\wscript.exe [181760 2025-05-14] "
            r"(Microsoft Windows -> Microsoft Corporation) -> "
            r'"%LOCALAPPDATA%\DiagnosticsNET\updater.vbs"'
        )
        a = extract_frst_scheduled_task(line_a)
        b = extract_frst_scheduled_task(line_b)
        self.assertIsNotNone(a)
        self.assertIsNotNone(b)
        self.assertEqual(a.name, r"System32\Tasks\NetworkDiagnosticService")
        self.assertEqual(b.name, r"System32\Tasks\SystemCacheMaintenance")
        self.assertEqual(a.arguments, r'"%LOCALAPPDATA%\DiagnosticsNET\update.vbs"')
        self.assertEqual(b.arguments, r'"%LOCALAPPDATA%\DiagnosticsNET\updater.vbs"')
        # And critically — the two FrstEntry values must NOT compare equal.
        self.assertNotEqual(a, b)

    def test_command_extractor_does_not_match(self):
        self.assertIsNone(extract_frst_scheduled_task_command(BINARY_LINE))

    def test_extract_any_frst_path_returns_binary_path(self):
        self.assertEqual(
            extract_any_frst_path(BINARY_LINE),
            r"C:\Program Files\Google\Chrome\Application\PlatformExperienceHelper"
            r"\platform_experience_helper.exe",
        )


class ScheduledTaskEmptyCompanyTests(TestCase):
    """Lines where the (company) parens are empty — typical for unsigned binaries
    in Program Files (x86). Pre-fix, the binary regex truncated filepath at the
    first `(` of `(x86)` and produced garbage company; now both parse correctly."""

    ASUS_LINE = (
        r"Task: {D7B60407-4E11-47AA-9C00-CC0F414753C6} - "
        r"System32\Tasks\ASUS Live Update1 => "
        r"C:\Program Files (x86)\ASUS\ASUS Live Update\UpdateChecker.exe "
        r"[17920 2016-08-01] () [File not signed]"
    )

    def test_parens_in_filepath_do_not_split_the_path(self):
        entry = extract_frst_scheduled_task(self.ASUS_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.filepath,
            r"C:\Program Files (x86)\ASUS\ASUS Live Update\UpdateChecker.exe",
        )
        self.assertEqual(entry.filename, "UpdateChecker.exe")

    def test_empty_company_parses_as_empty_string(self):
        entry = extract_frst_scheduled_task(self.ASUS_LINE)
        self.assertEqual(entry.company, "")

    def test_file_not_signed_flag_preserved(self):
        entry = extract_frst_scheduled_task(self.ASUS_LINE)
        self.assertTrue(entry.file_not_signed)

    def test_extract_any_frst_path_returns_full_path(self):
        self.assertEqual(
            extract_any_frst_path(self.ASUS_LINE),
            r"C:\Program Files (x86)\ASUS\ASUS Live Update\UpdateChecker.exe",
        )

    def test_empty_company_no_trailing_marker_still_parses(self):
        line = (
            r"Task: {B615BA87-24F8-40AA-BD14-A2B69D2F3E06} - "
            r"System32\Tasks\water => E:\Emoji\blinkdagger.mp3 "
            r"[62592 2024-10-20] () [File not signed]"
        )
        entry = extract_frst_scheduled_task(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.company, "")
        self.assertEqual(entry.date, "62592 2024-10-20")


class ScheduledTaskTrailingContentTests(TestCase):
    """Lines with content after (company): trailing args (` -> ...`), `[File not signed]`,
    `<==== ATTENTION`, or a parenthesized comment. Pre-fix, the greedy `\\((.+)\\)` would
    grab the wrong parens; the non-greedy fix anchors company to the first `(...)` after
    `[date]`."""

    def test_trailing_args_after_company_ignored(self):
        line = (
            r"Task: {58FFDC81-DD4D-40CF-8BC5-157A4DA81EFF} - "
            r"System32\Tasks\GameSettingsDLC => "
            r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe "
            r"[455680 2024-02-23] (Microsoft Windows -> Microsoft Corporation) "
            r'-> -ExecutionPolicy Bypass -WindowStyle Hidden -File "%LOCALAPPDATA%\UpdatesWin\updater.ps1"'
        )
        entry = extract_frst_scheduled_task(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.filepath, r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe")
        self.assertEqual(entry.company, "Microsoft Windows -> Microsoft Corporation")

    def test_x86_in_filepath_does_not_become_company(self):
        line = (
            r"Task: {98652CD2-EAED-4F42-AF89-C099BB801096} - "
            r"System32\Tasks\Lenovo\LenovoNowLauncher => "
            r"C:\Program Files (x86)\Lenovo\LenovoNow\x86\LenovoNow.exe "
            r"[471008 2025-07-22] (Lenovo -> Lenovo)"
        )
        entry = extract_frst_scheduled_task(line)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.filepath, r"C:\Program Files (x86)\Lenovo\LenovoNow\x86\LenovoNow.exe"
        )
        self.assertEqual(entry.company, "Lenovo -> Lenovo")

    def test_trailing_parenthesized_comment_does_not_become_company(self):
        line = (
            r"Task: {889624BF-955B-47F6-9CE3-0DE1D130FB25} - "
            r"System32\Tasks\Mozilla\Firefox Background Update A45DC619E7F6FE0D => "
            r"C:\Users\garqu\AppData\Local\Mozilla Firefox\firefox.exe "
            r"[712832 2025-08-28] (Mozilla Corporation -> Mozilla Corporation) "
            r"-> --backgroundtask background (the data entry has 6 more characters)."
        )
        entry = extract_frst_scheduled_task(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.company, "Mozilla Corporation -> Mozilla Corporation")


class ScheduledTaskNoMetadataTests(TestCase):
    """Lines without the `[size date] (company)` block — e.g. Opera/iTop autoupdate
    tasks that go straight from filepath to `-> args`. The loosened regex must still
    extract the filepath in those cases."""

    def test_opera_autoupdate_filepath_extracted(self):
        line = (
            r"Task: {BA8A74A5-7674-47BD-AACF-3014A7EC43FC} - "
            r"System32\Tasks\Opera scheduled assistant Autoupdate 1587829581 => "
            r"C:\Users\MZM\AppData\Local\Programs\Opera\launcher.exe "
            r"-> --scheduledautoupdate --component-name=assistant "
            r'--component-path="C:\Users\MZM\AppData\Local\Programs\Opera\assistant" $(Arg0)'
        )
        entry = extract_frst_scheduled_task(line)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.filepath,
            r"C:\Users\username\AppData\Local\Programs\Opera\launcher.exe",
        )
        self.assertEqual(entry.date, "")
        self.assertEqual(entry.company, "")

    def test_quoted_filepath_strips_surrounding_quotes(self):
        line = (
            r"Task: {0CA589B3-E2EC-4AE4-BDC1-B6733A344F4E} - "
            r"System32\Tasks\iTop XMS Task (One-Time) => "
            r'"C:\Program Files (x86)\iTop VPN\Pub\itopxmsp23.exe"  -> '
            r"C:\Program Files (x86)\iTop VPN\Pub\\/xms"
        )
        entry = extract_frst_scheduled_task(line)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.filepath,
            r"C:\Program Files (x86)\iTop VPN\Pub\itopxmsp23.exe",
        )
        self.assertEqual(entry.filename, "itopxmsp23.exe")
        self.assertEqual(entry.company, "")


class ScheduledTaskNestedParensTests(TestCase):
    """Companies whose own text contains `(...)` like `Intel(R)` or `Lenovo (Beijing)`
    must be captured in full. The OLD non-greedy `\\(([^\\)]*)\\)` regex stopped at
    the first nested `)` and produced truncations like `Intel(R`."""

    def test_intel_r_with_inner_parens(self):
        line = (
            r"Task: {16C4C389-17C9-4FF1-97AD-3767C12CF9D4} - "
            r"System32\Tasks\Intel\Thunderbolt\Start Thunderbolt application on login "
            r"if service is up => "
            r"C:\Program Files (x86)\Intel\Thunderbolt Software\\ConditionalAppStarter.exe "
            r"[226008 2018-12-25] (Intel(R) Client Connectivity Division SW -> Intel Corporation)"
        )
        entry = extract_frst_scheduled_task(line)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.company, "Intel(R) Client Connectivity Division SW -> Intel Corporation"
        )

    def test_lenovo_beijing_with_inner_parens(self):
        line = (
            r"Task: {6122ABCD-0000-0000-0000-000000000000} - "
            r"System32\Tasks\Lenovo\PCManager => "
            r"C:\Program Files (x86)\Lenovo\PCManager\5.1.150.11202\LenovoPcManagerService.exe "
            r"[1450912 2025-11-20] (Lenovo (Beijing) Limited -> Lenovo Corporation)"
        )
        entry = extract_frst_scheduled_task(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.company, "Lenovo (Beijing) Limited -> Lenovo Corporation")


class ScheduledTaskNoFileMarkerTests(TestCase):
    """`(No File)` is an FRST marker and `<==== ATTENTION` is its malware highlight.
    Neither belongs in the captured filepath."""

    def test_no_file_marker_excluded_from_filepath(self):
        line = (
            r"Task: {9CD48070-557E-4DF1-93B2-08526FD35873} - "
            r"System32\Tasks\Cr_286461593 => "
            r"C:\Users\mandy\AppData\Local\Temp\tmpf286461593\KB.14.782.4343.exe  "
            r"(No File) <==== ATTENTION"
        )
        entry = extract_frst_scheduled_task(line)
        self.assertIsNotNone(entry)
        self.assertEqual(
            entry.filepath,
            r"C:\Users\username\AppData\Local\Temp\tmpf286461593\KB.14.782.4343.exe",
        )
        self.assertNotIn("No File", entry.filepath)
        self.assertNotIn("<====", entry.filepath)


class ScheduledTaskTriggeredFormTests(TestCase):
    """`Task: {GUID} - <path> => {OTHER-GUID}` lines are triggered-task pointers
    (one task launches another), not binary launches. The regex must refuse to
    treat `{OTHER-GUID}` as a filepath."""

    LINE = (
        r"Task: {D2E8BEB4-6AC1-4881-8DAD-33150CE72101} - "
        r"System32\Tasks\Microsoft\Windows\WaaSMedic\PerformRemediation => "
        r"{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}"
    )

    def test_triggered_form_does_not_match_binary_extractor(self):
        self.assertIsNone(extract_frst_scheduled_task(self.LINE))

    def test_triggered_form_yields_no_path(self):
        self.assertIsNone(extract_any_frst_path(self.LINE))


class ScheduledTaskCommandFormTests(TestCase):
    def test_extracts_full_command_into_arguments(self):
        entry = extract_frst_scheduled_task_command(COMMAND_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "scheduled_task_command")
        self.assertEqual(entry.clsid, "")
        self.assertEqual(entry.filepath, "")
        self.assertEqual(entry.filename, "")
        self.assertEqual(
            entry.name,
            r"System32\Tasks\AVAST Software\Gaming mode Task Scheduler recovery",
        )
        self.assertEqual(
            entry.arguments,
            r'schtasks.exe -> /Change /TN "\MicrosoftEdgeUpdateTaskMachineCore" /ENABLE',
        )

    def test_binary_extractor_does_not_match(self):
        self.assertIsNone(extract_frst_scheduled_task(COMMAND_LINE))

    def test_get_frst_entry_returns_command_entry(self):
        entry = get_frst_entry(COMMAND_LINE)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.entry_type, "scheduled_task_command")
        self.assertEqual(entry.filepath, "")

    def test_extract_any_frst_path_returns_none(self):
        self.assertIsNone(extract_any_frst_path(COMMAND_LINE))
