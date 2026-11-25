"""Spor 0.9.0 log shapes (spor_log.py, correlations): the PERSISTENCE sub-section
"Reset and setup hooks" (ResetConfig.xml with its phase:/script: sub-lines, a
reset script with command: lines, a task copy, a .reg file, an answer file with
a decoded: command), NETWORK proxy settings, DEFENDER root certificates and
hidden Settings pages, browser extensions not from a store; the new flags'
tiers. Lines modelled on WEEVILPROXY (WithSecure, May 2026)."""

from django.test import SimpleTestCase

from .. import spor_log
from ..correlations.spor_self import self_links, self_status

OEM = 'C:\\Recovery\\OEM'
CMD = OEM + '\\Fix.cmd'
TASK = OEM + '\\MicrosoftHealthCheckerV1-atwbpi'
NODE = 'C:\\Windows\\System32\\MicrosoftHealthCheckerV1-atwbpi\\node.exe'

SPOR = '\n'.join([
    '==================== Spor 0.9.0 - forensic triage log ==============================================',
    'Created:   2026-11-26 10:00:00 UTC (local time 11:00, UTC+01:00)',
    'Users:     Ann',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '',
    f'2026-11-10 09:00:58 [Persistence] reset script: {CMD} => restores a scheduled task or the machine ID; written in the time window <==== !reset-hook',
    f'    command: copy /y "{TASK}" "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\Guard\\MicrosoftHealthCheckerV1-atwbpi"',
    '2026-11-10 09:00:00 [Network] proxy (user Ann): 127.0.0.1:57352 => listening: ' + NODE + ' (pid 8728) <==== !local-proxy',
    '2026-05-19 00:12:00 [Defender] root certificate (machine): CN=WeevilRoot => thumbprint AB12; valid 2026-05-19 to 2036-05-19 <==== !custom-root',
    '2026-05-19 00:10:00 [Defender] Settings pages hidden (machine): hide:network-proxy => hides network-proxy <==== !settings-hidden',
    '',
    '==================== PERSISTENCE - Run keys, services, scheduled tasks, Startup folders, WMI, with times ====',
    '--- Reset and setup hooks ---',
    '(line: changed [kind] file [status] <==== flags)',
    '',
    f'2026-11-10 09:00:58 [reset config] {OEM}\\ResetConfig.xml <==== !reset-hook',
    '    phase: BasicReset_AfterImageApply',
    f'    script: {CMD}',
    '    phase: FactoryReset_AfterImageApply',
    f'    script: {CMD}',
    '    why: written in the time window',
    f'2026-11-10 09:00:58 [reset script] {CMD} <==== !reset-hook',
    f'    command: copy /y "{TASK}" "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\Guard\\MicrosoftHealthCheckerV1-atwbpi"',
    f'    command: reg import "{OEM}\\task.reg"',
    '    why: restores a scheduled task or the machine ID; written in the time window',
    f'2026-11-10 09:00:58 [task copy] {TASK} <==== !reset-hook',
    '    command: powershell -cOmma Add-MpPreference -ExclusionPath (Get-Location) -Force',
    '2022-03-26 07:27:15 [reset script] C:\\Recovery\\OEM\\AfterImageApply_BDB0C1E8-6951-46C4-AB7F-C07B29F462FD.cmd <==== !reset-config',
    '    command: copy C:\\Recovery\\OEM\\Unattend.xml C:\\Windows\\Panther\\Unattend.xml',
    '2026-11-12 08:00:00 [answer file] E:\\autounattend.xml <==== !reset-hook',
    '    command: powershell -nop -enc UgBlAGcA',
    '    decoded: Register-ScheduledTask -TaskName X',
    '    info: \\sources\\boot.wim on this drive: Windows Setup reads this answer file',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '',
    f'{CMD} => {"11" * 32}',
    f'{NODE} => {"22" * 32}, signature valid; signer OpenJS Foundation',
    '',
    '==================== End of log. Scan took 9.9 s ====',
])
LINES = SPOR.split('\n')


def no_of(prefix, start=0):
    return next(no for no, text in enumerate(LINES, start=1) if no > start and text.strip().startswith(prefix))


def linked(links, no):
    return {entry['line_no']: entry.get('match') for entry in links.get(str(no), ())}


class TierTests(SimpleTestCase):
    def test_the_new_flags_have_their_tiers(self):
        for flag in ('!reset-hook', '!new-in-windows', '!local-proxy', '!root-cert', '!settings-hidden', '!unpacked-extension'):
            self.assertEqual(spor_log.flag_tier(flag), 'strong', flag)
        for flag in ('!reset-config', '!proxy', '!dev-mode', '!custom-root', '!settings-changed'):
            self.assertEqual(spor_log.flag_tier(flag), 'info', flag)


class HookTests(SimpleTestCase):
    def setUp(self):
        self.links = self_links('spor', SPOR)

    def test_a_hook_line_is_about_its_file(self):
        mentions = {(m.line_no, m.role): m for m in spor_log.iter_mentions(LINES)}
        script_line = no_of(f'2026-11-10 09:00:58 [reset script] {CMD}')
        self.assertEqual(mentions[(script_line, 'item')].path, CMD)
        self.assertEqual(mentions[(script_line, 'item')].flags, ['!reset-hook'])
        # ResetConfig.xml's script: sub-lines name the script it runs
        config = no_of(f'2026-11-10 09:00:58 [reset config]')
        scripts = [m for m in spor_log.iter_mentions(LINES) if m.parent_line == config and m.role == 'script']
        self.assertEqual({m.path for m in scripts}, {CMD})

    def test_the_script_links_its_config_summary_and_files_line(self):
        script_line = no_of(f'2026-11-10 09:00:58 [reset script] {CMD}')
        found = linked(self.links, script_line)
        self.assertIn(no_of(f'{CMD} => '), found)
        self.assertIn(no_of('2026-11-10 09:00:58 [Persistence] reset script'), found)
        self.assertIn(no_of(f'script: {CMD}'), found)
        self.assertEqual(self_status(self.links[str(script_line)]), '!')

    def test_a_pc_makers_script_is_context(self):
        no = no_of('2022-03-26 07:27:15 [reset script]')
        [item] = [m for m in spor_log.iter_mentions(LINES) if m.line_no == no and m.role == 'item']
        self.assertEqual(spor_log.worst_tier(item.flags), 'info')

    def test_the_answer_files_decoded_command_is_extra(self):
        no = no_of('2026-11-12 08:00:00 [answer file]')
        [item] = [m for m in spor_log.iter_mentions(LINES) if m.line_no == no and m.role == 'item']
        self.assertIn(['decoded', 'Register-ScheduledTask -TaskName X'], item.extra)

    def test_the_proxy_finding_links_the_listening_program(self):
        no = no_of('2026-11-10 09:00:00 [Network] proxy')
        self.assertIn(no_of(f'{NODE} => '), linked(self.links, no))


PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
WMI_SPOR = '\n'.join([
    '==================== Spor 0.9.0 - forensic triage log ==============================================',
    'Created:   2026-11-26 10:00:00 UTC (local time 11:00, UTC+01:00)',
    '',
    '==================== SUMMARY - flagged items; details in the sections below ========================',
    '',
    f'2026-11-10 09:00:00 [Persistence] WMI consumer: Updater => CommandLineEventConsumer runs {PS} <==== !suspicious',
    '',
    '==================== FILES - SHA256, signature and version of the files as they are on disk now ====',
    '',
    f'{PS} => {"33" * 32}, signature valid; signer OpenJS Foundation',
    '',
    '==================== End of log. Scan took 9.9 s ====',
])


class DetailsKeyTests(SimpleTestCase):
    def test_a_path_in_the_details_is_not_the_findings_file(self):
        # Only "listening:" names the finding's program; a WMI command's powershell.exe is not what the line is about.
        lines = WMI_SPOR.split('\n')
        summary = next(no for no, text in enumerate(lines, start=1) if '[Persistence] WMI consumer' in text)
        files = next(no for no, text in enumerate(lines, start=1) if text.startswith(PS + ' => '))
        links = self_links('spor', WMI_SPOR)
        self.assertNotIn(files, {entry['line_no'] for entry in links.get(str(summary), ())})
