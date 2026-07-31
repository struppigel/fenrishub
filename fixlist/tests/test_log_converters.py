from django.test import TestCase
from django.urls import reverse

from ..log_converters import convert_log_to_response, parse_securitycheck
from ..models import UploadedLog
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


SECURITYCHECK_LOG = """SecurityCheck by glax24 & Severnyj v1.4.99
Windows 10 Home (x64) Release: 22H2
---------------------------- [ Software ] ----------------------------
Google Chrome v.120.0.6099.110 [color=red]Warning! [url=https://www.google.com/chrome/]Download Update[/url][/color]
Extended support has ended [color=red]Warning! [url=https://www.microsoft.com/windows]Download Update[/url][/color]
Adobe Flash Player v.32.0.0.465 [b][color=red]Warning! no longer supported[/color][/b] [url=https://example.com/replacement]Replace[/url]
[color=blue]If [url=https://example.com/office]Microsoft Office[/url] update errors occur, reinstall it[/color]
TeamViewer v.15.49.2 [b][color=red]Warning! Remote desktop software![/color][/b]
AnyDesk v.7.0.10 [b][color=red]Attention! Remote access program![/color][/b] [color=red]Warning! Unwanted software[/color]
Driver Booster v.10.6.0 [b][color=red]Warning! Unwanted software[/color][/b]
[color=blue]Bundled with adware installers[/color]
Some Toolbar v.1.0 [b]Warning![/b] bundled adware
Ask Toolbar v.1.2 [b][color=red]It is recommended to uninstall[/color][/b]
User Account Control [color=red][b]disabled[/b][/color]
[color=red][b]Never check for updates[/b][/color]
"""

EXPECTED_REDDIT = """**Please update the following software:**
* **Google Chrome v.120.0.6099.110** | [New update available, download here](https://www.google.com/chrome/)
* **Windows 10 Home (x64) 22H2 - Extended support has ended** | [New update available, download here](https://www.microsoft.com/windows)

**Please remove the following potentially unwanted programs (PUP):**
* **Adobe Flash Player v.32.0.0.465** - No longer supported - please uninstall it and [replace it here](https://example.com/replacement)
* **AnyDesk v.7.0.10** - Unwanted software
* **Driver Booster v.10.6.0** - Unwanted software (Bundled with adware installers)
* **Some Toolbar v.1.0** - bundled adware
* **Ask Toolbar v.1.2** - It is recommended to uninstall

**Please let me know whether you recognize this remote desktop software (if not, uninstall it):**
* **TeamViewer v.15.49.2**
* **AnyDesk v.7.0.10**

**Please check the following Windows settings:**
* **User Account Control** - disabled
* **Never check for updates**

*Note: If Microsoft Office update errors occur, [reinstall here](https://example.com/office)*"""


class SecurityCheckParserTests(TestCase):

    def test_parses_every_item_type(self):
        results = parse_securitycheck(SECURITYCHECK_LOG)
        self.assertEqual(
            [r['type'] for r in results],
            [
                'update', 'update', 'eol', 'note', 'remote_desktop',
                'remote_desktop', 'unwanted', 'unwanted', 'unwanted', 'unwanted',
                'setting', 'setting',
            ],
        )

    def test_extended_support_line_is_prefixed_with_windows_version(self):
        results = parse_securitycheck(SECURITYCHECK_LOG)
        self.assertEqual(
            results[1]['app'],
            'Windows 10 Home (x64) 22H2 - Extended support has ended',
        )

    def test_end_of_life_keeps_its_replacement_link(self):
        results = parse_securitycheck(SECURITYCHECK_LOG)
        self.assertEqual(
            results[2],
            {'type': 'eol', 'app': 'Adobe Flash Player v.32.0.0.465',
             'url': 'https://example.com/replacement'},
        )

    def test_end_of_life_without_replacement_link_has_no_url(self):
        results = parse_securitycheck('Adobe Reader v.11 [b][color=red]Внимание! больше не поддерживается[/color][/b]')
        self.assertEqual(
            results,
            [{'type': 'eol', 'app': 'Adobe Reader v.11', 'url': None}],
        )

    def test_line_with_two_warnings_yields_one_entry_per_marker(self):
        results = parse_securitycheck(SECURITYCHECK_LOG)
        self.assertEqual(results[5], {'type': 'remote_desktop', 'app': 'AnyDesk v.7.0.10'})
        self.assertEqual(
            results[6],
            {'type': 'unwanted', 'app': 'AnyDesk v.7.0.10', 'reason': 'Unwanted software'},
        )

    def test_blue_line_without_a_link_becomes_a_hint_on_the_previous_entry(self):
        results = parse_securitycheck(SECURITYCHECK_LOG)
        self.assertEqual(results[7]['app'], 'Driver Booster v.10.6.0')
        self.assertEqual(results[7]['hint'], 'Bundled with adware installers')

    def test_windows_settings_are_parsed_labelled_and_standalone(self):
        results = parse_securitycheck(SECURITYCHECK_LOG)
        self.assertEqual(
            results[-2],
            {'type': 'setting', 'setting': 'User Account Control', 'state': 'disabled'},
        )
        self.assertEqual(
            results[-1],
            {'type': 'setting', 'setting': 'Never check for updates', 'state': ''},
        )

    def test_download_label_is_not_reported_as_a_reason(self):
        line = 'Java 8 v.8.0.3510 [color=red]Warning! [url=https://java.com]Download Update[/url][/color]'
        self.assertEqual(
            parse_securitycheck(line),
            [{'type': 'update', 'app': 'Java 8 v.8.0.3510', 'url': 'https://java.com'}],
        )

    def test_uninstall_recommendation_without_warning_marker_is_unwanted(self):
        line = 'Ask Toolbar v.1.2 [b][color=red]Uninstallation recommended[/color][/b]'
        self.assertEqual(
            parse_securitycheck(line),
            [{'type': 'unwanted', 'app': 'Ask Toolbar v.1.2', 'reason': 'Uninstallation recommended'}],
        )

    def test_real_log_line_shapes(self):
        """Line shapes taken verbatim from a v.1.4.0.58 log."""
        log = (
            'User Account Control [b]enabled[/b] (Level 3)\n'
            'Windows Update (wuauserv) - The service has stopped\n'
            'Steam v.2.10.91.91\n'
            'WinRAR 6.11 (64-bit) v.6.11.0 [color=red][b]Warning! '
            '[url=https://www.rarlab.com/download.htm]Download Update[/url][/b][/color]\n'
            '[color=blue][b]^Please run Acrobat Reader DC and go Help - Check for updates...^[/b][/color]\n'
            'Chrome Remote Desktop Host v.151.0.7922.13 [b][color=red]Warning! Remote desktop software![/color][/b].\n'
        )
        results = parse_securitycheck(log)
        self.assertEqual(
            results,
            [
                {'type': 'update', 'app': 'WinRAR 6.11 (64-bit) v.6.11.0',
                 'url': 'https://www.rarlab.com/download.htm',
                 'hint': 'Please run Acrobat Reader DC and go Help - Check for updates'},
                {'type': 'remote_desktop', 'app': 'Chrome Remote Desktop Host v.151.0.7922.13'},
            ],
        )

    def test_log_without_findings_yields_nothing(self):
        self.assertEqual(parse_securitycheck('SecurityCheck by glax24\nAll good here.\n'), [])


class ConvertLogToResponseTests(TestCase):

    def test_securitycheck_log_renders_reddit_markdown(self):
        self.assertEqual(convert_log_to_response('SecurityCheck', SECURITYCHECK_LOG), EXPECTED_REDDIT)

    def test_other_log_types_are_not_converted(self):
        self.assertEqual(convert_log_to_response('FRST', SECURITYCHECK_LOG), '')

    def test_securitycheck_log_without_findings_returns_empty(self):
        self.assertEqual(convert_log_to_response('SecurityCheck', 'SecurityCheck by glax24\n'), '')


class CopyResponseButtonTests(UploadedLogSharedSetupMixin, TestCase):

    def _create_log(self, upload_id, log_type, content):
        return UploadedLog.objects.create(
            upload_id=upload_id,
            forum_username='forum_user',
            original_filename='SecurityCheck.txt',
            log_type=log_type,
            content=content,
        )

    def test_button_shown_for_securitycheck_log(self):
        log = self._create_log('secure-river', 'SecurityCheck', SECURITYCHECK_LOG)
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[log.upload_id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '>copy parsed response<')
        self.assertContains(response, 'id="convertedResponse"')
        self.assertEqual(response.context['converted_response'], EXPECTED_REDDIT)

    def test_button_hidden_for_other_log_types(self):
        log = self._create_log('frst-river', 'FRST', SECURITYCHECK_LOG)
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[log.upload_id]))
        self.assertNotContains(response, '>copy parsed response<')

    def test_button_hidden_when_securitycheck_log_has_no_findings(self):
        log = self._create_log('empty-river', 'SecurityCheck', 'SecurityCheck by glax24\n')
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('view_uploaded_log', args=[log.upload_id]))
        self.assertNotContains(response, '>copy parsed response<')
