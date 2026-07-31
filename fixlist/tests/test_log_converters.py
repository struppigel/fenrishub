from django.test import TestCase
from django.urls import reverse

from ..log_converters import convert_log_to_response, parse_securitycheck
from ..models import UploadedLog
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


SECURITYCHECK_LOG = """SecurityCheck by glax24 & Severnyj v1.4.99
Windows 10 Home (x64) Release: 22H2
---------------------------- [ Software ] ----------------------------
Google Chrome v.120.0.6099.110 [color=red]Warning! Download Update[/color] [url=https://www.google.com/chrome/]Download Update[/url]
Extended support has ended [color=red]Warning! Download Update[/color] [url=https://www.microsoft.com/windows]Download Update[/url]
Adobe Flash Player v.32.0.0.465 [b][color=red]Warning! no longer supported[/color][/b] [url=https://example.com/replacement]Replace[/url]
[color=blue][url=https://example.com/office]Microsoft Office[/url][/color]
TeamViewer v.15.49.2 [b][color=red]Warning! Remote desktop software![/color][/b]
Driver Booster v.10.6.0 [b][color=red]Warning! Unwanted software[/color][/b]
Some Toolbar v.1.0 [b]Warning![/b] bundled adware
"""

EXPECTED_REDDIT = """Please update the following software:

* Google Chrome v.120.0.6099.110 | [New update available, download here](https://www.google.com/chrome/)
* Windows 10 Home (x64) 22H2 - Extended support has ended | [New update available, download here](https://www.microsoft.com/windows)
* Adobe Flash Player v.32.0.0.465 | [No longer supported, replace here](https://example.com/replacement)

Please remove the following potentially unwanted programs (PUP):

* **Driver Booster v.10.6.0** - Unwanted software
* **Some Toolbar v.1.0** - bundled adware

Please let me know whether you recognize this remote desktop software:

* TeamViewer v.15.49.2

*Note: If Microsoft Office update errors occur, [reinstall here](https://example.com/office)*"""


class SecurityCheckParserTests(TestCase):

    def test_parses_every_item_type(self):
        results = parse_securitycheck(SECURITYCHECK_LOG)
        self.assertEqual(
            [r['type'] for r in results],
            ['update', 'update', 'eol', 'note', 'remote_desktop', 'unwanted', 'unwanted'],
        )

    def test_extended_support_line_is_prefixed_with_windows_version(self):
        results = parse_securitycheck(SECURITYCHECK_LOG)
        self.assertEqual(
            results[1]['app'],
            'Windows 10 Home (x64) 22H2 - Extended support has ended',
        )

    def test_plain_bold_warning_reason_is_stripped_of_bbcode(self):
        results = parse_securitycheck('Some Toolbar v.1.0 [b]Warning![/b] bundled [i]adware[/i]')
        self.assertEqual(results, [{'type': 'unwanted', 'app': 'Some Toolbar v.1.0', 'reason': 'bundled adware'}])

    def test_download_update_wins_over_generic_warning(self):
        line = 'Java 8 v.8.0.3510 [color=red]Warning! Download Update[/color] [url=https://java.com]Download Update[/url]'
        results = parse_securitycheck(line)
        self.assertEqual(results, [{'type': 'update', 'app': 'Java 8 v.8.0.3510', 'url': 'https://java.com'}])

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
