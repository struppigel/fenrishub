"""Regression tests for behaviour that drifted between duplicated code paths.

Each case covers a spot where two copies of the same logic had diverged
before they were merged into one shared helper.
"""
from unittest import mock

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from django.urls import reverse

from ..models import ClassificationRule, UploadedLog
from .test_llm_api import ApiTestBase, make_uploaded_log


class UploadDetailAssignRefreshesStatsTests(TestCase):
    """The upload detail page assigns/unassigns through the same service as the list."""

    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='pw')
        self.client.login(username='alice', password='pw')

    def _log(self, **kwargs):
        return UploadedLog.objects.create(
            upload_id='detail-assign', forum_username='u', original_filename='x.txt',
            content='payload', **kwargs,
        )

    def test_assign_from_detail_page_schedules_stats_recalc(self):
        log = self._log()
        with mock.patch('fixlist.views.upload_actions.schedule_analysis_stats_recalc') as recalc:
            self.client.post(reverse('view_uploaded_log', args=[log.upload_id]), {'action': 'assign_to_me'})
        log.refresh_from_db()
        self.assertEqual(log.recipient_user, self.user)
        recalc.assert_called_once()

    def test_unassign_from_detail_page_schedules_stats_recalc(self):
        log = self._log(recipient_user=self.user)
        with mock.patch('fixlist.views.upload_actions.schedule_analysis_stats_recalc') as recalc:
            self.client.post(reverse('view_uploaded_log', args=[log.upload_id]), {'action': 'unassign_to_general'})
        log.refresh_from_db()
        self.assertIsNone(log.recipient_user)
        recalc.assert_called_once()


class RulesListCreateParsesEntriesTests(TestCase):
    """The rules list `create` action fills parsed metadata like the add-rule page."""

    def test_create_from_rules_list_stores_parsed_entry_fields(self):
        User.objects.create_user(username='alice', password='pw')
        self.client.login(username='alice', password='pw')
        line = r'HKLM\...\Run: [Evil] => C:\Users\Bob\AppData\Roaming\evil.exe [12345 2026-01-01] () [File not signed]'
        self.client.post(reverse('rules'), {
            'action': 'create',
            'status': ClassificationRule.STATUS_MALWARE,
            'match_type': ClassificationRule.MATCH_EXACT,
            'source_text': line,
        })
        rule = ClassificationRule.objects.get(source_text=line)
        self.assertTrue(rule.entry_type)
        self.assertTrue(rule.filepath)


class JsonBodyMustBeAnObjectTests(TestCase):
    """Every JSON endpoint answers 400, not 500, to a body that is not an object."""

    def setUp(self):
        self.user = User.objects.create_user(username='mod', password='pw')
        self.user.groups.add(Group.objects.get_or_create(name='moderator')[0])
        self.client.login(username='mod', password='pw')

    def _post(self, url_name, body):
        return self.client.post(reverse(url_name), data=body, content_type='application/json')

    def test_rule_test_api_rejects_non_object(self):
        response = self._post('test_rule_api', '[]')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Invalid JSON payload.')

    def test_log_type_test_api_rejects_non_object(self):
        response = self._post('test_log_type_api', '"text"')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'Invalid JSON payload.')

    def test_analyzer_api_rejects_non_object(self):
        response = self._post('analyze_line_details_api', '[1, 2]')
        self.assertEqual(response.status_code, 400)

    @override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=10)
    def test_centralbox_hash_api_answers_413_when_too_large(self):
        response = self._post('centralbox_hash_check_api', '{"sha256": "' + 'a' * 64 + '"}')
        self.assertEqual(response.status_code, 413)


class ScanDateAllLanguagesTests(TestCase):
    """The scan date is read from the "Ran by" header in every FRST language."""

    def test_german_header(self):
        from ..models import extract_scan_date
        scanned = extract_scan_date('durchgeführt von Bob (Administrator) auf PC (13-11-2026 11:04:20)')
        self.assertEqual((scanned.year, scanned.month, scanned.day, scanned.hour), (2026, 11, 13, 11))

    def test_english_fixlog_header(self):
        from ..models import extract_scan_date
        scanned = extract_scan_date('Ran by USER (05-11-2026 14:29:00) Run:1')
        self.assertEqual((scanned.day, scanned.minute), (5, 29))


class TokenApiParamErrorsTests(ApiTestBase):
    """A malformed query parameter is a 400 naming it, raised from any token API view."""

    def test_non_integer_limit_is_400(self):
        response = self.api_get('api_v1_uploads', data={'limit': 'many'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('limit', response.json()['error'])

    def test_unknown_status_code_is_400(self):
        make_uploaded_log('amber-falcon')
        response = self.api_get('api_v1_upload_analysis', 'amber-falcon', data={'status': 'Z'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('Unknown status code', response.json()['error'])


class StatusHelpersTests(TestCase):
    def test_dominant_status_follows_precedence(self):
        from ..status_types import dominant_status
        self.assertEqual(dominant_status('IPC'), 'P')
        self.assertEqual(dominant_status({'J', 'A'}), 'A')
        self.assertEqual(dominant_status([]), '?')
        self.assertEqual(dominant_status([], default=''), '')

    def test_precedence_rank_puts_unknown_codes_last(self):
        from ..status_types import STATUS_PRECEDENCE, precedence_rank
        self.assertEqual(precedence_rank('B'), 0)
        self.assertEqual(precedence_rank('Z'), len(STATUS_PRECEDENCE))
        self.assertEqual(precedence_rank(''), len(STATUS_PRECEDENCE))

    def test_paint_letters_derive_from_css_classes(self):
        from ..status_types import STATUS_PAINT
        self.assertEqual(STATUS_PAINT['!'], 'w')
        self.assertEqual(STATUS_PAINT['B'], 'b')
        self.assertNotIn('?', STATUS_PAINT)


class CreatedRulesKeepEveryParsedFieldTests(TestCase):
    """create_rules stores every field parse_rule_line derives, attributes included."""

    def test_onemonth_rule_keeps_its_attributes(self):
        from ..views.rules import create_rules
        user = User.objects.create_user(username='alice', password='pw')
        line = r'2026-10-01 10:00 - 2026-10-01 10:00 - 000012345 ___SH C:\Users\Bob\x.exe'
        created, _skipped, error = create_rules(
            user, status=ClassificationRule.STATUS_MALWARE,
            match_type=ClassificationRule.MATCH_PARSED_ENTRY, source_text=line,
        )
        self.assertIsNone(error)
        self.assertEqual(created[0].attributes, '___SH')
        self.assertEqual(ClassificationRule.objects.get(pk=created[0].pk).attributes, '___SH')


class CommonJsStatusTypesTests(TestCase):
    """static/js/common.js mirrors fixlist/status_types.py; the two must not drift."""

    def test_common_js_status_maps_match_status_types(self):
        import re
        from pathlib import Path
        from ..status_types import STATUS_CSS_CLASS, STATUS_LABELS, STATUS_PRECEDENCE
        source = (Path(__file__).resolve().parents[2] / 'static' / 'js' / 'common.js').read_text(encoding='utf-8')

        def js_map(name):
            body = re.search(name + r': \{(.*?)\}', source, re.S).group(1)
            return {key.strip("'"): value for key, value in re.findall(r"('?[^\s:,']+'?): '([^']*)'", body)}

        self.assertEqual(js_map('cssClass'), STATUS_CSS_CLASS)
        self.assertEqual(js_map('label'), STATUS_LABELS)
        precedence = re.search(r"precedence: \[(.*?)\]", source).group(1)
        self.assertEqual(''.join(re.findall(r"'([^']+)'", precedence)), STATUS_PRECEDENCE)
