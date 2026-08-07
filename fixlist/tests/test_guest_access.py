"""Tests for guest-token access to the log analyzer and help page."""

import json

from django.test import TestCase
from django.urls import reverse

from ..models import ClassificationRule, Fixlist, SiteConfig, UploadedLog
from .factories import make_uploaded_log, make_user


GUEST_TOKEN = 'TestGuestToken1234567890abcdef'


def _set_guest_token(token: str = GUEST_TOKEN):
    config = SiteConfig.get_solo()
    config.guest_token = token
    config.save()


class GuestAnalyzerAccessTests(TestCase):
    def test_analyzer_redirects_when_token_unset(self):
        # Default: no token configured.
        response = self.client.get(reverse('log_analyzer') + '?guest=anything')
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_analyzer_redirects_when_token_wrong(self):
        _set_guest_token()
        response = self.client.get(reverse('log_analyzer') + '?guest=wrong-value')
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_analyzer_redirects_when_token_blank(self):
        _set_guest_token('')  # explicitly empty
        response = self.client.get(reverse('log_analyzer') + f'?guest={GUEST_TOKEN}')
        self.assertEqual(response.status_code, 302)

    def test_analyzer_renders_for_valid_guest(self):
        _set_guest_token()
        response = self.client.get(reverse('log_analyzer') + f'?guest={GUEST_TOKEN}')
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        # Write affordances must be hidden.
        self.assertNotIn('id="saveRulesRescanButton"', body)
        self.assertNotIn('id="saveFixlistButton"', body)
        self.assertNotIn('id="toggleLoadUploadButton"', body)
        self.assertNotIn('id="snippetMenu"', body)
        self.assertNotIn('id="uploadSourceRow"', body)
        # Read-only affordances should remain.
        self.assertIn('id="parseButton"', body)
        # Guest token must be exposed to JS for API calls.
        self.assertIn(f'guestToken: "{GUEST_TOKEN}"', body)
        self.assertNotIn('id="speechMenu"', body)

    def test_guest_gets_no_per_helper_upload_link(self):
        """A guest has no username, so {UPLOADLINK_USER} must stay literal."""
        _set_guest_token()
        response = self.client.get(reverse('log_analyzer') + f'?guest={GUEST_TOKEN}')

        self.assertEqual(response.context['upload_link_helper_base'], '')
        self.assertEqual(
            response.context['upload_link_general'],
            'http://testserver' + reverse('upload_log'),
        )

    def test_analyzer_does_not_leak_uploaded_logs_to_guests(self):
        _set_guest_token()
        make_uploaded_log(upload_id='secret-river', original_filename='secret.txt')
        response = self.client.get(reverse('log_analyzer') + f'?guest={GUEST_TOKEN}')
        self.assertNotIn(b'secret-river', response.content)


class GuestAnalyzerApiTests(TestCase):
    def setUp(self):
        _set_guest_token()

    def _post_json(self, name, payload):
        return self.client.post(
            reverse(name) + f'?guest={GUEST_TOKEN}',
            data=json.dumps(payload),
            content_type='application/json',
        )

    def test_analyze_log_api_works_for_guest(self):
        response = self._post_json('analyze_log_api', {'log': 'HKLM\\... => something\n'})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn('lines', body)

    def test_analyze_log_api_does_not_create_uploaded_log_for_guest(self):
        before = UploadedLog.objects.count()
        self._post_json('analyze_log_api', {'log': 'sample line\n'})
        self.assertEqual(UploadedLog.objects.count(), before)

    def test_analyze_log_api_ignores_upload_id_for_guest(self):
        upload = make_uploaded_log(upload_id='ledger-stone')
        original_total = upload.total_line_count
        self._post_json('analyze_log_api', {'log': 'a\nb\nc', 'upload_id': upload.upload_id})
        upload.refresh_from_db()
        self.assertEqual(upload.total_line_count, original_total)

    def test_line_details_api_works_for_guest(self):
        response = self._post_json(
            'analyze_line_details_api',
            {'line': 'HKLM\\Software\\foo => baz', 'status': 'B'},
        )
        self.assertEqual(response.status_code, 200)

    def test_status_update_api_works_for_guest(self):
        response = self._post_json(
            'update_analyzed_line_status_api',
            {
                'line': 'HKLM\\Software\\foo => baz',
                'status': 'B',
                'current_status': '?',
            },
        )
        # Returns 200 on valid parse, 400 on parse failure — both are non-redirects.
        self.assertIn(response.status_code, (200, 400))

    def test_persist_rules_api_blocks_guests(self):
        before = ClassificationRule.objects.count()
        response = self._post_json('persist_pending_rule_changes_api', {'pending_changes': []})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(ClassificationRule.objects.count(), before)

    def test_preview_rules_api_blocks_guests(self):
        response = self._post_json('preview_pending_rule_changes_api', {'pending_changes': []})
        self.assertEqual(response.status_code, 403)

    def test_uploaded_log_content_api_blocks_guests(self):
        upload = make_uploaded_log(upload_id='locked-vault')
        response = self.client.get(
            reverse('uploaded_log_content_api', args=[upload.upload_id])
            + f'?guest={GUEST_TOKEN}'
        )
        self.assertEqual(response.status_code, 403)

    def test_create_fixlist_view_blocks_guests(self):
        before = Fixlist.objects.count()
        response = self.client.get(reverse('create_fixlist') + f'?guest={GUEST_TOKEN}')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Fixlist.objects.count(), before)


class GuestHelpPageTests(TestCase):
    def test_help_redirects_without_token(self):
        _set_guest_token()
        response = self.client.get(reverse('help'))
        self.assertEqual(response.status_code, 302)

    def test_help_renders_with_valid_token(self):
        _set_guest_token()
        response = self.client.get(reverse('help') + f'?guest={GUEST_TOKEN}')
        self.assertEqual(response.status_code, 200)

    def test_help_redirects_with_wrong_token(self):
        _set_guest_token()
        response = self.client.get(reverse('help') + '?guest=wrong')
        self.assertEqual(response.status_code, 302)


class GuestTokenRotationTests(TestCase):
    def test_rotating_token_invalidates_old_link(self):
        _set_guest_token('old-token-' + 'x' * 20)
        response_old = self.client.get(
            reverse('log_analyzer') + '?guest=' + 'old-token-' + 'x' * 20
        )
        self.assertEqual(response_old.status_code, 200)

        _set_guest_token('new-token-' + 'y' * 20)
        response_now = self.client.get(
            reverse('log_analyzer') + '?guest=' + 'old-token-' + 'x' * 20
        )
        self.assertEqual(response_now.status_code, 302)


class AuthenticatedUserUnaffectedTests(TestCase):
    def test_authenticated_user_still_sees_full_analyzer(self):
        _set_guest_token()
        user = make_user(username='alice', password='password123')
        self.client.login(username='alice', password='password123')

        response = self.client.get(reverse('log_analyzer'))

        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn('id="saveRulesRescanButton"', body)
        self.assertIn('id="saveFixlistButton"', body)


class SiteConfigSingletonTests(TestCase):
    def test_save_pins_pk_to_one(self):
        config = SiteConfig.get_solo()
        config.guest_token = 'whatever'
        config.save()
        self.assertEqual(config.pk, 1)
        self.assertEqual(SiteConfig.objects.count(), 1)

    def test_get_solo_creates_when_missing(self):
        SiteConfig.objects.all().delete()
        config = SiteConfig.get_solo()
        self.assertEqual(config.pk, 1)

    def test_current_guest_token_returns_empty_when_missing(self):
        SiteConfig.objects.all().delete()
        self.assertEqual(SiteConfig.current_guest_token(), '')

    def test_generate_guest_token_returns_32_chars(self):
        token = SiteConfig.generate_guest_token()
        self.assertEqual(len(token), 32)
        self.assertTrue(token.isalnum())
