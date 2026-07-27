"""Tests for the log content search page and its zip download."""

import io
import zipfile

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .. import analyzer
from ..models import UploadedLog
from ..views import log_search
from .uploaded_log_shared_setup import UploadedLogSharedSetupMixin


class LogSearchViewTests(UploadedLogSharedSetupMixin, TestCase):

    def _create_log(self, upload_id, content, **kwargs):
        defaults = {
            'forum_username': 'forum_user',
            'original_filename': f'{upload_id}.txt',
            'recipient_user': self.user,
        }
        defaults.update(kwargs)
        return UploadedLog.objects.create(upload_id=upload_id, content=content, **defaults)

    def _login(self):
        self.client.login(username='alice', password='password123')

    def test_log_search_requires_login(self):
        response = self.client.get(reverse('log_search'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)

    def test_empty_query_renders_idle_state(self):
        self._create_log('idle-log', 'C:\\Windows\\evil.exe')
        self._login()

        response = self.client.get(reverse('log_search'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['results'], [])
        self.assertEqual(response.context['match_count'], 0)
        self.assertContains(response, 'enter a search term')

    def test_substring_search_is_case_insensitive_and_excludes_non_matches(self):
        self._create_log('hit-log', 'line one\nC:\\Windows\\EVIL.exe\nline three')
        self._create_log('miss-log', 'nothing interesting here')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'evil.exe'})

        self.assertEqual(response.context['match_count'], 1)
        self.assertContains(response, 'hit-log')
        self.assertNotContains(response, 'miss-log')

    def test_case_sensitive_substring_search_excludes_other_casings(self):
        self._create_log('exact-case', 'found Malware.Generic here')
        self._create_log('other-case', 'found MALWARE.GENERIC here')
        self._login()

        response = self.client.get(
            reverse('log_search'), {'q': 'Malware.Generic', 'case': '1'}
        )

        self.assertTrue(response.context['case_sensitive'])
        self.assertEqual(response.context['match_count'], 1)
        self.assertContains(response, 'exact-case')
        self.assertNotContains(response, 'other-case')

    def test_case_sensitive_regex_search_excludes_other_casings(self):
        self._create_log('regex-exact', 'Service: WuauServ2 running')
        self._create_log('regex-other', 'Service: wuauserv2 running')
        self._login()

        response = self.client.get(
            reverse('log_search'), {'q': 'WuauServ[0-9]', 'regex': '1', 'case': '1'}
        )

        self.assertIsNone(response.context['search_error'])
        self.assertEqual(response.context['match_count'], 1)
        self.assertContains(response, 'regex-exact')
        self.assertNotContains(response, 'regex-other')

    def test_log_type_filter_narrows_results(self):
        self._create_log('frst-log', 'shared indicator', log_type='FRST')
        self._create_log('addition-log', 'shared indicator', log_type='Addition')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'indicator', 'type': 'Addition'})

        self.assertEqual(response.context['log_type_filter'], 'Addition')
        self.assertEqual(response.context['match_count'], 1)
        self.assertContains(response, 'addition-log')
        self.assertNotContains(response, 'frst-log')

    def test_log_type_filter_applies_in_regex_mode(self):
        self._create_log('frst-regex', 'wuauserv2 running', log_type='FRST')
        self._create_log('addition-regex', 'wuauserv2 running', log_type='Addition')
        self._login()

        response = self.client.get(
            reverse('log_search'), {'q': 'wuauserv[0-9]', 'regex': '1', 'type': 'FRST'}
        )

        self.assertEqual(response.context['match_count'], 1)
        self.assertContains(response, 'frst-regex')

    def test_unknown_log_type_filter_is_ignored(self):
        self._create_log('typed-log', 'shared indicator', log_type='FRST')
        self._login()

        response = self.client.get(
            reverse('log_search'), {'q': 'indicator', 'type': 'NotARealType'}
        )

        self.assertEqual(response.context['log_type_filter'], '')
        self.assertEqual(response.context['match_count'], 1)

    def test_log_type_options_come_from_stored_logs(self):
        self._create_log('frst-option', 'content', log_type='FRST&Addition')
        self._login()

        response = self.client.get(reverse('log_search'))

        self.assertIn('FRST&Addition', response.context['log_types'])
        self.assertContains(response, 'all log types')

    def test_repeated_search_reuses_cached_result_ids(self):
        self._create_log('cached-log', 'cached indicator')
        self._login()

        first = self.client.get(reverse('log_search'), {'q': 'cached indicator'})
        self.assertEqual(first.context['match_count'], 1)

        # A log added after the first search stays out of the cached result set.
        self._create_log('later-log', 'cached indicator')
        second = self.client.get(reverse('log_search'), {'q': 'cached indicator'})

        self.assertEqual(second.context['match_count'], 1)
        self.assertContains(second, 'cached-log')
        self.assertNotContains(second, 'later-log')

    def test_cached_result_ids_never_resurrect_a_trashed_log(self):
        keeper = self._create_log('keeper-log', 'trash indicator')
        goner = self._create_log('goner-log', 'trash indicator')
        self._login()

        first = self.client.get(reverse('log_search'), {'q': 'trash indicator'})
        self.assertEqual(first.context['match_count'], 2)

        goner.deleted_at = timezone.now()
        goner.save(update_fields=['deleted_at'])
        second = self.client.get(reverse('log_search'), {'q': 'trash indicator'})

        self.assertContains(second, keeper.upload_id)
        self.assertNotContains(second, 'goner-log')

    def test_results_render_selection_checkboxes_and_download_buttons(self):
        self._create_log('tickable-log', 'shared indicator')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'indicator'})

        self.assertContains(response, 'name="selected_upload_ids" value="tickable-log"')
        self.assertContains(response, '>download selected</button>')
        self.assertContains(response, '>download all</button>')

    def test_case_toggle_is_carried_into_pagination_and_download_links(self):
        self._create_log('carry-log', 'Indicator')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'Indicator', 'case': '1'})

        self.assertIn('case=1', response.context['pagination_query'])
        self.assertIn('case=1', response.context['download_query'])

    def test_preview_reports_first_matching_line_and_number(self):
        self._create_log('preview-log', 'alpha\nbeta target beta\ngamma target gamma')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'target'})

        result = response.context['results'][0]
        self.assertEqual(result['line_number'], 2)
        self.assertEqual(result['before'], 'beta ')
        self.assertEqual(result['hit'], 'target')
        self.assertEqual(result['after'], ' beta')

    def test_preview_handles_windows_line_endings(self):
        self._create_log('crlf-log', 'alpha\r\nbeta target\r\ngamma')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'target'})

        result = response.context['results'][0]
        self.assertEqual(result['line_number'], 2)
        self.assertEqual(result['after'], '')

    def test_search_covers_other_users_channels(self):
        self._create_log('bob-log', 'shared indicator', recipient_user=self.other_user)
        self._create_log('unassigned-log', 'shared indicator', recipient_user=None)
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'indicator'})

        self.assertEqual(response.context['match_count'], 2)

    def test_trashed_logs_are_excluded(self):
        self._create_log('live-log', 'shared indicator')
        self._create_log('trashed-log', 'shared indicator', deleted_at=timezone.now())
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'indicator'})

        self.assertEqual(response.context['match_count'], 1)
        self.assertContains(response, 'live-log')
        self.assertNotContains(response, 'trashed-log')

    def test_regex_search_matches(self):
        self._create_log('regex-hit', 'Service: wuauserv4 running')
        self._create_log('regex-miss', 'Service: wuauserv running')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'wuauserv[0-9]', 'regex': '1'})

        self.assertIsNone(response.context['search_error'])
        self.assertEqual(response.context['match_count'], 1)
        self.assertContains(response, 'regex-hit')

    def test_regex_search_is_case_insensitive(self):
        self._create_log('regex-case', 'FOUND Malware.Generic here')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'malware\\.generic', 'regex': '1'})

        self.assertEqual(response.context['match_count'], 1)

    def test_invalid_regex_reports_error_without_results(self):
        self._create_log('any-log', 'content')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'unbalanced(', 'regex': '1'})

        self.assertIsNotNone(response.context['search_error'])
        self.assertIn('invalid regex', response.context['search_error'])
        self.assertEqual(response.context['results'], [])

    def test_unsupported_regex_construct_is_rejected(self):
        if analyzer._re2 is None:
            self.skipTest('re2 binding not installed')
        self._create_log('any-log', 'content')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'foo(?=bar)', 'regex': '1'})

        self.assertIsNotNone(response.context['search_error'])
        self.assertIn('lookahead', response.context['search_error'])
        self.assertEqual(response.context['results'], [])

    def test_results_are_paginated(self):
        for index in range(log_search.RESULTS_PER_PAGE + 3):
            self._create_log(f'page-log-{index}', 'paged indicator')
        self._login()

        response = self.client.get(reverse('log_search'), {'q': 'paged indicator'})

        self.assertEqual(response.context['match_count'], log_search.RESULTS_PER_PAGE + 3)
        self.assertEqual(len(response.context['results']), log_search.RESULTS_PER_PAGE)
        self.assertEqual(response.context['page_obj'].paginator.num_pages, 2)

    def test_search_result_set_is_capped_and_reported(self):
        limit = 3
        for index in range(limit + 2):
            self._create_log(f'capped-log-{index}', 'capped indicator')
        self._login()

        original_limit = log_search.SEARCH_MATCH_LIMIT
        log_search.SEARCH_MATCH_LIMIT = limit
        try:
            response = self.client.get(reverse('log_search'), {'q': 'capped indicator'})
        finally:
            log_search.SEARCH_MATCH_LIMIT = original_limit

        self.assertTrue(response.context['truncated'])
        self.assertEqual(response.context['match_count'], limit)
        self.assertContains(response, 'narrow the search term')


class LogSearchDownloadTests(UploadedLogSharedSetupMixin, TestCase):

    def _create_log(self, upload_id, content, filename=None):
        return UploadedLog.objects.create(
            upload_id=upload_id,
            forum_username='forum_user',
            original_filename=filename or f'{upload_id}.txt',
            content=content,
            recipient_user=self.user,
        )

    def _login(self):
        self.client.login(username='alice', password='password123')

    def test_download_returns_zip_of_matching_logs(self):
        self._create_log('zip-one', 'shared indicator one')
        self._create_log('zip-two', 'shared indicator two')
        self._create_log('zip-miss', 'unrelated')
        self._login()

        response = self.client.get(reverse('log_search_download'), {'q': 'indicator'})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/zip')
        self.assertIn('fenris_search_logs.zip', response['Content-Disposition'])
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            self.assertEqual(sorted(archive.namelist()), ['zip-one.txt', 'zip-two.txt'])
            self.assertEqual(archive.read('zip-one.txt').decode(), 'shared indicator one')

    def test_download_disambiguates_duplicate_filenames(self):
        self._create_log('dup-one', 'shared indicator one', filename='FRST.txt')
        self._create_log('dup-two', 'shared indicator two', filename='FRST.txt')
        self._login()

        response = self.client.get(reverse('log_search_download'), {'q': 'indicator'})

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            self.assertEqual(sorted(archive.namelist()), ['FRST.txt', 'FRST_2.txt'])

    def test_download_is_capped_at_zip_limit(self):
        limit = 3
        for index in range(limit + 2):
            self._create_log(f'cap-log-{index}', 'capped indicator')
        self._login()

        original_limit = log_search.ZIP_MATCH_LIMIT
        log_search.ZIP_MATCH_LIMIT = limit
        try:
            response = self.client.get(reverse('log_search_download'), {'q': 'capped indicator'})
        finally:
            log_search.ZIP_MATCH_LIMIT = original_limit

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            self.assertEqual(len(archive.namelist()), limit)

    def test_download_respects_case_sensitivity(self):
        self._create_log('zip-exact', 'shared Indicator')
        self._create_log('zip-other', 'shared INDICATOR')
        self._login()

        response = self.client.get(
            reverse('log_search_download'), {'q': 'Indicator', 'case': '1'}
        )

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            self.assertEqual(archive.namelist(), ['zip-exact.txt'])

    def test_download_selected_bundles_only_ticked_logs(self):
        self._create_log('sel-one', 'shared indicator one')
        self._create_log('sel-two', 'shared indicator two')
        self._create_log('sel-three', 'shared indicator three')
        self._login()

        response = self.client.get(
            reverse('log_search_download'),
            {'q': 'indicator', 'selected_upload_ids': ['sel-one', 'sel-three']},
        )

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            self.assertEqual(sorted(archive.namelist()), ['sel-one.txt', 'sel-three.txt'])

    def test_download_selected_ignores_trashed_logs(self):
        self._create_log('sel-live', 'shared indicator')
        trashed = self._create_log('sel-trashed', 'shared indicator')
        trashed.deleted_at = timezone.now()
        trashed.save(update_fields=['deleted_at'])
        self._login()

        response = self.client.get(
            reverse('log_search_download'),
            {'q': 'indicator', 'selected_upload_ids': ['sel-live', 'sel-trashed']},
        )

        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            self.assertEqual(archive.namelist(), ['sel-live.txt'])

    def test_download_selected_with_no_resolvable_logs_redirects_with_error(self):
        self._create_log('present-log', 'shared indicator')
        self._login()

        response = self.client.get(
            reverse('log_search_download'),
            {'q': 'indicator', 'selected_upload_ids': ['does-not-exist']},
            follow=True,
        )

        self.assertContains(response, 'None of the selected logs are available for download.')

    def test_download_without_matches_redirects_with_error(self):
        self._create_log('no-match', 'unrelated content')
        self._login()

        response = self.client.get(reverse('log_search_download'), {'q': 'indicator'}, follow=True)

        self.assertContains(response, 'No logs matched this search.')

    def test_download_requires_login(self):
        response = self.client.get(reverse('log_search_download'), {'q': 'indicator'})
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login'), response.url)
