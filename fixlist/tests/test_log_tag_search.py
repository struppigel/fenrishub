"""Tests for finding logs by rule tag: the uploads list filter and the log search page.

Cached analyses are written by hand with chosen rule ids and warnings, so the
analyzer never runs.
"""

import io
import zipfile

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from ..analyzer import ANALYSIS_PAYLOAD_FORMAT
from ..models import RuleTag, UploadedLog, UploadedLogAnalysis, UserProfile
from ..tagging import attach_rule_tags, found_tags_by_upload, logs_with_tags
from .factories import make_rule


def _line(text, rule_ids=()):
    return {'line': text, 'dominant_status': 'B' if rule_ids else '?', 'rule_ids': list(rule_ids)}


def _payload(lines=(), warnings=(), wholelog_rule_ids=()):
    return {
        'format': ANALYSIS_PAYLOAD_FORMAT,
        'lines': list(lines),
        'summary': {},
        'warnings': list(warnings),
        'wholelog_rule_ids': list(wholelog_rule_ids),
    }


class TagSearchSetupMixin:
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username='alice', password='pw')
        self.miner_rule = make_rule('C:\\miner.exe')
        self.adware_rule = make_rule('C:\\adware.exe')
        self.miner = RuleTag.objects.create(name='miner')
        self.adware = RuleTag.objects.create(name='adware')
        self.miner_rule.tags.add(self.miner)
        self.adware_rule.tags.add(self.adware)
        self.low_memory = RuleTag.objects.get(builtin_code='low_memory')

    def _log(self, upload_id, content='Scan result of Farbar Recovery Scan Tool', **kwargs):
        defaults = {
            'forum_username': 'forum_user',
            'original_filename': f'{upload_id}.txt',
            'recipient_user': self.user,
            'log_type': 'FRST',
        }
        defaults.update(kwargs)
        return UploadedLog.objects.create(upload_id=upload_id, content=content, **defaults)

    def _cache(self, log, payload, rule_set_key='shared', source_content_hash=None):
        return UploadedLogAnalysis.objects.create(
            upload=log,
            rule_set_key=rule_set_key,
            payload=payload,
            source_content_hash=log.content_hash if source_content_hash is None else source_content_hash,
        )

    def _search(self, tag_ids, rule_set_key='shared', candidates=None):
        if candidates is None:
            candidates = UploadedLog.objects.all()
        return logs_with_tags(tag_ids, rule_set_key, candidates)


class LogsWithTagsTests(TagSearchSetupMixin, TestCase):

    def test_tag_found_through_a_lines_deciding_rule(self):
        log = self._log('miner-line')
        self._cache(log, _payload(lines=[_line('C:\\miner.exe', [self.miner_rule.pk])]))
        other = self._log('clean')
        self._cache(other, _payload(lines=[_line('C:\\clean.exe')]))

        self.assertEqual(self._search([self.miner.pk]), ([log.pk], 0))

    def test_tag_found_through_an_alert_warning(self):
        log = self._log('miner-alert')
        self._cache(log, _payload(warnings=[{'code': 'alert_rule', 'rule_ids': [self.miner_rule.pk]}]))

        self.assertEqual(self._search([self.miner.pk])[0], [log.pk])

    def test_tag_found_through_a_wholelog_rule(self):
        log = self._log('miner-wholelog')
        self._cache(log, _payload(wholelog_rule_ids=[self.miner_rule.pk]))

        self.assertEqual(self._search([self.miner.pk])[0], [log.pk])

    def test_builtin_tag_found_through_its_warning_code(self):
        log = self._log('low-mem')
        self._cache(log, _payload(warnings=[{'code': 'low_memory'}]))
        other = self._log('plenty-mem')
        self._cache(other, _payload(warnings=[{'code': 'recent_os_install'}]))

        self.assertEqual(self._search([self.low_memory.pk])[0], [log.pk])

    def test_several_tags_must_all_be_present(self):
        both = self._log('both')
        self._cache(both, _payload(lines=[
            _line('C:\\miner.exe', [self.miner_rule.pk]),
            _line('C:\\adware.exe', [self.adware_rule.pk]),
        ]))
        only_miner = self._log('only-miner')
        self._cache(only_miner, _payload(lines=[_line('C:\\miner.exe', [self.miner_rule.pk])]))

        self.assertEqual(self._search([self.miner.pk, self.adware.pk])[0], [both.pk])

    def test_tag_on_no_rule_matches_nothing(self):
        unused = RuleTag.objects.create(name='unused')
        log = self._log('any')
        self._cache(log, _payload(lines=[_line('C:\\miner.exe', [self.miner_rule.pk])]))

        self.assertEqual(self._search([unused.pk]), ([], 0))

    def test_stale_or_missing_analyses_are_skipped_and_counted(self):
        stale_hash = self._log('stale-hash')
        self._cache(stale_hash, _payload(lines=[_line('x', [self.miner_rule.pk])]), source_content_hash='0' * 32)
        old_format = self._log('old-format')
        old_payload = _payload(lines=[_line('x', [self.miner_rule.pk])])
        old_payload['format'] = ANALYSIS_PAYLOAD_FORMAT - 1
        self._cache(old_format, old_payload)
        self._log('never-analyzed')
        # A log type the analyzer skips is not reported as missed.
        self._log('a-fixlog', log_type='Fixlog')

        self.assertEqual(self._search([self.miner.pk]), ([], 3))

    def test_viewers_private_analysis_wins_over_shared(self):
        log = self._log('private-wins')
        self._cache(log, _payload(lines=[_line('x', [self.miner_rule.pk])]), rule_set_key='shared')
        self._cache(log, _payload(lines=[_line('x', [self.adware_rule.pk])]), rule_set_key='private:7')

        self.assertEqual(self._search([self.adware.pk], 'private:7')[0], [log.pk])
        self.assertEqual(self._search([self.miner.pk], 'private:7')[0], [])

    def test_shared_analysis_is_the_fallback_for_a_private_viewer(self):
        log = self._log('shared-fallback')
        self._cache(log, _payload(lines=[_line('x', [self.miner_rule.pk])]), rule_set_key='shared')

        self.assertEqual(self._search([self.miner.pk], 'private:7'), ([log.pk], 0))

    def test_only_candidates_are_searched_in_their_order(self):
        older = self._log('older')
        newer = self._log('newer')
        outside = self._log('outside', log_type='Addition')
        for log in (older, newer, outside):
            self._cache(log, _payload(lines=[_line('x', [self.miner_rule.pk])]))

        candidates = UploadedLog.objects.filter(log_type='FRST').order_by('upload_id')
        self.assertEqual(self._search([self.miner.pk], candidates=candidates)[0], [newer.pk, older.pk])

    def test_attach_rule_tags_finds_the_same_tags(self):
        payload = _payload(
            lines=[_line('C:\\miner.exe', [self.miner_rule.pk])],
            warnings=[{'code': 'low_memory'}],
            wholelog_rule_ids=[self.adware_rule.pk],
        )
        attach_rule_tags(payload)
        found = {tag['id'] for tag in payload['rule_tags']}
        self.assertEqual(found, {self.miner.pk, self.adware.pk, self.low_memory.pk})


class UploadsListTagSearchTests(TagSearchSetupMixin, TestCase):
    """The uploads list's search text also finds logs by the tag it names."""

    def setUp(self):
        super().setUp()
        self.client.login(username='alice', password='pw')

    def _listed(self, response):
        return sorted(log.upload_id for log in response.context['uploads'])

    def test_search_text_naming_a_tag_finds_tagged_logs_and_text_matches(self):
        tagged = self._log('zzz', original_filename='zzz.txt')
        self._cache(tagged, _payload(lines=[_line('x', [self.miner_rule.pk])]))
        named = self._log('miner-named', original_filename='other.txt')
        self._cache(named, _payload(lines=[_line('x')]))
        unrelated = self._log('unrelated', original_filename='other.txt')
        self._cache(unrelated, _payload(lines=[_line('x')]))

        response = self.client.get(reverse('uploaded_logs'), {'q': 'MINER'})

        self.assertEqual(self._listed(response), ['miner-named', 'zzz'])

    def test_search_text_naming_no_tag_is_a_plain_text_search(self):
        tagged = self._log('zzz')
        self._cache(tagged, _payload(lines=[_line('x', [self.miner_rule.pk])]))
        self._log('min-one')

        response = self.client.get(reverse('uploaded_logs'), {'q': 'min'})

        self.assertEqual(self._listed(response), ['min-one'])
        self.assertEqual(response.context['tag_unanalyzed_count'], 0)

    def test_builtin_tag_by_name(self):
        log = self._log('low')
        self._cache(log, _payload(warnings=[{'code': 'low_memory'}]))

        response = self.client.get(reverse('uploaded_logs'), {'q': self.low_memory.name})

        self.assertEqual(self._listed(response), ['low'])

    def test_respects_the_channel_filter(self):
        bob = User.objects.create_user(username='bob', password='pw')
        mine = self._log('mine')
        theirs = self._log('theirs', recipient_user=bob)
        for log in (mine, theirs):
            self._cache(log, _payload(lines=[_line('x', [self.miner_rule.pk])]))

        response = self.client.get(reverse('uploaded_logs'), {'q': 'miner'})
        self.assertEqual(self._listed(response), ['mine'])

        response = self.client.get(reverse('uploaded_logs'), {'q': 'miner', 'channel': 'all'})
        self.assertEqual(self._listed(response), ['mine', 'theirs'])

    def test_reports_logs_without_an_analysis(self):
        self._log('never-analyzed')

        response = self.client.get(reverse('uploaded_logs'), {'q': 'miner'})

        self.assertEqual(response.context['tag_unanalyzed_count'], 1)
        self.assertContains(response, 'not searched for tags')

    def test_no_tag_picker_on_the_uploads_page(self):
        response = self.client.get(reverse('uploaded_logs'))

        self.assertNotContains(response, 'tagFilterPicker')


class LogSearchTagFilterTests(TagSearchSetupMixin, TestCase):

    def setUp(self):
        super().setUp()
        self.client.login(username='alice', password='pw')

    def test_tags_only_search_previews_the_tagged_line(self):
        content = 'Scan result of Farbar Recovery Scan Tool\n\nR1 C:\\miner.exe\n'
        log = self._log('tagged', content=content)
        self._cache(log, _payload(lines=[
            _line('Scan result of Farbar Recovery Scan Tool'),
            _line('R1 C:\\miner.exe', [self.miner_rule.pk]),
        ]))
        clean = self._log('untagged', content=content + 'x')
        self._cache(clean, _payload(lines=[_line('R1 C:\\miner.exe')]))

        response = self.client.get(reverse('log_search'), {'tags': [self.miner.pk]})

        results = response.context['results']
        self.assertEqual([result['log'].upload_id for result in results], ['tagged'])
        self.assertEqual(results[0]['line_number'], 3)
        self.assertEqual(results[0]['after'], 'R1 C:\\miner.exe')

    def test_text_and_tags_combine(self):
        both = self._log('both', content='needle line')
        self._cache(both, _payload(lines=[_line('needle line', [self.miner_rule.pk])]))
        text_only = self._log('text-only', content='needle again')
        self._cache(text_only, _payload(lines=[_line('needle again')]))
        tag_only = self._log('tag-only', content='haystack')
        self._cache(tag_only, _payload(lines=[_line('haystack', [self.miner_rule.pk])]))

        response = self.client.get(reverse('log_search'), {'q': 'needle', 'tags': [self.miner.pk]})

        results = response.context['results']
        self.assertEqual([result['log'].upload_id for result in results], ['both'])
        self.assertEqual(results[0]['hit'], 'needle')

    def test_no_results_names_the_tags(self):
        response = self.client.get(reverse('log_search'), {'tags': [self.miner.pk]})

        self.assertContains(response, 'have the tag miner')

    def test_download_all_respects_tags(self):
        log = self._log('zip-me', content='tagged body')
        self._cache(log, _payload(lines=[_line('tagged body', [self.miner_rule.pk])]))
        other = self._log('leave-me', content='other body')
        self._cache(other, _payload(lines=[_line('other body')]))

        response = self.client.get(reverse('log_search_download'), {'tags': [self.miner.pk]})

        self.assertEqual(response.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(b''.join(response.streaming_content) if response.streaming else response.content)) as archive:
            contents = [archive.read(name).decode('utf-8') for name in archive.namelist()]
        self.assertEqual(contents, ['tagged body'])

    def test_private_viewer_searches_their_own_analysis(self):
        UserProfile.objects.create(user=self.user, rule_set_mode='private')
        log = self._log('private-view', content='body')
        self._cache(log, _payload(lines=[_line('body', [self.miner_rule.pk])]), rule_set_key='shared')
        self._cache(log, _payload(lines=[_line('body')]), rule_set_key=f'private:{self.user.pk}')

        response = self.client.get(reverse('log_search'), {'tags': [self.miner.pk]})

        self.assertEqual(response.context['results'], [])

    def test_results_show_the_tags_found_in_each_log(self):
        log = self._log('shows-tags', content='needle')
        self._cache(log, _payload(
            lines=[_line('needle', [self.miner_rule.pk])],
            warnings=[{'code': 'low_memory'}],
        ))
        self._log('no-analysis', content='needle too')

        response = self.client.get(reverse('log_search'), {'q': 'needle'})

        tags_by_log = {
            result['log'].upload_id: [tag['name'] for tag in result['tags']]
            for result in response.context['results']
        }
        self.assertEqual(tags_by_log, {
            'shows-tags': sorted(['miner', self.low_memory.name], key=str.lower),
            'no-analysis': [],
        })
        self.assertContains(response, f'<span class="tag-chip tag-cat-{self.miner.category_id}" title="">miner</span>', html=True)

    def test_tag_suggestions_list_names_only(self):
        response = self.client.get(reverse('log_search'))

        self.assertContains(response, 'showDescriptions: false')


class FoundTagsByUploadTests(TagSearchSetupMixin, TestCase):

    def _names(self, found, log):
        return [tag['name'] for tag in found[log.pk]]

    def test_finds_tags_through_lines_alerts_wholelog_and_builtin_warnings(self):
        log = self._log('all-sources')
        self._cache(log, _payload(
            lines=[_line('x', [self.miner_rule.pk])],
            warnings=[{'code': 'alert_rule', 'rule_ids': [self.adware_rule.pk]}, {'code': 'low_memory'}],
        ))
        wholelog = self._log('wholelog')
        self._cache(wholelog, _payload(wholelog_rule_ids=[self.miner_rule.pk]))
        bare = self._log('bare')

        found = found_tags_by_upload([log.pk, wholelog.pk, bare.pk], 'shared')

        self.assertEqual(self._names(found, log), sorted(['adware', 'miner', self.low_memory.name], key=str.lower))
        self.assertEqual(self._names(found, wholelog), ['miner'])
        self.assertEqual(found[bare.pk], [])

    def test_matches_attach_rule_tags(self):
        payload = _payload(
            lines=[_line('x', [self.miner_rule.pk])],
            warnings=[{'code': 'low_memory'}],
            wholelog_rule_ids=[self.adware_rule.pk],
        )
        log = self._log('same-as-attach')
        self._cache(log, payload)

        found = {tag['id'] for tag in found_tags_by_upload([log.pk], 'shared')[log.pk]}
        attached = {tag['id'] for tag in attach_rule_tags(dict(payload))['rule_tags']}
        self.assertEqual(found, attached)

    def test_private_analysis_wins_and_shared_is_the_fallback(self):
        both = self._log('both-keys')
        self._cache(both, _payload(lines=[_line('x', [self.miner_rule.pk])]), rule_set_key='shared')
        self._cache(both, _payload(lines=[_line('x', [self.adware_rule.pk])]), rule_set_key='private:7')
        shared_only = self._log('shared-only')
        self._cache(shared_only, _payload(lines=[_line('x', [self.miner_rule.pk])]), rule_set_key='shared')

        found = found_tags_by_upload([both.pk, shared_only.pk], 'private:7')

        self.assertEqual(self._names(found, both), ['adware'])
        self.assertEqual(self._names(found, shared_only), ['miner'])

    def test_stale_analysis_gives_no_tags(self):
        log = self._log('stale')
        self._cache(log, _payload(lines=[_line('x', [self.miner_rule.pk])]), source_content_hash='0' * 32)

        self.assertEqual(found_tags_by_upload([log.pk], 'shared'), {log.pk: []})

    def test_query_count_does_not_grow_with_the_number_of_logs(self):
        logs = [self._log(f'many-{index}') for index in range(6)]
        for log in logs:
            self._cache(log, _payload(lines=[_line('x', [self.miner_rule.pk])], warnings=[{'code': 'low_memory'}]))

        with self.assertNumQueries(4):
            found_tags_by_upload([log.pk for log in logs], 'shared')


class UploadsListRowTagsTests(TagSearchSetupMixin, TestCase):

    def setUp(self):
        super().setUp()
        self.client.login(username='alice', password='pw')

    def test_rows_show_their_tags(self):
        tagged = self._log('tagged-row')
        self._cache(tagged, _payload(lines=[_line('x', [self.miner_rule.pk])]))
        self._log('untagged-row')

        response = self.client.get(reverse('uploaded_logs'))

        tags = {log.upload_id: [tag['name'] for tag in log.rule_tags] for log in response.context['uploads']}
        self.assertEqual(tags, {'tagged-row': ['miner'], 'untagged-row': []})
        self.assertContains(response, f'<span class="tag-chip tag-cat-{self.miner.category_id}" title="">miner</span>', html=True)

    def test_trash_rows_show_their_tags(self):
        from django.utils import timezone
        trashed = self._log('trashed-row', deleted_at=timezone.now())
        self._cache(trashed, _payload(lines=[_line('x', [self.miner_rule.pk])]))

        response = self.client.get(reverse('uploads_trash'))

        self.assertEqual([tag['name'] for tag in response.context['uploads'][0].rule_tags], ['miner'])
