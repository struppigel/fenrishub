"""The "centralbox names" page: stored centralbox families and malware types
no tag covers yet (tagging.centralbox_name_suggestions), and the tag editor
filled in from it. Database only: nothing may call centralbox."""

import json
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .. import centralbox
from ..models import HashAlias, HashVerdict, RuleTag, TagCategory, UploadedLog, UploadedLogFileHash
from ..tagging import centralbox_name_suggestions, compile_pattern, pattern_error, suggested_tag_pattern
from .factories import make_uploaded_log, make_user

SHA_A = 'a1' * 32
SHA_B = 'b2' * 32
SHA_C = 'c3' * 32
MD5_C = 'c3' * 16


def verdict(sha, family='', malware_type=''):
    now = timezone.now()
    return HashVerdict.objects.create(sha256=sha, state='known', verdict='malicious', family=family,
                                      malware_type=malware_type, checked_at=now, next_check_at=now + timedelta(days=7))


def hash_row(upload_id, sha='', md5=''):
    upload = UploadedLog.objects.filter(upload_id=upload_id).first() or make_uploaded_log(
        upload_id, log_type='Malwarebytes', content='x', forum_username='nobody')
    UploadedLogFileHash.objects.create(upload=upload, sha256=sha, md5=md5, line_no=1, anchor_line_no=1,
                                       source='malwarebytes', auto=bool(sha))
    return upload


def by_name(rows):
    return {row['name']: row for row in rows}


class SuggestionTests(TestCase):
    def setUp(self):
        self.category = TagCategory.objects.create(name='test', priority=5)

    def tag(self, name, pattern, centralbox):
        return RuleTag.objects.create(name=name, match_pattern=pattern, match_centralbox=centralbox,
                                      category=self.category)

    def test_untagged_names_with_hash_and_log_counts(self):
        verdict(SHA_A, family='AsyncRAT', malware_type='rat')
        verdict(SHA_B, family='asyncrat')
        hash_row('log-one', sha=SHA_A)
        hash_row('log-two', sha=SHA_A)
        hash_row('log-two', sha=SHA_B)
        result = centralbox_name_suggestions()
        families = by_name(result['families'])
        # Grouped case-insensitively; the spelling seen most (ties: first) is shown.
        (name,) = families
        self.assertEqual(name.lower(), 'asyncrat')
        self.assertEqual((families[name]['hashes'], families[name]['logs'], families[name]['near_tags']), (2, 2, []))
        self.assertEqual(by_name(result['types'])['rat']['hashes'], 1)

    def test_covered_names_are_left_out_and_near_tags_are_offered(self):
        verdict(SHA_A, family='lumma')
        verdict(SHA_B, family='xmrig')
        self.tag('Lumma stealer', r'lumma', centralbox=True)
        near = self.tag('Coinminer', r'xmrig|miner', centralbox=False)
        families = by_name(centralbox_name_suggestions()['families'])
        self.assertNotIn('lumma', families)
        self.assertEqual(families['xmrig']['near_tags'], [{'id': near.pk, 'name': 'Coinminer'}])

    def test_md5_only_rows_count_through_pairs_and_aliases_and_deleted_logs_do_not(self):
        verdict(SHA_C, family='redline')
        hash_row('tk-log', md5=MD5_C)              # Trojan Killer: MD5 only
        HashAlias.objects.create(md5=MD5_C, sha256=SHA_C, checked_at=timezone.now(),
                                 next_check_at=timezone.now() + timedelta(days=1))
        gone = hash_row('gone-log', sha=SHA_C)
        UploadedLog.objects.filter(pk=gone.pk).update(deleted_at=timezone.now())
        row = by_name(centralbox_name_suggestions()['families'])['redline']
        self.assertEqual(row['logs'], 1)
        # Through a pair seen in a live log too (the alias is not needed then).
        HashAlias.objects.all().delete()
        pair = hash_row('pair-log', sha=SHA_C, md5=MD5_C)
        self.assertEqual(by_name(centralbox_name_suggestions()['families'])['redline']['logs'], 2)
        self.assertTrue(pair)

    def test_query_count_is_bounded(self):
        for index in range(5):
            sha = f'{index:064x}'
            verdict(sha, family=f'family{index}', malware_type='stealer')
            hash_row(f'log-{index}', sha=sha)
        with self.assertNumQueries(5):
            centralbox_name_suggestions()

    def test_generic_and_unknown_are_never_suggested(self):
        verdict(SHA_A, family='Generic', malware_type='generic')
        verdict(SHA_B, family='unknown', malware_type='stealer')
        result = centralbox_name_suggestions()
        self.assertEqual(result['families'], [])
        self.assertEqual([row['name'] for row in result['types']], ['stealer'])

    def test_nothing_stored(self):
        self.assertEqual(centralbox_name_suggestions(), {'families': [], 'types': []})


class SuggestedPatternTests(TestCase):
    def test_whole_word_with_metacharacters_escaped(self):
        for name, longer in (('asyncrat', 'asyncrat2'), ('Win32/Agent.x', 'Win32/Agent.xy'), ('agent tesla', 'agent teslas')):
            pattern = suggested_tag_pattern(name)
            self.assertIsNone(pattern_error(pattern), name)
            compiled = compile_pattern(pattern)
            self.assertTrue(compiled.search(f'family: {name.upper()}'), name)
            self.assertFalse(compiled.search(longer), name)
        self.assertEqual(suggested_tag_pattern('.net'), r'\.net\b')
        self.assertEqual(suggested_tag_pattern('a.b'), r'\ba\.b\b')


class PageTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)
        self.category = TagCategory.objects.create(name='test', priority=5)

    def get_page(self):
        with mock.patch.object(centralbox, '_request') as request:
            response = self.client.get(reverse('rule_tag_centralbox_names'))
        request.assert_not_called()
        return response

    def test_needs_a_login(self):
        self.client.logout()
        self.assertEqual(self.client.get(reverse('rule_tag_centralbox_names')).status_code, 302)

    def test_lists_both_groups_with_create_and_turn_on_links(self):
        verdict(SHA_A, family='asyncrat', malware_type='stealer')
        verdict(SHA_B, family='xmrig')
        near = RuleTag.objects.create(name='Coinminer', match_pattern='xmrig', category=self.category)
        page = self.get_page().content.decode()
        self.assertIn('families', page)
        self.assertIn('malware types', page)
        self.assertIn(reverse('rule_tag_add') + '?centralbox=asyncrat', page)
        self.assertIn(reverse('rule_tag_add') + '?centralbox=stealer', page)
        self.assertIn(reverse('rule_tag_edit', args=[near.pk]) + '?centralbox=1', page)
        self.assertNotIn('?centralbox=xmrig', page)

    def test_empty_states(self):
        self.assertIn('no centralbox results', self.get_page().content.decode())
        verdict(SHA_A, family='lumma')
        RuleTag.objects.create(name='Lumma', match_pattern='lumma', match_centralbox=True, category=self.category)
        self.assertIn('every stored centralbox name has a tag', self.get_page().content.decode())

    def test_tags_page_links_here(self):
        page = self.client.get(reverse('rule_tags')).content.decode()
        self.assertIn(reverse('rule_tag_centralbox_names'), page)

    def prefill(self, response):
        content = response.content.decode()
        start = content.index('id="tagPrefillData"')
        return json.loads(content[content.index('>', start) + 1:content.index('</script>', start)])

    def test_new_tag_is_filled_in_for_a_stored_name_only(self):
        verdict(SHA_A, family='AsyncRAT')
        tags_before = RuleTag.objects.count()
        prefill = self.prefill(self.client.get(reverse('rule_tag_add'), {'centralbox': 'asyncrat'}))
        self.assertEqual(prefill, {'name': 'asyncrat', 'match_pattern': r'\basyncrat\b', 'match_centralbox': True})
        for name in ('unknownfamily', 'x' * 65, 'bad\x01name', ''):
            self.assertIsNone(self.prefill(self.client.get(reverse('rule_tag_add'), {'centralbox': name})), name)
        self.assertEqual(RuleTag.objects.count(), tags_before)  # nothing is saved

    def test_existing_tag_gets_centralbox_ticked(self):
        tag = RuleTag.objects.create(name='Coinminer', match_pattern='xmrig', category=self.category)
        url = reverse('rule_tag_edit', args=[tag.pk])
        self.assertEqual(self.prefill(self.client.get(url, {'centralbox': '1'})), {'match_centralbox': True})
        self.assertIsNone(self.prefill(self.client.get(url)))
        tag.refresh_from_db()
        self.assertFalse(tag.match_centralbox)
