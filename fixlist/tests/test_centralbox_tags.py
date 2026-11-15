"""Rule tags matching centralbox family / malware type (RuleTag.match_centralbox),
and the limit on automatic checks for logs with many hashes."""

import json
from datetime import timedelta

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from .. import centralbox
from ..models import HashVerdict, RuleTag, TagCategory, UploadedLog, UploadedLogFileHash
from ..rule_sets import SHARED_RULE_SET_KEY
from ..tagging import found_tags_by_upload, logs_with_tags, save_tag, serialize_tag
from ..views.centralbox import page_hash_context
from .factories import make_uploaded_log, make_user
from .test_log_highlighting import MALWAREBYTES

SHA = '033bb9eef12e0e23adb36c9788edaa342704362512a8113d6aaeec3e01bf83ad'


def store(sha=SHA, verdict='malicious', family='asyncrat', malware_type='stealer'):
    now = timezone.now()
    return HashVerdict.objects.create(
        sha256=sha, state='known', verdict=verdict, family=family, malware_type=malware_type,
        checked_at=now, next_check_at=now + timedelta(days=7),
    )


class CentralboxTagTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = make_user()
        self.client.force_login(self.user)
        self.upload = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MALWAREBYTES, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.upload)
        self.category = TagCategory.objects.create(name='family test', priority=7)

    def tag(self, name='AsyncRAT', pattern='asyncrat', **extra):
        return RuleTag.objects.create(name=name, match_pattern=pattern, match_centralbox=True,
                                      category=self.category, **extra)

    def found(self):
        return [tag['name'] for tag in found_tags_by_upload([self.upload.pk], SHARED_RULE_SET_KEY)[self.upload.pk]]

    def test_save_needs_a_regex_and_round_trips(self):
        tag, error = save_tag(self.user, None, {'name': 'Stealers', 'match_centralbox': True})
        self.assertIsNone(tag)
        self.assertIn('needs a regex', error)
        tag, error = save_tag(self.user, None, {'name': 'Stealers', 'match_pattern': 'stealer', 'match_centralbox': True})
        self.assertIsNone(error)
        self.assertTrue(serialize_tag(tag)['match_centralbox'])
        tag, error = save_tag(self.user, tag, {'match_centralbox': 'yes'})
        self.assertIn('boolean', error)

    def test_scanner_log_carries_tags_from_family_and_type(self):
        store()
        self.tag()
        self.tag(name='Stealers', pattern='^stealer$')
        RuleTag.objects.create(name='Not centralbox', match_pattern='asyncrat', category=self.category)
        self.assertEqual(self.found(), ['AsyncRAT', 'Stealers'])

    def test_any_verdict_counts_and_exclude_blocks(self):
        store(verdict='clean', family='lumma', malware_type='')
        self.tag(name='Lumma', pattern='lumma')
        self.tag(name='Excluded', pattern='lum', exclude_pattern='lumma')
        self.assertEqual(self.found(), ['Lumma'])

    def test_no_verdict_no_tag(self):
        self.tag()
        self.assertEqual(self.found(), [])

    def test_tag_search_finds_the_scanner_log(self):
        store()
        tag = self.tag()
        other = make_uploaded_log('other-log', log_type='Malwarebytes', content='nothing', forum_username='nobody')
        matched, _ = logs_with_tags([tag.pk], SHARED_RULE_SET_KEY, UploadedLog.objects.all())
        self.assertEqual(matched, [self.upload.pk])
        self.assertNotIn(other.pk, matched)

    def test_log_page_shows_tags_next_to_the_hash(self):
        store()
        self.tag()
        hidden = TagCategory.objects.create(name='hidden test', priority=0)
        RuleTag.objects.create(name='Hidden', match_pattern='asyncrat', match_centralbox=True, category=hidden)
        context = page_hash_context(self.upload, self.user)
        self.assertEqual(context['tags'], {SHA: ['AsyncRAT']})

    def test_editor_preview_lists_matching_centralbox_names(self):
        store()
        store(sha='f' * 64, family='asyncrat', malware_type='rat')
        response = self.client.post(reverse('rule_tag_preview_api'),
                                    json.dumps({'pattern': 'asyncrat|^rat$', 'match_centralbox': True}),
                                    content_type='application/json')
        names = {(item['name'], item['field'], item['count']) for item in response.json()['centralbox']}
        self.assertEqual(names, {('asyncrat', 'family', 2), ('rat', 'malware type', 1)})


class AutoCheckLimitTests(TestCase):
    def setUp(self):
        self.upload = make_uploaded_log('mb-log', log_type='Malwarebytes', content=MALWAREBYTES, forum_username='nobody')
        UploadedLogFileHash.rebuild_for(self.upload)

    def test_logs_with_too_many_hashes_are_not_checked_by_themselves(self):
        self.assertEqual(centralbox.auto_hashes_of([self.upload.pk]), [SHA])
        self.assertTrue(page_hash_context(self.upload)['auto_check'])
        with override_settings(CENTRALBOX_MAX_AUTO_HASHES_PER_LOG=0):
            self.assertEqual(centralbox.auto_hashes_of([self.upload.pk]), [])
            self.assertFalse(page_hash_context(self.upload)['auto_check'])
