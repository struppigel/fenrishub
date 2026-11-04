"""Rule tags and speeches through the token API.

Reading tags is open to every token. Writing needs a superuser's write token,
re-checked on every request. Everything is additive: existing endpoints keep
their methods and response keys, so older MCP clients keep working.
"""

import json

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from ..analyzer import invalidate_rule_buckets_cache
from ..models import ApiToken, ClassificationRule, RuleTag, Speech
from .factories import make_rule, make_uploaded_log, make_user
from .test_llm_api import enable_api


class ApiWriteBase(TestCase):
    def setUp(self):
        cache.clear()
        enable_api()
        invalidate_rule_buckets_cache()
        self.admin = User.objects.create_superuser(username='root', password='pw')
        self.helper = make_user('alice')
        _token, self.write_raw = ApiToken.issue(self.admin, 'write', can_write=True)
        _token, self.admin_read_raw = ApiToken.issue(self.admin, 'read')
        _token, self.helper_raw = ApiToken.issue(self.helper, 'read')

    def get(self, name, *args, raw=None, data=None):
        return self.client.get(
            reverse(name, args=args), data or {}, secure=True,
            HTTP_AUTHORIZATION=f'Bearer {raw or self.helper_raw}',
        )

    def post(self, name, *args, body=None, raw=None):
        return self.client.post(
            reverse(name, args=args), json.dumps(body or {}), content_type='application/json',
            secure=True, HTTP_AUTHORIZATION=f'Bearer {raw or self.write_raw}',
        )


class WriteAuthTests(ApiWriteBase):
    def test_read_only_token_of_a_superuser_cannot_write(self):
        response = self.post('api_v1_tag_create', body={'name': 'x', 'match_statuses': ['P']}, raw=self.admin_read_raw)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(RuleTag.objects.filter(name='x').exists())

    def test_write_token_stops_working_when_superuser_status_is_revoked(self):
        self.admin.is_superuser = False
        self.admin.save()
        response = self.post('api_v1_tag_create', body={'name': 'x', 'match_statuses': ['P']})
        self.assertEqual(response.status_code, 403)

    def test_only_superusers_can_issue_write_tokens(self):
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            ApiToken.issue(self.helper, 'sneaky', can_write=True)

    def test_token_page_ignores_the_write_box_for_non_superusers(self):
        self.client.force_login(self.helper)
        self.client.post(reverse('api_tokens'), {'action': 'create', 'name': 'web', 'expiry_days': 90, 'can_write': 'on'})
        self.assertFalse(ApiToken.objects.get(user=self.helper, name='web').can_write)

    def test_token_page_creates_write_tokens_for_superusers(self):
        self.client.force_login(self.admin)
        self.client.post(reverse('api_tokens'), {'action': 'create', 'name': 'web', 'expiry_days': 90, 'can_write': 'on'})
        self.assertTrue(ApiToken.objects.get(user=self.admin, name='web').can_write)

    def test_get_on_a_write_endpoint_is_refused(self):
        response = self.get('api_v1_tag_create', raw=self.write_raw)
        self.assertEqual(response.status_code, 405)

    def test_kill_switch_blocks_writes(self):
        enable_api(False)
        response = self.post('api_v1_tag_create', body={'name': 'x', 'match_statuses': ['P']})
        self.assertEqual(response.status_code, 503)


class TagWriteTests(ApiWriteBase):
    def test_create_and_partially_update_a_tag(self):
        response = self.post('api_v1_tag_create', body={
            'name': 'installed PUP program', 'match_statuses': ['P'],
            'match_entry_types': ['installed_software'], 'auto_apply': True,
        })
        self.assertEqual(response.status_code, 201)
        tag_id = response.json()['tag_id']

        self.post('api_v1_tag_update', tag_id, body={'description': 'uninstall it'})
        tag = RuleTag.objects.get(pk=tag_id)
        self.assertEqual((tag.description, tag.match_statuses, tag.auto_apply), ('uninstall it', ['P'], True))

    def test_validation_matches_the_tag_editor(self):
        response = self.post('api_v1_tag_create', body={'name': 'x', 'match_pattern': '(?=a)b'})
        self.assertEqual(response.status_code, 400)

    def test_apply_is_a_dry_run_until_confirmed(self):
        tag = RuleTag.objects.create(name='pups', match_statuses=['P'])
        rule = make_rule('pup line', status='P', owner=self.admin)
        make_rule('bad line', status='B', owner=self.admin)

        dry = self.post('api_v1_tag_apply', tag.pk, body={'mode': 'add_matching'}).json()
        self.assertEqual((dry['dry_run'], dry['would_add']), (True, 1))
        self.assertEqual([row['rule_id'] for row in dry['sample']], [rule.pk])
        self.assertFalse(tag.rules.exists())

        done = self.post('api_v1_tag_apply', tag.pk, body={'mode': 'add_matching', 'confirm': True}).json()
        self.assertEqual(done['added'], 1)
        self.assertEqual(list(tag.rules.all()), [rule])

    def test_remove_unmatched_covers_every_rule(self):
        tag = RuleTag.objects.create(name='pups', match_statuses=['P'])
        stale = [make_rule(f'b{i}', status='B', owner=self.admin) for i in range(60)]
        tag.rules.add(*stale)
        response = self.post('api_v1_tag_apply', tag.pk, body={'mode': 'remove_unmatched', 'confirm': True})
        self.assertEqual(response.json()['removed'], 60)

    def test_explicit_rule_ids(self):
        tag = RuleTag.objects.create(name='manual')
        rule = make_rule('x', owner=self.admin)
        self.post('api_v1_tag_apply', tag.pk, body={'mode': 'add_rules', 'rule_ids': [rule.pk], 'confirm': True})
        self.assertEqual(list(rule.tags.all()), [tag])
        self.post('api_v1_tag_apply', tag.pk, body={'mode': 'remove_rules', 'rule_ids': [rule.pk], 'confirm': True})
        self.assertFalse(rule.tags.exists())


class SpeechWriteTests(ApiWriteBase):
    def test_create_own_speech_with_tags(self):
        tag = RuleTag.objects.create(name='renloader')
        response = self.post('api_v1_speech_create', body={
            'name': 'uninstall', 'content': 'Hi {USERNAME}', 'is_shared': True, 'trigger_tag_ids': [tag.pk],
        })
        self.assertEqual(response.status_code, 201)
        speech = Speech.objects.get(owner=self.admin, name='uninstall')
        self.assertEqual(list(speech.trigger_tags.all()), [tag])
        self.assertEqual(response.json()['trigger_tags'], [{'tag_id': tag.pk, 'name': 'renloader'}])

    def test_update_keeps_the_fix_message_flag(self):
        fix = Speech.objects.get(owner=self.admin, is_fix_message=True)
        self.post('api_v1_speech_update', fix.pk, body={'content': 'new fix text'})
        fix.refresh_from_db()
        self.assertEqual((fix.content, fix.is_fix_message), ('new fix text', True))

    def test_other_users_speech_is_not_found(self):
        theirs = Speech.objects.create(owner=self.helper, name='theirs', content='x', is_shared=True)
        response = self.post('api_v1_speech_update', theirs.pk, body={'content': 'hijack'})
        self.assertEqual(response.status_code, 404)


class TagReadTests(ApiWriteBase):
    def test_any_token_can_list_and_read_tags(self):
        tag = RuleTag.objects.create(name='renloader', match_statuses=['P'])
        rules = [make_rule(f'r{i}', status='P', owner=self.admin) for i in range(3)]
        tag.rules.add(*rules)
        private = Speech.objects.create(owner=self.admin, name='private', content='x')
        shared = Speech.objects.create(owner=self.admin, name='shared', content='x', is_shared=True)
        tag.speeches.add(private, shared)

        names = [entry['name'] for entry in self.get('api_v1_tags').json()['tags']]
        self.assertIn('renloader', names)

        body = self.get('api_v1_tag', tag.pk, data={'limit': 2}).json()
        self.assertEqual((body['rules_total'], len(body['rules'])), (3, 2))
        self.assertEqual([s['name'] for s in body['speeches']], ['shared'])

    def test_analysis_lists_rule_tags(self):
        tag = RuleTag.objects.create(name='renloader')
        rule = make_rule('BAD LINE', owner=self.admin)
        rule.tags.add(tag)
        make_uploaded_log('amber-falcon', content='BAD LINE')
        body = self.get('api_v1_upload_analysis', 'amber-falcon').json()
        self.assertEqual([t['name'] for t in body['rule_tags']], ['renloader'])
        self.assertEqual(body['untrusted_lines'][0]['tag_ids'], [tag.pk])


class RuleReadTests(ApiWriteBase):
    def setUp(self):
        super().setUp()
        self.tag = RuleTag.objects.create(name='renloader')
        self.bad = make_rule('C:\\bad.exe', status='B', owner=self.admin, description='loader dropper')
        self.bad.tags.add(self.tag)
        self.pup = make_rule('toolbar', status='P', match_type='substring', owner=self.helper)
        self.off = make_rule('old entry', status='C', owner=self.helper, is_enabled=False)

    def ids(self, **params):
        response = self.get('api_v1_rules', data=params)
        self.assertEqual(response.status_code, 200, response.content)
        return {row['rule_id'] for row in response.json()['rules']}

    def test_any_token_lists_every_owners_rules(self):
        self.assertEqual(self.ids(), {self.bad.pk, self.pup.pk, self.off.pk})

    def test_filters_narrow_the_list(self):
        self.assertEqual(self.ids(q='DROPPER'), {self.bad.pk})
        self.assertEqual(self.ids(q='bad.exe'), {self.bad.pk})
        self.assertEqual(self.ids(status='P'), {self.pup.pk})
        self.assertEqual(self.ids(match_type='substring'), {self.pup.pk})
        self.assertEqual(self.ids(tag='RENLOADER'), {self.bad.pk})
        self.assertEqual(self.ids(tag=str(self.tag.pk)), {self.bad.pk})
        self.assertEqual(self.ids(owner='alice'), {self.pup.pk, self.off.pk})
        self.assertEqual(self.ids(enabled='0'), {self.off.pk})
        self.assertEqual(self.ids(enabled='1'), {self.bad.pk, self.pup.pk})

    def test_bad_filters_are_errors(self):
        for params in ({'tag': 'nope'}, {'status': 'X'}, {'match_type': 'fuzzy'}, {'enabled': 'yes'}, {'sort': 'name'}):
            self.assertEqual(self.get('api_v1_rules', data=params).status_code, 400, params)

    def test_rows_carry_tags_and_paging(self):
        body = self.get('api_v1_rules', data={'limit': 2, 'sort': 'status'}).json()
        self.assertEqual((body['total'], body['offset'], body['limit'], len(body['rules'])), (3, 0, 2, 2))
        row = body['rules'][0]
        self.assertEqual(row['rule_id'], self.bad.pk)
        self.assertEqual(row['tags'], [{'tag_id': self.tag.pk, 'name': 'renloader'}])
        self.assertEqual((row['owner'], row['is_enabled']), ('root', True))

    def test_get_rule_returns_every_field(self):
        body = self.get('api_v1_rule', self.bad.pk).json()
        self.assertEqual(body['source_text'], 'C:\\bad.exe')
        self.assertEqual(body['tags'], [{'tag_id': self.tag.pk, 'name': 'renloader'}])
        self.assertIn('filepath', body['parsed'])
        self.assertIn('created_at', body)

    def test_unknown_rule_is_404(self):
        self.assertEqual(self.get('api_v1_rule', 999999).status_code, 404)

    def test_needs_a_token(self):
        response = self.client.get(reverse('api_v1_rules'), secure=True)
        self.assertEqual(response.status_code, 401)

    def test_analysis_lines_carry_rule_ids(self):
        rule = make_rule('BAD LINE', owner=self.admin)
        make_uploaded_log('amber-falcon', content='BAD LINE')
        body = self.get('api_v1_upload_analysis', 'amber-falcon').json()
        self.assertEqual(body['untrusted_lines'][0]['rule_ids'], [rule.pk])


class BackwardCompatibilityTests(ApiWriteBase):
    """Older MCP clients read these keys; they must stay."""

    def test_speech_list_keeps_its_keys(self):
        Speech.objects.create(owner=self.helper, name='mine', content='x')
        item = next(s for s in self.get('api_v1_speeches').json()['speeches'] if s['name'] == 'mine')
        self.assertTrue({
            'speech_id', 'name', 'category', 'owner', 'is_own', 'is_shared', 'updated_at', 'content',
        } <= set(item))

    def test_analysis_keeps_its_keys(self):
        make_uploaded_log('amber-falcon', content='line')
        body = self.get('api_v1_upload_analysis', 'amber-falcon').json()
        self.assertTrue({
            'rule_set', 'status_legend', 'summary', 'warnings', 'matching_line_count',
            'offset', 'limit', 'untrusted_lines',
        } <= set(body))
        self.assertTrue({
            'n', 'text', 'status', 'status_label', 'status_codes', 'entry_type', 'matcher',
            'reasons', 'components', 'dates', 'fixlist_replacement',
        } <= set(body['untrusted_lines'][0]))

    def test_read_endpoints_stay_get_only(self):
        response = self.post('api_v1_speeches', body={})
        self.assertEqual(response.status_code, 405)
