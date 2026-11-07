"""Rule tags, speeches and classification rules through the token API.

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
from ..models import ApiToken, ClassificationRule, FixlistSnippet, RuleTag, Speech
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

    def _api_v1_patterns(self):
        from ..urls import urlpatterns
        return [pattern for pattern in urlpatterns if (pattern.name or '').startswith('api_v1_')]

    def test_every_changing_endpoint_needs_a_write_token(self):
        write_names = {pattern.name for pattern in self._api_v1_patterns() if getattr(pattern.callback, 'api_write', None)}
        self.assertEqual(write_names, {
            'api_v1_tag_create', 'api_v1_tag_update', 'api_v1_tag_apply',
            'api_v1_speech_create', 'api_v1_speech_update',
            'api_v1_rule_create', 'api_v1_rule_update',
        })
        tag = RuleTag.objects.create(name='renloader')
        speech = Speech.objects.create(owner=self.admin, name='mine', content='x')
        snippet = FixlistSnippet.objects.create(owner=self.admin, name='fix', content='x')
        rule = make_rule('C:\\mine.exe', owner=self.admin)
        args = {
            'api_v1_tag_update': [tag.pk], 'api_v1_tag_apply': [tag.pk], 'api_v1_speech_update': [speech.pk],
            'api_v1_rule_update': [rule.pk],
        }
        body = {'name': 'changed', 'content': 'changed', 'mode': 'add_rules', 'rule_ids': [], 'confirm': True,
                'snippet_ids': [snippet.pk], 'speech_ids': [speech.pk],
                'status': 'B', 'match_type': 'exact', 'source_text': 'changed', 'description': 'changed'}

        for name in sorted(write_names):
            for raw in (self.helper_raw, self.admin_read_raw):
                response = self.post(name, *args.get(name, []), body=body, raw=raw)
                self.assertEqual(response.status_code, 403, name)

        tag.refresh_from_db()
        speech.refresh_from_db()
        self.assertEqual((tag.name, speech.content), ('renloader', 'x'))
        self.assertFalse(tag.snippets.exists() or tag.speeches.exists())
        self.assertFalse(RuleTag.objects.filter(name='changed').exists())
        self.assertFalse(Speech.objects.filter(name='changed').exists())
        rule.refresh_from_db()
        self.assertEqual((rule.source_text, rule.description), ('C:\\mine.exe', ''))
        self.assertFalse(ClassificationRule.objects.filter(source_text='changed').exists())

    def test_every_other_endpoint_is_get_only(self):
        for pattern in self._api_v1_patterns():
            self.assertIsNotNone(getattr(pattern.callback, 'api_write', None), f'{pattern.name} is not token-gated')
            if not pattern.callback.api_write:
                args = [1] * len(pattern.pattern.converters)
                response = self.post(pattern.name, *args, raw=self.write_raw)
                self.assertEqual(response.status_code, 405, pattern.name)

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

    def test_snippet_ids_link_and_unlink_snippets(self):
        tag = RuleTag.objects.create(name='renloader')
        own = FixlistSnippet.objects.create(owner=self.admin, name='renloader fix', content='Folder: C:\\x')
        # Another helper's snippet the caller never selected cannot be linked.
        foreign = FixlistSnippet.objects.create(owner=self.helper, name='not mine', content='x', is_shared=True)

        response = self.post('api_v1_tag_update', tag.pk, body={'snippet_ids': [own.pk, foreign.pk]})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()['snippet_count'], 1)
        self.assertEqual(list(tag.snippets.all()), [own])
        self.assertEqual(
            [s['snippet_id'] for s in self.get('api_v1_tag', tag.pk, raw=self.admin_read_raw).json()['snippets']],
            [own.pk],
        )

        # Leaving the field out keeps the links; [] removes them.
        self.post('api_v1_tag_update', tag.pk, body={'description': 'loader'})
        self.assertEqual(list(tag.snippets.all()), [own])
        self.post('api_v1_tag_update', tag.pk, body={'snippet_ids': []})
        self.assertFalse(tag.snippets.exists())

    def test_create_tag_with_snippets(self):
        own = FixlistSnippet.objects.create(owner=self.admin, name='renloader fix', content='x')

        response = self.post('api_v1_tag_create', body={'name': 'renloader', 'snippet_ids': [own.pk]})

        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(list(RuleTag.objects.get(name='renloader').snippets.all()), [own])

    def test_snippet_ids_must_be_integers(self):
        tag = RuleTag.objects.create(name='renloader')
        response = self.post('api_v1_tag_update', tag.pk, body={'snippet_ids': ['1']})
        self.assertEqual(response.status_code, 400)


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


class RuleWriteTests(ApiWriteBase):
    def create(self, **body):
        return self.post('api_v1_rule_create', body=body)

    def test_create_makes_a_rule_owned_by_the_caller(self):
        response = self.create(status='B', match_type='exact', source_text='C:\\bad.exe', description='dropper')

        self.assertEqual(response.status_code, 201, response.content)
        body = response.json()
        self.assertEqual(body['skipped'], [])
        self.assertEqual(len(body['created']), 1)
        row = body['created'][0]
        rule = ClassificationRule.objects.get(pk=row['rule_id'])
        self.assertEqual(
            (rule.owner, rule.status, rule.match_type, rule.source_text, rule.description, rule.is_enabled),
            (self.admin, 'B', 'exact', 'C:\\bad.exe', 'dropper', True),
        )
        self.assertEqual((row['owner'], row['source_text']), ('root', 'C:\\bad.exe'))
        self.assertIn('parsed', row)

    def test_create_stores_parsed_metadata_like_the_add_rule_page(self):
        from ..analyzer import parse_rule_line
        line = r'S3 BadSvc; C:\Windows\System32\drivers\badsvc.sys [12345 2024-01-01] (Evil Corp) [File not signed]'
        parsed = parse_rule_line(line, status='B')
        self.assertTrue(parsed and parsed.get('filepath'), 'test line must parse')

        response = self.create(status='B', match_type='parsed', source_text=line)

        self.assertEqual(response.status_code, 201, response.content)
        rule = ClassificationRule.objects.get(pk=response.json()['created'][0]['rule_id'])
        self.assertEqual((rule.entry_type, rule.filepath), (parsed['entry_type'], parsed['filepath']))

    def test_create_applies_auto_tags_unless_tag_ids_are_given(self):
        auto = RuleTag.objects.create(name='pup', match_statuses=['P'], auto_apply=True)
        other = RuleTag.objects.create(name='other')

        auto_rule = self.create(status='P', match_type='substring', source_text='toolbar').json()['created'][0]
        picked = self.create(
            status='P', match_type='substring', source_text='coupon', tag_ids=[other.pk],
        ).json()['created'][0]

        self.assertEqual([t['tag_id'] for t in auto_rule['tags']], [auto.pk])
        self.assertEqual([t['tag_id'] for t in picked['tags']], [other.pk])

    def test_one_rule_per_line_and_duplicates_skipped(self):
        make_rule('second', owner=self.admin)
        response = self.create(status='B', match_type='exact', source_text='first\nsecond\nthird')

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual([row['source_text'] for row in body['created']], ['first', 'third'])
        self.assertEqual(body['skipped'], ['second'])

    def test_all_duplicates_is_a_conflict(self):
        make_rule('dup', owner=self.admin)
        response = self.create(status='B', match_type='exact', source_text='dup')

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['skipped'], ['dup'])
        self.assertEqual(ClassificationRule.objects.filter(source_text='dup').count(), 1)

    def test_another_helpers_identical_rule_is_no_duplicate(self):
        make_rule('shared line', owner=self.helper)
        self.assertEqual(self.create(status='B', match_type='exact', source_text='shared line').status_code, 201)

    def test_create_validation_matches_the_add_rule_page(self):
        cases = [
            {'match_type': 'exact', 'source_text': 'x'},
            {'status': 'B', 'source_text': 'x'},
            {'status': 'B', 'match_type': 'exact'},
            {'status': '?', 'match_type': 'exact', 'source_text': 'x'},
            {'status': 'X', 'match_type': 'exact', 'source_text': 'x'},
            {'status': 'B', 'match_type': 'fuzzy', 'source_text': 'x'},
            {'status': 'B', 'match_type': 'exact', 'source_text': 'x', 'whole_log': True},
            {'status': 'B', 'match_type': 'exact', 'source_text': 5},
            {'status': 'B', 'match_type': 'exact', 'source_text': 'x', 'priority': 'high'},
            {'status': 'B', 'match_type': 'exact', 'source_text': 'x', 'whole_log': 'yes'},
            {'status': 'B', 'match_type': 'exact', 'source_text': 'x', 'tag_ids': ['a']},
        ]
        for body in cases:
            self.assertEqual(self.create(**body).status_code, 400, body)
        self.assertFalse(ClassificationRule.objects.exists())

    def test_invalid_regex_is_rejected(self):
        response = self.create(status='B', match_type='regex', source_text='bad(')

        self.assertEqual(response.status_code, 400)
        self.assertIn('Invalid regex', response.json()['error'])
        self.assertFalse(ClassificationRule.objects.exists())

    def test_valid_regex_is_created(self):
        response = self.create(status='B', match_type='regex', source_text='^Task: evil')
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()['warnings'], [])

    def test_priority_is_stored(self):
        row = self.create(status='B', match_type='exact', source_text='x', priority=17).json()['created'][0]
        self.assertEqual(row['priority'], 17)

    def test_created_rule_is_used_by_the_analyzer_right_away(self):
        make_uploaded_log('amber-falcon', content='BAD LINE')
        rule_id = self.create(status='B', match_type='exact', source_text='BAD LINE').json()['created'][0]['rule_id']

        body = self.get('api_v1_upload_analysis', 'amber-falcon', raw=self.write_raw).json()
        self.assertEqual(body['untrusted_lines'][0]['rule_ids'], [rule_id])

    def test_update_changes_only_the_fields_sent(self):
        tag = RuleTag.objects.create(name='keep')
        rule = make_rule('C:\\bad.exe', owner=self.admin, description='old', priority=12)
        rule.tags.add(tag)

        response = self.post('api_v1_rule_update', rule.pk, body={'description': 'new', 'is_enabled': False})

        self.assertEqual(response.status_code, 200, response.content)
        rule.refresh_from_db()
        self.assertEqual(
            (rule.description, rule.is_enabled, rule.source_text, rule.status, rule.priority),
            ('new', False, 'C:\\bad.exe', 'B', 12),
        )
        self.assertEqual(list(rule.tags.values_list('pk', flat=True)), [tag.pk])
        self.assertEqual(response.json()['description'], 'new')

    def test_update_replaces_tags_when_given(self):
        old = RuleTag.objects.create(name='old')
        new = RuleTag.objects.create(name='new')
        rule = make_rule('x', owner=self.admin)
        rule.tags.add(old)

        self.post('api_v1_rule_update', rule.pk, body={'tag_ids': [new.pk]})

        self.assertEqual(list(rule.tags.values_list('pk', flat=True)), [new.pk])

    def test_priority_null_resets_to_the_match_type_default(self):
        rule = make_rule('x', owner=self.admin, priority=17)
        self.post('api_v1_rule_update', rule.pk, body={'priority': None})
        rule.refresh_from_db()
        self.assertEqual(rule.priority, ClassificationRule.default_priority_for('exact'))

    def test_update_is_seen_by_the_analyzer_right_away(self):
        make_uploaded_log('amber-falcon', content='BAD LINE')
        rule = make_rule('OTHER LINE', owner=self.admin)

        self.post('api_v1_rule_update', rule.pk, body={'source_text': 'BAD LINE'})

        body = self.get('api_v1_upload_analysis', 'amber-falcon', raw=self.write_raw).json()
        self.assertEqual(body['untrusted_lines'][0]['rule_ids'], [rule.pk])

    def test_superuser_can_update_another_helpers_rule(self):
        rule = make_rule('theirs', owner=self.helper, description='old')

        response = self.post('api_v1_rule_update', rule.pk, body={'description': 'fixed'})

        self.assertEqual(response.status_code, 200, response.content)
        rule.refresh_from_db()
        self.assertEqual(rule.description, 'fixed')
        self.assertEqual(rule.owner, self.helper)
        self.assertEqual(response.json()['owner'], 'alice')

    def test_update_of_another_helpers_rule_checks_duplicates_in_their_set(self):
        make_rule('one', owner=self.helper)
        two = make_rule('two', owner=self.helper)
        make_rule('admins only', owner=self.admin)

        refused = self.post('api_v1_rule_update', two.pk, body={'source_text': 'one'})
        allowed = self.post('api_v1_rule_update', two.pk, body={'source_text': 'admins only'})

        self.assertEqual(refused.status_code, 400)
        self.assertEqual(allowed.status_code, 200, allowed.content)
        two.refresh_from_db()
        self.assertEqual(two.source_text, 'admins only')

    def test_update_of_another_helpers_rule_is_seen_by_the_analyzer(self):
        make_uploaded_log('amber-falcon', content='BAD LINE')
        rule = make_rule('OTHER LINE', owner=self.helper)

        self.post('api_v1_rule_update', rule.pk, body={'source_text': 'BAD LINE'})

        body = self.get('api_v1_upload_analysis', 'amber-falcon', raw=self.write_raw).json()
        self.assertEqual(body['untrusted_lines'][0]['rule_ids'], [rule.pk])

    def test_update_into_a_duplicate_is_refused(self):
        make_rule('one', owner=self.admin)
        two = make_rule('two', owner=self.admin)

        response = self.post('api_v1_rule_update', two.pk, body={'source_text': 'one'})

        self.assertEqual(response.status_code, 400)
        two.refresh_from_db()
        self.assertEqual(two.source_text, 'two')

    def test_update_validation(self):
        rule = make_rule('x', owner=self.admin)
        for body in ({'status': '?'}, {'match_type': 'fuzzy'}, {'source_text': ''}, {'source_text': 'a\nb'},
                     {'is_enabled': 'no'}, {'match_type': 'regex', 'source_text': 'bad('}):
            self.assertEqual(self.post('api_v1_rule_update', rule.pk, body=body).status_code, 400, body)
        rule.refresh_from_db()
        self.assertEqual((rule.source_text, rule.status, rule.match_type), ('x', 'B', 'exact'))

    def test_unknown_rule_update_is_404(self):
        self.assertEqual(self.post('api_v1_rule_update', 999999, body={'description': 'x'}).status_code, 404)


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
